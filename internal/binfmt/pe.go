package binfmt

import (
	"encoding/binary"
	"strconv"
	"strings"
)

// PE 常量（Windows SDK 里的 IMAGE_*）。
const (
	peMachineI386  = 0x014c
	peMachineAMD64 = 0x8664
	peMachineARM   = 0x01c0
	peMachineARM64 = 0xaa64

	peCharDLL = 0x2000

	peDllCharASLR = 0x0040 // DYNAMIC_BASE
	peDllCharDEP  = 0x0100 // NX_COMPAT
	peDllCharCFG  = 0x4000 // GUARD_CF

	peScnExec  = 0x20000000
	peScnRead  = 0x40000000
	peScnWrite = 0x80000000

	peSectionHeaderSize = 40
	peImportDescSize    = 20
	peMaxThunks         = 8192
	peMaxDLLs           = 128
)

// peSeg 是段表里解析导入表要用的原始信息（对外输出用 Section，内部映射用这个）。
type peSeg struct {
	name    string
	va      uint64
	vSize   uint64
	rawPtr  uint64
	rawSize uint64
	chars   uint32 // IMAGE_SCN_*：只在算 Perm 时用
}

// off 把 RVA 映射成文件偏移。
func (s peSeg) off(rva uint64) (int, bool) {
	span := s.vSize
	if s.rawSize > span {
		span = s.rawSize
	}
	if rva < s.va || rva >= s.va+span {
		return 0, false
	}
	delta := rva - s.va
	if delta >= s.rawSize {
		return 0, false // 落在 .bss 这类无文件内容的区间
	}
	return int(s.rawPtr + delta), true
}

// parsePE 解析 PE32 / PE32+。
//
// 只做静态读，不解包、不执行。所有越界访问都先判长度——样本是**不可信输入**，
// 一个畸形头就让分析器 panic 是不可接受的（worker 会因为一次 panic 丢掉整轮上下文）。
func parsePE(data []byte, rep *Report) {
	if len(data) < 0x40 {
		parseWarn(rep, "PE: 文件不足 64 字节，无法读取 DOS 头")
		return
	}
	peOff := int(binary.LittleEndian.Uint32(data[0x3c:]))
	if peOff <= 0 || peOff+24 > len(data) {
		parseWarn(rep, "PE: e_lfanew 越界（%d），文件可能被截断或加密", peOff)
		return
	}
	if string(data[peOff:peOff+4]) != "PE\x00\x00" {
		parseWarn(rep, "PE: 签名不匹配（DOS 头存在但缺 PE\\0\\0），疑似 DOS 程序")
		return
	}

	coff := peOff + 4
	machine := binary.LittleEndian.Uint16(data[coff:])
	nSec := int(binary.LittleEndian.Uint16(data[coff+2:]))
	optSize := int(binary.LittleEndian.Uint16(data[coff+16:]))
	charac := binary.LittleEndian.Uint16(data[coff+18:])
	rep.Endian = "little"
	if charac&peCharDLL != 0 {
		rep.Kind = "dll"
	} else {
		rep.Kind = "exe"
	}

	opt := coff + 20
	if optSize == 0 || opt+2 > len(data) {
		parseWarn(rep, "PE: 缺少可选头（obj 或畸形文件）")
		return
	}
	magic := binary.LittleEndian.Uint16(data[opt:])
	plus := magic == 0x20b
	switch {
	case plus:
		rep.Bits = 64
	case magic == 0x10b:
		rep.Bits = 32
	default:
		parseWarn(rep, "PE: 未知可选头 magic 0x%x", magic)
		return
	}
	rep.Arch = peArch(machine, rep.Bits)

	var entryRVA, imageBase uint64
	if opt+20 <= len(data) {
		entryRVA = uint64(binary.LittleEndian.Uint32(data[opt+16:]))
	}
	if plus && opt+32 <= len(data) {
		imageBase = binary.LittleEndian.Uint64(data[opt+24:])
	} else if !plus && opt+32 <= len(data) {
		imageBase = uint64(binary.LittleEndian.Uint32(data[opt+28:]))
	}
	if entryRVA != 0 {
		rep.Entry = hexAddr(imageBase + entryRVA)
	} else {
		rep.Entry = "0x0"
	}
	if opt+72 <= len(data) {
		dllChar := binary.LittleEndian.Uint16(data[opt+70:])
		rep.Security.ASLR = dllChar&peDllCharASLR != 0
		rep.Security.DEP = dllChar&peDllCharDEP != 0
		rep.Security.CFG = dllChar&peDllCharCFG != 0
	}

	// 段表
	secStart := opt + optSize
	segs := make([]peSeg, 0, nSec)
	for i := 0; i < nSec && i < 96; i++ {
		off := secStart + i*peSectionHeaderSize
		if off+peSectionHeaderSize > len(data) {
			parseWarn(rep, "PE: 段表被截断（声明 %d 段，读到第 %d 段）", nSec, i)
			break
		}
		name := strings.TrimRight(string(data[off:off+8]), "\x00")
		vsize := uint64(binary.LittleEndian.Uint32(data[off+8:]))
		vaddr := uint64(binary.LittleEndian.Uint32(data[off+12:]))
		rawSize := uint64(binary.LittleEndian.Uint32(data[off+16:]))
		rawPtr := uint64(binary.LittleEndian.Uint32(data[off+20:]))
		chars := binary.LittleEndian.Uint32(data[off+36:])
		segs = append(segs, peSeg{name: name, va: vaddr, vSize: vsize, rawPtr: rawPtr, rawSize: rawSize, chars: chars})
	}
	sections := make([]Section, 0, len(segs))
	for _, s := range segs {
		ent := 0.0
		if s.rawSize > 0 && s.rawPtr+s.rawSize <= uint64(len(data)) {
			ent = entropy(data[s.rawPtr : s.rawPtr+s.rawSize])
		} else if s.rawSize > 0 {
			parseWarn(rep, "PE: 段 %s 的原始数据越界", s.name)
		}
		chars := s.chars
		sections = append(sections, Section{
			Name:    s.name,
			VAddr:   s.va,
			VSize:   s.vSize,
			RawSize: s.rawSize,
			Entropy: ent,
			Perm:    sectionPerm(chars&peScnRead != 0, chars&peScnWrite != 0, chars&peScnExec != 0),
		})
	}
	sortSections(sections)
	if len(sections) > maxSections {
		sections = sections[:maxSections]
	}
	rep.Sections = sections

	// 数据目录：导出表 [0]、导入表 [1]
	ddBase := opt + 96
	if plus {
		ddBase = opt + 112
	}
	readDD := func(i int) uint32 {
		off := ddBase + i*8
		if off+4 > len(data) {
			return 0
		}
		return binary.LittleEndian.Uint32(data[off:])
	}
	if expRVA := readDD(0); expRVA != 0 {
		if off, ok := peMap(segs, uint64(expRVA)); ok && off+28 <= len(data) {
			rep.Exports = int(binary.LittleEndian.Uint32(data[off+24:]))
		}
	}
	if impRVA := readDD(1); impRVA != 0 {
		rep.Imports = parsePEImports(data, segs, uint64(impRVA), plus)
	}

	rep.Packer = peHeuristics(rep, segs, uint64(entryRVA))
}

func peArch(machine uint16, bits int) string {
	switch machine {
	case peMachineAMD64:
		return "amd64"
	case peMachineI386:
		return "386"
	case peMachineARM64:
		return "arm64"
	case peMachineARM:
		return "arm"
	}
	if bits == 64 {
		return "unknown64"
	}
	return "unknown32"
}

// peMap 把 RVA 映射成文件偏移：逐个段尝试，命中第一个。
func peMap(segs []peSeg, rva uint64) (int, bool) {
	for _, s := range segs {
		if off, ok := s.off(rva); ok {
			return off, true
		}
	}
	return 0, false
}

func parsePEImports(data []byte, segs []peSeg, impRVA uint64, plus bool) ImportSummary {
	out := ImportSummary{}
	base, ok := peMap(segs, impRVA)
	if !ok {
		return out
	}
	thunkSize := uint64(4)
	if plus {
		thunkSize = 8
	}
	const maxSuspiciousScan = 200
	for i := 0; i < peMaxDLLs; i++ {
		off := base + i*peImportDescSize
		if off+peImportDescSize > len(data) {
			break
		}
		oft := uint64(binary.LittleEndian.Uint32(data[off:]))
		nameRVA := uint64(binary.LittleEndian.Uint32(data[off+12:]))
		ft := uint64(binary.LittleEndian.Uint32(data[off+16:]))
		if oft == 0 && nameRVA == 0 && ft == 0 {
			break // 全零描述符 = 结束
		}
		if nameOff, ok := peMap(segs, nameRVA); ok {
			if dll := readCString(data, nameOff, 64); dll != "" {
				out.DLLs = append(out.DLLs, dll)
			}
		}
		// 优先 OriginalFirstThunk，回落 FirstThunk
		thunkRVA := oft
		if thunkRVA == 0 {
			thunkRVA = ft
		}
		if thunkOff, ok := peMap(segs, thunkRVA); ok {
			for j := 0; j < peMaxThunks; j++ {
				p := thunkOff + int(uint64(j)*thunkSize)
				if p+int(thunkSize) > len(data) {
					break
				}
				var val uint64
				if plus {
					val = binary.LittleEndian.Uint64(data[p:])
				} else {
					val = uint64(binary.LittleEndian.Uint32(data[p:]))
				}
				if val == 0 {
					break
				}
				out.Count++
				// 高位为序号导入（无名字），跳过名字解析
				ordinalFlag := uint64(0x80000000)
				if plus {
					ordinalFlag = 0x8000000000000000
				}
				if val&ordinalFlag == 0 && out.Count <= maxSuspiciousScan {
					if no, ok := peMap(segs, val); ok {
						if fn := readCString(data, no+2, 64); isSuspiciousAPI(fn) {
							out.Suspicious = append(out.Suspicious, fn)
						}
					}
				}
			}
		}
	}
	out.DLLs = clip(out.DLLs, maxDLLs)
	out.Suspicious = clip(dedup(out.Suspicious), maxSuspicious)
	return out
}

// readCString 读一个以 NUL 结尾的 ASCII 串（限长，防止读到别的结构里去）。
func readCString(data []byte, off, max int) string {
	if off <= 0 || off >= len(data) {
		return ""
	}
	end := off
	for end < len(data) && end-off < max && data[end] != 0 {
		c := data[end]
		if c < 0x20 || c > 0x7e {
			return "" // 非可打印 → 不是字符串，直接放弃
		}
		end++
	}
	if end == off {
		return ""
	}
	return string(data[off:end])
}

// peHeuristics 汇总加壳/混淆依据。
//
// 只给结论不给依据的检测会被模型当圣旨，所以每条都必须带 reasons。
func peHeuristics(rep *Report, segs []peSeg, entryRVA uint64) PackerHint {
	var reasons []string
	for _, s := range rep.Sections {
		ln := strings.ToLower(s.Name)
		for _, p := range []string{"upx0", "upx1", "upx2", ".aspack", ".adata", ".themida", ".vmp0", ".vmp1", "mpress1", "mpress2", ".petite"} {
			if strings.HasPrefix(ln, p) {
				reasons = append(reasons, "段名命中已知壳 "+s.Name)
			}
		}
		if s.RawSize >= 4096 && s.Entropy >= 7.2 {
			reasons = append(reasons, "高熵段 "+s.Name+"="+strconv.FormatFloat(s.Entropy, 'f', 2, 64))
		}
		if s.Perm == "RWX" {
			reasons = append(reasons, "可写可执行段 "+s.Name)
		}
	}
	if rep.Imports.Count > 0 && rep.Imports.Count < 10 {
		reasons = append(reasons, "导入函数异常少（"+strconv.Itoa(rep.Imports.Count)+" 个）")
	}
	// 入口是否落在可执行段内
	if entryRVA != 0 {
		inExec := false
		for _, s := range rep.Sections {
			if strings.Contains(s.Perm, "X") && entryRVA >= s.VAddr && entryRVA < s.VAddr+maxU64(s.VSize, s.RawSize) {
				inExec = true
				break
			}
		}
		if !inExec {
			reasons = append(reasons, "入口点不在任何可执行段内")
		}
	}
	return PackerHint{Suspected: len(reasons) > 0, Reasons: clip(dedup(reasons), 4)}
}

func maxU64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}
