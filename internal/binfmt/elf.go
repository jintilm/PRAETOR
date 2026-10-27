package binfmt

import (
	"encoding/binary"
	"strconv"
	"strings"
)

// ELF 常量。
const (
	elfClass32 = 1
	elfClass64 = 2
	elfDataLE  = 1
	elfDataBE  = 2

	etRel  = 1
	etExec = 2
	etDyn  = 3

	shtStrtab  = 3
	shtDynamic = 6
	shtDynsym  = 11

	ptGnuStack = 0x6474e551
	ptGnuRelro = 0x6474e552
	pfX        = 1
	pfW        = 2
	pfR        = 4

	shfWrite = 0x1
	shfExec  = 0x4

	dtNeeded  = 1
	dtFlags   = 30
	dtBindNow = 24
	dtFlags1  = 0x6ffffffb
	dfBindNow = 0x8
	df1Now    = 0x1
	dtNull    = 0
)

type elfSec struct {
	name    string
	typ     uint32
	flags   uint64
	addr    uint64
	offset  uint64
	size    uint64
	link    uint32
	entsize uint64
}

// parseELF 解析 ELF32/ELF64（LE/BE 都支持，虽然实际几乎只有 LE）。
func parseELF(data []byte, rep *Report) {
	if len(data) < 52 {
		parseWarn(rep, "ELF: 文件不足 52 字节")
		return
	}
	class := data[4]
	if class != elfClass32 && class != elfClass64 {
		parseWarn(rep, "ELF: 未知 EI_CLASS=%d", class)
		return
	}
	var bo binary.ByteOrder = binary.LittleEndian
	switch data[5] {
	case elfDataLE:
		rep.Endian = "little"
	case elfDataBE:
		bo = binary.BigEndian
		rep.Endian = "big"
	default:
		parseWarn(rep, "ELF: 未知 EI_DATA=%d", data[5])
		return
	}
	is64 := class == elfClass64
	if is64 {
		rep.Bits = 64
	} else {
		rep.Bits = 32
	}

	ety := bo.Uint16(data[16:])
	machine := bo.Uint16(data[18:])
	rep.Arch = elfArch(machine, rep.Bits)
	switch ety {
	case etExec:
		rep.Kind = "exe"
		rep.Security.PIE = false
	case etDyn:
		// PIE 可执行与 .so 都是 ET_DYN；有入口点基本可判为 PIE。
		rep.Security.PIE = true
		rep.Kind = "pie"
	case etRel:
		rep.Kind = "obj"
	default:
		rep.Kind = "elf"
	}

	var entry, phoff, shoff uint64
	var phentsize, phnum, shentsize, shnum, shstrndx int
	if is64 {
		entry = bo.Uint64(data[24:])
		phoff = bo.Uint64(data[32:])
		shoff = bo.Uint64(data[40:])
		phentsize = int(bo.Uint16(data[54:]))
		phnum = int(bo.Uint16(data[56:]))
		shentsize = int(bo.Uint16(data[58:]))
		shnum = int(bo.Uint16(data[60:]))
		shstrndx = int(bo.Uint16(data[62:]))
	} else {
		entry = uint64(bo.Uint32(data[24:]))
		phoff = uint64(bo.Uint32(data[28:]))
		shoff = uint64(bo.Uint32(data[32:]))
		phentsize = int(bo.Uint16(data[42:]))
		phnum = int(bo.Uint16(data[44:]))
		shentsize = int(bo.Uint16(data[46:]))
		shnum = int(bo.Uint16(data[48:]))
		shstrndx = int(bo.Uint16(data[50:]))
	}
	if entry != 0 {
		rep.Entry = hexAddr(entry)
	} else {
		rep.Entry = "0x0"
	}

	// 程序头：NX（PT_GNU_STACK 是否可执行）与 RELRO
	for i := 0; i < phnum && i < 128; i++ {
		off := phoff + uint64(i*phentsize)
		if off+uint64(phentsize) > uint64(len(data)) || phentsize == 0 {
			parseWarn(rep, "ELF: 程序头被截断（第 %d 个）", i)
			break
		}
		var typ uint32
		var flags uint64
		if is64 {
			typ = bo.Uint32(data[off:])
			flags = uint64(bo.Uint32(data[off+4:]))
		} else {
			typ = bo.Uint32(data[off:])
			flags = uint64(bo.Uint32(data[off+24:]))
		}
		switch typ {
		case ptGnuStack:
			rep.Security.NX = flags&pfX == 0 // 栈不可执行 = NX 生效
			rep.Security.DEP = rep.Security.NX
		case ptGnuRelro:
			rep.Security.RELRO = true
		}
	}

	// 节表
	secs := make([]elfSec, 0, shnum)
	for i := 0; i < shnum && i < 256; i++ {
		off := shoff + uint64(i*shentsize)
		if shentsize == 0 || off+uint64(shentsize) > uint64(len(data)) {
			parseWarn(rep, "ELF: 节表被截断（第 %d 节）", i)
			break
		}
		var s elfSec
		s.typ = bo.Uint32(data[off+4:])
		if is64 {
			s.flags = bo.Uint64(data[off+8:])
			s.addr = bo.Uint64(data[off+16:])
			s.offset = bo.Uint64(data[off+24:])
			s.size = bo.Uint64(data[off+32:])
			s.link = bo.Uint32(data[off+40:])
			s.entsize = bo.Uint64(data[off+56:])
		} else {
			s.flags = uint64(bo.Uint32(data[off+8:]))
			s.addr = uint64(bo.Uint32(data[off+12:]))
			s.offset = uint64(bo.Uint32(data[off+16:]))
			s.size = uint64(bo.Uint32(data[off+20:]))
			s.link = bo.Uint32(data[off+24:])
			s.entsize = uint64(bo.Uint32(data[off+36:]))
		}
		secs = append(secs, s)
	}

	// 节名来自 .shstrtab
	if shstrndx > 0 && shstrndx < len(secs) {
		strtab := secs[shstrndx]
		if strtab.offset+strtab.size <= uint64(len(data)) {
			for i := range secs {
				off := shoff + uint64(i*shentsize)
				if off+4 > uint64(len(data)) {
					break
				}
				nameOff := uint64(bo.Uint32(data[off:]))
				if nameOff < strtab.size {
					secs[i].name = readCString(data, int(strtab.offset+nameOff), 64)
				}
			}
		}
	}

	out := make([]Section, 0, len(secs))
	for _, s := range secs {
		if s.typ == 0 || s.name == "" { // SHT_NULL / 无名节不进摘要
			continue
		}
		ent := 0.0
		if s.typ != 8 && s.size > 0 && s.offset+s.size <= uint64(len(data)) && s.size <= maxScanBytes {
			ent = entropy(data[s.offset : s.offset+s.size])
		}
		out = append(out, Section{
			Name:    s.name,
			VAddr:   s.addr,
			VSize:   s.size,
			RawSize: s.size,
			Entropy: ent,
			Perm:    sectionPerm(true, s.flags&shfWrite != 0, s.flags&shfExec != 0),
		})
	}
	sortSections(out)
	if len(out) > maxSections {
		out = out[:maxSections]
	}
	rep.Sections = out

	// 动态节：依赖库 + BIND_NOW
	for _, s := range secs {
		if s.typ != shtDynamic || s.size == 0 || s.offset+s.size > uint64(len(data)) {
			continue
		}
		var dynstr elfSec
		haveStr := false
		if int(s.link) < len(secs) {
			dynstr = secs[s.link]
			haveStr = dynstr.typ == shtStrtab && dynstr.offset+dynstr.size <= uint64(len(data))
		}
		entSize := uint64(8)
		if is64 {
			entSize = 16
		}
		bindNow := false
		for off := s.offset; off+entSize <= s.offset+s.size && off+entSize <= uint64(len(data)); off += entSize {
			var tag, val uint64
			if is64 {
				tag = bo.Uint64(data[off:])
				val = bo.Uint64(data[off+8:])
			} else {
				tag = uint64(bo.Uint32(data[off:]))
				val = uint64(bo.Uint32(data[off+4:]))
			}
			if tag == dtNull {
				break
			}
			switch tag {
			case dtNeeded:
				if haveStr && val < dynstr.size {
					if lib := readCString(data, int(dynstr.offset+val), 96); lib != "" {
						rep.Imports.DLLs = append(rep.Imports.DLLs, lib)
						rep.Imports.Count++
					}
				}
			case dtBindNow:
				bindNow = true
			case dtFlags:
				bindNow = bindNow || val&dfBindNow != 0
			case dtFlags1:
				bindNow = bindNow || val&df1Now != 0
			}
		}
		if bindNow {
			rep.Security.RELRO = true // Full RELRO 的必要条件（粗略）
		}
	}
	rep.Imports.DLLs = clip(dedup(rep.Imports.DLLs), maxDLLs)

	// 动态符号数 ≈ 导出/导入符号总量，给模型一个"规模感"
	for _, s := range secs {
		if s.typ == shtDynsym && s.entsize > 0 {
			rep.Exports = int(s.size / s.entsize)
		}
	}

	// 可执行栈 + 无 NX 是风险信号；这里不重复报警，交给 summary 显示。
	rep.Packer = elfHeuristics(rep)
}

func elfArch(machine uint16, bits int) string {
	switch machine {
	case 3:
		return "386"
	case 62:
		return "amd64"
	case 40:
		return "arm"
	case 183:
		return "arm64"
	case 8:
		return "mips"
	case 243:
		return "riscv"
	}
	return "unknown" + strconv.Itoa(bits)
}

// elfHeuristics：ELF 没有"壳"的概念那么强，主要看高熵段（打包/加密的 .so 或固件片段）。
func elfHeuristics(rep *Report) PackerHint {
	var reasons []string
	for _, s := range rep.Sections {
		if s.RawSize >= 4096 && s.Entropy >= 7.2 {
			reasons = append(reasons, "高熵段 "+s.Name+"="+strconv.FormatFloat(s.Entropy, 'f', 2, 64))
		}
		if s.Perm == "RWX" {
			reasons = append(reasons, "可写可执行段 "+s.Name)
		}
	}
	if len(rep.Imports.DLLs) == 0 && rep.Kind == "pie" {
		reasons = append(reasons, "静态链接或依赖被裁剪（无 DT_NEEDED）")
	}
	return PackerHint{Suspected: len(reasons) > 0, Reasons: clip(dedup(reasons), 4)}
}

// elfSummary 供 summary 渲染时判断（避免 strings 包依赖 ELF 常量）。
func elfIsDyn(rep *Report) bool { return rep.Kind == "pie" || rep.Kind == "so" }

var _ = strings.TrimSpace // 保留 strings 依赖，便于后续扩展节名过滤
