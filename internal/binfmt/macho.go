package binfmt

import (
	"encoding/binary"
	"strconv"
)

// Mach-O 常量。
const (
	machMagic32  = 0xfeedface
	machMagic64  = 0xfeedfacf
	machCigam32  = 0xcefaedfe
	machCigam64  = 0xcffaedfe
	machFatMagic = 0xcafebabe
	machFatCigam = 0xbebafeca

	machFileObj    = 1
	machFileExec   = 2
	machFileDylib  = 6
	machFileBundle = 8
)

func isMachO(data []byte) bool {
	if len(data) < 8 {
		return false
	}
	m := binary.BigEndian.Uint32(data)
	switch m {
	case machMagic32, machMagic64, machCigam32, machCigam64, machFatMagic, machFatCigam:
		return true
	}
	return false
}

// parseMachO 只解析头部与基本属性。
//
// 刻意不做 load command 全解析：Mach-O 的段/符号信息对"先判断这是什么、要不要深挖"
// 帮助有限，而完整解析的代码量是 PE/ELF 的两三倍。需要深挖时走 rizin（可选加速器）。
func parseMachO(data []byte, rep *Report) {
	m := binary.BigEndian.Uint32(data)
	var bo binary.ByteOrder = binary.BigEndian
	swapped := false
	switch m {
	case machMagic32, machMagic64:
		bo = binary.BigEndian
	case machCigam32, machCigam64:
		bo = binary.LittleEndian
		swapped = true
	case machFatMagic, machFatCigam:
		rep.Kind = "fat"
		rep.Endian = "big"
		rep.Warnings = append(rep.Warnings, "Mach-O fat/universal 二进制：含多个架构，需先拆分再分析")
		return
	default:
		return
	}
	_ = swapped
	magic := bo.Uint32(data)
	switch magic {
	case machMagic64, machCigam64:
		rep.Bits = 64
	case machMagic32, machCigam32:
		rep.Bits = 32
	}
	if bo == binary.BigEndian {
		rep.Endian = "big"
	} else {
		rep.Endian = "little"
	}

	cputype := bo.Uint32(data[4:])
	filetype := bo.Uint32(data[12:])
	ncmds := bo.Uint32(data[16:])
	rep.Arch = machArch(cputype)
	switch filetype {
	case machFileExec:
		rep.Kind = "exe"
	case machFileDylib:
		rep.Kind = "dylib"
	case machFileBundle:
		rep.Kind = "bundle"
	case machFileObj:
		rep.Kind = "obj"
	default:
		rep.Kind = "macho"
	}
	rep.Entry = "0x0" // 入口在 LC_MAIN 里，未解析
	rep.Warnings = append(rep.Warnings,
		"Mach-O: 未解析 load command（"+strconv.Itoa(int(ncmds))+" 条）；段表与依赖库请用可选加速器（rizin/otool）")
}

func machArch(cputype uint32) string {
	switch cputype {
	case 7:
		return "386"
	case 0x01000007:
		return "amd64"
	case 12:
		return "arm"
	case 0x0100000c:
		return "arm64"
	}
	return "unknown"
}

// isArchive / archiveKind / isScript 是"非可执行但常见"的兜底识别。
//
// 价值在于给出正确方向：APK/ZIP 要先解包、脚本要先看解释器，而不是让模型对着一个
// 容器文件反复 hexdump。
func isArchive(data []byte) bool {
	if len(data) >= 4 && string(data[:4]) == "PK\x03\x04" {
		return true
	}
	if len(data) >= 8 && string(data[:8]) == "!<arch>\n" {
		return true
	}
	if len(data) >= 4 && string(data[:4]) == "Rar!" {
		return true
	}
	if len(data) >= 6 && string(data[:6]) == "7z\xbc\xaf\x27\x1c" {
		return true
	}
	return false
}

func archiveKind(data []byte) string {
	if len(data) >= 4 && string(data[:4]) == "PK\x03\x04" {
		// APK 的 AndroidManifest.xml 在包里；不展开，只提示
		return "zip"
	}
	if len(data) >= 8 && string(data[:8]) == "!<arch>\n" {
		return "ar"
	}
	if len(data) >= 4 && string(data[:4]) == "Rar!" {
		return "rar"
	}
	return "7z"
}

func isScript(data []byte) bool {
	if len(data) >= 2 && data[0] == '#' && data[1] == '!' {
		return true
	}
	return false
}
