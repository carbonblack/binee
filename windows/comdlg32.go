package windows

import (
	"bytes"
	"encoding/binary"
)

type OpenFileName32 struct {
	StructSize    uint32
	Owner         uint32
	Instance      uint32
	Filter        uint32
	CustomFilter  uint32
	MaxCustFilter uint32
	FilterIndex   uint32
	File          uint32
	MaxFile       uint32
	FileTitle     uint32
	MaxFileTitle  uint32
	InitialDir    uint32
	Title         uint32
	Flags         uint32
	FileOffset    uint16
	FileExtension uint16
	DefExit       uint32
	CustData      uint32
	Hook          uint32
	TemplateName  uint32
	EditInfo      uint32
	Prompt        uint32
	Reserved      uint32
	Reserved2     uint32
	FlagsEx       uint32
}

func Comdlg32Hooks(emu *WinEmulator) {
	emu.AddHook("", "GetOpenFileNameW", &Hook{
		Parameters: []string{"Arg1"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			openFileName := OpenFileName32{}
			buf, _ := emu.Uc.MemRead(in.Args[0], uint64(binary.Size(&openFileName)))
			binary.Read(bytes.NewReader(buf), binary.LittleEndian, &openFileName)
			return SkipFunctionStdCall(true, 0x1)(emu, in)
		},
	})
}
