package windows

import (
	"bytes"
	"encoding/binary"

	"github.com/carbonblack/binee/util"
)

func getSystemInfo(emu *WinEmulator, in *Instruction) func(emu *WinEmulator, in *Instruction) bool {
	info := struct {
		Dummy          uint64
		PageSize       uint32
		MinAppAddress  uint32
		MaxAppAddress  uint32
		ActiveProcMask uint32
		NumberOfProc   uint32
		ProcType       uint32
		AllocationGran uint32
		ProcLevel      uint16
		ProcRev        uint16
	}{
		0x0,
		0x1000,
		0x1000,
		0x7ffeffff,
		0x3,
		uint32(emu.Opts.ProcessorsCount),
		uint32(emu.Opts.ProcessorType),
		0x10000,
		uint16(emu.Opts.ProcessorLevel),
		uint16(emu.Opts.ProcessorRevision),
	}
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, &info)
	emu.Uc.MemWrite(in.Args[0], buf.Bytes())
	return SkipFunctionStdCall(false, 0x0)
}

func Sysinfoapi(emu *WinEmulator) {
	emu.AddHook("", "GetComputerNameExA", &Hook{
		Parameters: []string{"NameType", "lpBuffer", "nSize"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			in.Hook.Parameters[0] = "s:NameType"
			switch in.Args[0] {
			case 0:
				in.Hook.Values[0] = "ComputerNameDnsDomain"
			case 1:
				in.Hook.Values[0] = "ComputerNameDnsFullyQualified"
			case 2:
				in.Hook.Values[0] = "ComputerNameDnsHostname"
				emu.Uc.MemWrite(in.Args[1], []byte(emu.Opts.ComputerName+"\x00"))
			case 3:
				in.Hook.Values[0] = "ComputerNameNetBIOS"
				emu.Uc.MemWrite(in.Args[1], []byte(emu.Opts.ComputerName+"\x00"))
			case 4:
				in.Hook.Values[0] = "ComputerNamePhysicalDnsDomain"
			case 5:
				in.Hook.Values[0] = "ComputerNamePhysicalDnsFullyQualified"
				emu.Uc.MemWrite(in.Args[1], []byte(emu.Opts.ComputerName+"\x00"))
			case 6:
				in.Hook.Values[0] = "ComputerNamePhysicalDnsHostname"
				emu.Uc.MemWrite(in.Args[1], []byte(emu.Opts.ComputerName+"\x00"))
			case 7:
				in.Hook.Values[0] = "ComputerNamePhysicalNetBIOS"
				emu.Uc.MemWrite(in.Args[1], []byte(emu.Opts.ComputerName+"\x00"))
			}
			return SkipFunctionStdCall(true, 0x1)(emu, in)
		},
	})
	emu.AddHook("", "GetComputerNameExW", &Hook{
		Parameters: []string{"NameType", "lpBuffer", "nSize"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			in.Hook.Parameters[0] = "s:NameType"
			switch in.Args[0] {
			case 0:
				in.Hook.Values[0] = "ComputerNameDnsDomain"
			case 1:
				in.Hook.Values[0] = "ComputerNameDnsFullyQualified"
			case 2:
				in.Hook.Values[0] = "ComputerNameDnsHostname"
				emu.Uc.MemWrite(in.Args[1], util.AsciiToWinWChar(emu.Opts.ComputerName+"\u0000"))
			case 3:
				in.Hook.Values[0] = "ComputerNameNetBIOS"
				emu.Uc.MemWrite(in.Args[1], util.AsciiToWinWChar(emu.Opts.ComputerName+"\u0000"))
			case 4:
				in.Hook.Values[0] = "ComputerNamePhysicalDnsDomain"
			case 5:
				in.Hook.Values[0] = "ComputerNamePhysicalDnsFullyQualified"
				emu.Uc.MemWrite(in.Args[1], util.AsciiToWinWChar(emu.Opts.ComputerName+"\u0000"))
			case 6:
				in.Hook.Values[0] = "ComputerNamePhysicalDnsHostname"
				emu.Uc.MemWrite(in.Args[1], util.AsciiToWinWChar(emu.Opts.ComputerName+"\u0000"))
			case 7:
				in.Hook.Values[0] = "ComputerNamePhysicalNetBIOS"
				emu.Uc.MemWrite(in.Args[1], util.AsciiToWinWChar(emu.Opts.ComputerName+"\u0000"))
			}
			return SkipFunctionStdCall(true, 0x1)(emu, in)
		},
	})
	emu.AddHook("", "GetNativeSystemInfo", &Hook{
		Parameters: []string{"lpSystemInfo"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			return getSystemInfo(emu, in)(emu, in)
		},
	})

	emu.AddHook("", "GetSystemInfo", &Hook{
		Parameters: []string{"lpSystemInfo"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			return getSystemInfo(emu, in)(emu, in)
		},
	})
}
