package windows

import "encoding/binary"
import "binee/util"

type ServiceTableEntry struct {
	ServiceName string
	ServiceProc uint64
}

func startServiceCtrlDispatcher(emu *WinEmulator, addr uint64, wide bool) ServiceTableEntry {
	entry := ServiceTableEntry{}
	nameAddrBytes, _ := emu.Uc.MemRead(addr, emu.PtrSize)
	nameAddr := uint64(binary.LittleEndian.Uint32(nameAddrBytes))

	var name string
	if wide == true {
		name = util.ReadWideChar(emu.Uc, nameAddr, 0)
	} else {
		name = util.ReadAscii(emu.Uc, nameAddr, 0)
	}

	procAddrBytes, _ := emu.Uc.MemRead(addr+emu.PtrSize, emu.PtrSize)
	procAddr := uint64(binary.LittleEndian.Uint32(procAddrBytes))

	entry.ServiceName = name
	entry.ServiceProc = procAddr
	return entry
}

func AdvApi32Hooks(emu *WinEmulator) {
	emu.AddHook("", "StartServiceCtrlDispatcherA", &Hook{
		Parameters: []string{"v:lpServiceStartTable"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			entry := startServiceCtrlDispatcher(emu, in.Args[0], false)
			in.Hook.Values[0] = entry
			return SkipFunctionStdCall(true, 0x1)(emu, in)
		},
	})

	emu.AddHook("", "StartServiceCtrlDispatcherW", &Hook{
		Parameters: []string{"v:lpServiceStartTable"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			entry := startServiceCtrlDispatcher(emu, in.Args[0], true)
			in.Hook.Values[0] = entry
			return SkipFunctionStdCall(true, 0x1)(emu, in)
		},
	})
}
