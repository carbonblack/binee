package windows

import "github.com/carbonblack/binee/util"

func getCommandLine(emu *WinEmulator, in *Instruction) bool {
	//This is a temporary implementation, we should depend on peb.
	wide := in.Hook.Name[len(in.Hook.Name)-1] == 'W'
	length := 0
	cmd := ""
	for i, _ := range emu.Args {
		length += len(emu.Args[i])
		cmd += emu.Args[i] + " "
	}
	cmd = cmd[:len(cmd)-1]
	var raw []byte

	if wide {
		raw = append(util.ASCIIToWinWChar(cmd), 0, 0)
	} else {
		raw = append([]byte(cmd), 0)
	}
	addr := emu.Heap.Malloc(uint64(len(raw)))
	if err := emu.Uc.MemWrite(addr, raw); err != nil {
		return SkipFunctionStdCall(true, 0)(emu, in)
	}
	return SkipFunctionStdCall(true, addr)(emu, in)
}

func Processenv(emu *WinEmulator) {
	emu.AddHook("", "GetCommandLineW", &Hook{
		Parameters: []string{},
		Fn:         getCommandLine,
	})
	emu.AddHook("", "GetCommandLineA", &Hook{
		Parameters: []string{},
		Fn:         getCommandLine,
	})
}
