package windows

func virtualAlloc(emu *WinEmulator, in *Instruction) bool {
	baseAddr := in.Args[0]
	size := in.Args[1]
	addr, _ := emu.Heap.MMap(baseAddr, size)
	return SkipFunctionStdCall(true, addr)(emu, in)
}
func virtualFree(emu *WinEmulator, in *Instruction) bool {
	start := in.Args[0]
	size := in.Args[1]
	var memType string
	switch in.Args[2] {
	case MEM_RELEASE:
		memType = "MEM_RELEASE"
		break
	case MEM_DECOMMIT:
		memType = "MEM_DECOMMIT"
		break
	case MEM_COALESCE_PLACEHOLDERS:
		memType = "MEM_COALESCE_PLACEHOLDERS"
		break
	case MEM_PRESERVE_PLACEHOLDER:
		memType = "MEM_PRESERVE_PLACEHOLDER"
		break
	}
	in.Hook.Values[2] = memType
	if size == 0 && emu.Heap.Free(start) == 1 {
		return SkipFunctionStdCall(true, 0)(emu, in)
	}
	return SkipFunctionStdCall(true, 0)(emu, in)
}
func MemoryApiHooks(emu *WinEmulator) {

	emu.AddHook("", "VirtualAlloc", &Hook{
		Parameters: []string{"lpAddress", "dwSize", "flAllocationType", "flProtect"},
		Fn:         virtualAlloc,
	})
	emu.AddHook("", "VirtualFree", &Hook{
		Parameters: []string{"lpAddress", "dwSize", "dwFreeType"},
		Fn:         virtualFree,
	})

	emu.AddHook("", "VirtualAllocEx", &Hook{
		Parameters: []string{"hProcess", "lpAddress", "dwSize", "flAllocationType", "flProtect"},
	})
	emu.AddHook("", "VirtualProtect", &Hook{
		Parameters: []string{"lpAddress", "dwSize", "flNewProtect", "lpflOldProtect"},
		Fn:         SkipFunctionStdCall(true, 0x1),
	})
}
