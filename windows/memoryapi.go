package windows

func MemoryApiHooks(emu *WinEmulator) {
	emu.AddHook("", "VirtualAlloc", &Hook{
		Parameters: []string{"lpAddress", "dwSize", "flAllocationType", "flProtect"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			lpAddress := in.Args[0] //where he wants to find some free memory
			dwSize := in.Args[1]    //how much memory wants
			flAllocationType := in.Args[2]
			//tbh he should only allocate memory when he commits, but idk why binee splits MEM_COMMIT|MEM_RESERVE in 2
			//separate calls
			if flAllocationType == MEM_RESERVE {
				addr := emu.Heap.Malloc(dwSize)
				return SkipFunctionStdCall(true, addr)(emu, in)
			} else if flAllocationType == MEM_COMMIT {
				//return the address that he asked
				return SkipFunctionStdCall(true, lpAddress)(emu, in)
			} else {
				//TODO
				return SkipFunctionStdCall(true, 0x123)(emu, in)
			}

		},
	})
	emu.AddHook("", "VirtualAllocEx", &Hook{
		Parameters: []string{"hProcess", "lpAddress", "dwSize", "flAllocationType", "flProtect"},
	})
	emu.AddHook("", "VirtualProtect", &Hook{
		Parameters: []string{"lpAddress", "dwSize", "flNewProtect", "lpflOldProtect"},
		Fn:         SkipFunctionStdCall(true, 0x1),
	})
}
