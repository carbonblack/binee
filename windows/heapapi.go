package windows

func HeapapiHooks(emu *WinEmulator) {
	emu.AddHook("", "DuplicateHandle", &Hook{
		Parameters: []string{"hSourceProcessHandle", "hSourceHandle", "hTargetProcessHandle", "lpTargetHandle", "dwDesiredAccess", "bInheritHandle", "dwOptions"},
		Fn:         SkipFunctionStdCall(true, 0x1),
	})
	emu.AddHook("", "HeapAlloc", &Hook{
		Parameters: []string{"hHeap", "dwFlags", "dwBytes"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			addr := emu.Heap.Malloc(in.Args[2])
			return SkipFunctionStdCall(true, addr)(emu, in)
		},
	})
	emu.AddHook("", "HeapCreate", &Hook{
		Parameters: []string{"flOptions", "dwInitialSize", "dwMaximumSize"},
		Fn:         SkipFunctionStdCall(true, 0x123456),
	})
	emu.AddHook("", "HeapDestroy", &Hook{
		Parameters: []string{"hHeap"},
	})
	emu.AddHook("", "HeapFree", &Hook{
		Parameters: []string{"hHeap", "dwFlags", "lpMem"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			size := emu.Heap.Size(in.Args[2])
			if size == 0 {
				return SkipFunctionStdCall(true, ERROR_INVALID_ADDRESS)(emu, in)
			}
			nullBytes := make([]byte, size)
			if err := emu.Uc.MemWrite(in.Args[2], nullBytes); err != nil {
				return SkipFunctionStdCall(true, ERROR_INVALID_ADDRESS)(emu, in)
			}
			success := emu.Heap.Free(in.Args[2])
			return SkipFunctionStdCall(true, success)(emu, in)
		},
		NoLog: true,
	})
	emu.AddHook("", "HeapSetInformation", &Hook{
		Parameters: []string{"HeapHandle", "HeapInformationClass", "HeapInformation", "HeapInformationLength"},
		Fn:         SkipFunctionStdCall(true, 0x1),
	})
	emu.AddHook("", "HeapSize", &Hook{
		Parameters: []string{"hHeap", "dwFlags", "lpMem"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			return SkipFunctionStdCall(true, emu.Heap.Size(in.Args[2]))(emu, in)
		},
	})
	emu.AddHook("", "HeapReAlloc", &Hook{
		Parameters: []string{"hHeap", "dwFlags", "lpMem", "dwBytes"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			addr, oldSize := emu.Heap.ReAlloc(in.Args[2], in.Args[3])
			// new address given, move bytes
			if addr != in.Args[2] {
				buf, _ := emu.Uc.MemRead(in.Args[2], oldSize)
				emu.Uc.MemWrite(addr, buf)
			}
			return SkipFunctionCdecl(true, addr)(emu, in)
		},
	})
	emu.AddHook("", "HeapValidate", &Hook{
		Parameters: []string{"hHeap", "dwFlags", "lpMem"},
		Fn:         SkipFunctionStdCall(true, 0x1),
	})

}
