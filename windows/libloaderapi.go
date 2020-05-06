package windows

func LibloaderapiHooks(emu *WinEmulator) {
	emu.AddHook("", "DisableThreadLibraryCalls", &Hook{
		Parameters: []string{"hLibModule"},
		Fn:         SkipFunctionStdCall(true, 0x1),
	})

	emu.AddHook("", "ResolveDelayLoadedAPI", &Hook{
		Parameters: []string{"ParentModuleBase", "DelayloadedDescriptor", "FailureDllHook", "FailureSystemHook", "ThunkAddress", "Flags"},
		Fn:         SkipFunctionStdCall(true, 0x1),
	})

	emu.AddHook("", "SetDefaultDllDirectories", &Hook{
		Parameters: []string{"DirectoryFlags"},
		Fn:         SkipFunctionStdCall(true, 0x1),
	})

	emu.AddHook("", "LoadResource", &Hook{
		Parameters: []string{"hModule", "hResInfo"},
		Fn: func(emulator *WinEmulator, in *Instruction) bool {
			baseAddress := in.Args[0]
			if baseAddress == 0 { //if null then same module
				baseAddress = emu.MemRegions.ImageAddress
			}
			addr := in.Args[1]
			if _, ok := emu.Handles[addr]; !ok {
				return SkipFunctionStdCall(true, 0)(emu, in)
			}
			dataEntry := emu.Handles[addr].ResourceDataEntry
			location := baseAddress + uint64(dataEntry.OffsetToData)
			return SkipFunctionStdCall(true, location)(emu, in)
		},
	})
	emu.AddHook("", "SizeofResource", &Hook{
		Parameters: []string{"hModule", "hResInfo"},
		Fn: func(emulator *WinEmulator, in *Instruction) bool {
			addr := in.Args[1]
			if handle, ok := emu.Handles[addr]; ok {
				return SkipFunctionStdCall(true, uint64(handle.ResourceDataEntry.Size))(emu, in)
			}
			return SkipFunctionStdCall(true, 0)(emu, in)
		},
	})
	emu.AddHook("", "LockResource", &Hook{
		Parameters: []string{"HGlobal"},
		Fn: func(emulator *WinEmulator, in *Instruction) bool {
			return SkipFunctionStdCall(true, in.Args[0])(emu, in)
		},
	})
}
