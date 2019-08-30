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
}
