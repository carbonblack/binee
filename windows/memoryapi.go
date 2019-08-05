package windows

func MemoryApiHooks(emu *WinEmulator) {
	emu.AddHook("", "VirtualAlloc", &Hook{
		Parameters: []string{"lpAddress", "dwSize", "flAllocationType", "flProtect"},
	})
	emu.AddHook("", "VirtualAllocEx", &Hook{
		Parameters: []string{"hProcess", "lpAddress", "dwSize", "flAllocationType", "flProtect"},
	})
	emu.AddHook("", "VirtualProtect", &Hook{
		Parameters: []string{"lpAddress", "dwSize", "flNewProtect", "lpflOldProtect"},
		Fn:         SkipFunctionStdCall(true, 0x1),
	})
}
