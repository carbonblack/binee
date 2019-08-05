package windows

func Ole2Hooks(emu *WinEmulator) {
	emu.AddHook("", "OleInitialize", &Hook{Parameters: []string{"pvReserved"}, Fn: SkipFunctionStdCall(true, 0x0)})
	emu.AddHook("", "OleUninitialize", &Hook{Parameters: []string{}, Fn: SkipFunctionStdCall(false, 0x0)})
}
