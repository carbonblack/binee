package windows

func UtilapiHooks(emu *WinEmulator) {
	emu.AddHook("", "Beep", &Hook{Parameters: []string{"dwFreq", "dwDuration"}, Fn: SkipFunctionStdCall(true, 0x1)})
}
