package windows

func ComctlHooks(emu *WinEmulator) {
	emu.AddHook("", "InitCommonControls", &Hook{Parameters: []string{}, Fn: SkipFunctionStdCall(false, 0)})
	emu.AddHook("", "ImageList_Destroy", &Hook{Parameters: []string{"himl"}, Fn: SkipFunctionStdCall(true, 1)})
}
