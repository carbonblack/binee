package windows

func ShlobjCoreHooks(emu *WinEmulator) {
	emu.AddHook("", "SHGetSpecialFolderPathA", &Hook{
		Parameters: []string{"hwnd", "a:pszPath", "csidl", "fCreate"},
		Fn:         SkipFunctionStdCall(true, 0x1),
	})
}
