package windows

func ShlobjCoreHooks(emu *WinEmulator) {
	emu.AddHook("", "SHGetSpecialFolderPathA", &Hook{
		Parameters: []string{"hwnd", "a:pszPath", "csidl", "fCreate"},
		Fn:         SkipFunctionStdCall(true, 0x1),
	})
	emu.AddHook("", "SHChangeNotify", &Hook{
		Parameters: []string{"wEventId", "uFlags", "dwItem1", "dwItem2"},
		Fn:         SkipFunctionStdCall(false, 1),
	})
}
