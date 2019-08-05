package windows

func ShellapiHooks(emu *WinEmulator) {
	emu.AddHook("", "SHGetFileInfoA", &Hook{
		Parameters: []string{"a:pszPath", "dwFileAttributes", "psfi", "cbFileInfo", "uFlags"},
		Fn:         SkipFunctionStdCall(false, 0),
	})
}
