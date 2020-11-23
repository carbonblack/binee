package windows

func ShlwapiHooks(emu *WinEmulator) {
	emu.AddHook("", "StrStrW", &Hook{
		Parameters: []string{"w:pszFirst", "w:pszSrch"},
	})
	emu.AddHook("", "StrChrW", &Hook{
		Parameters: []string{"w:pszStart", "w:wMatch"},
	})

	emu.AddHook("", "PathFindFileNameA", &Hook{
		Parameters: []string{"a:pszPath"},
		Fn:         SkipFunctionStdCall(true, 0),
	})

	emu.AddHook("", "GetOpenBriefcaseInfo", &Hook{
		Parameters: []string{"dstCase", "rawCase"},
		Fn:         SkipFunctionStdCall(true, 0),
	})
}
