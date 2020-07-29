package windows

func ShlwapiHooks(emu *WinEmulator) {
	emu.AddHook("", "StrStrW", &Hook{
		Parameters: []string{"w:pszFirst", "w:pszSrch"},
	})
	emu.AddHook("", "StrChrW", &Hook{
		Parameters: []string{"w:pszStart", "w:wMatch"},
	})
}
