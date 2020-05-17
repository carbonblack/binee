package windows

func ShellapiHooks(emu *WinEmulator) {
	emu.AddHook("", "SHGetFileInfoA", &Hook{
		Parameters: []string{"a:pszPath", "dwFileAttributes", "psfi", "cbFileInfo", "uFlags"},
		Fn:         SkipFunctionStdCall(false, 0),
	})
	emu.AddHook("", "FindExecutableA", &Hook{
		Parameters: []string{"a:lpFile", "a:lpDirectory", "a:lpResult"},
		Fn: func(emulator *WinEmulator, in *Instruction) bool {
			result := "C:\\WINDOWS\\system32\\LaunchWinApp.exe"
			emu.Uc.MemWrite(in.Args[2], append([]byte(result), 0))
			return SkipFunctionStdCall(true, 33)(emu, in)
		},
	})

}
