package windows

func MmapiHooks(emu *WinEmulator) {
	emu.AddHook("", "mciSendString", &Hook{
		Parameters: []string{"a:lpszCommand", "lpszReturnString", "cchReturn", "hwndCallback"},
		Fn:         SkipFunctionStdCall(true, 0x0),
	})
	emu.AddHook("", "mciSendStringW", &Hook{
		Parameters: []string{"w:lpszCommand", "lpszReturnString", "cchReturn", "hwndCallback"},
		Fn:         SkipFunctionStdCall(true, 0x0),
	})

}
