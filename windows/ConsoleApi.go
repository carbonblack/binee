package windows

func ConsoleApi(emu *WinEmulator) {

	emu.AddHook("", "GetConsoleProcessList", &Hook{
		Parameters: []string{"lpdwProcessList", "dwProcessCount"},
		Fn:         SkipFunctionStdCall(true, 5),
	})
	emu.AddHook("", "FreeConsole", &Hook{
		Parameters: []string{},
		Fn:         SkipFunctionStdCall(true, 0x5),
	})
	emu.AddHook("", "AttachConsole", &Hook{
		Parameters: []string{"dwProcessId"},
		Fn:         SkipFunctionStdCall(true, 0x5),
	})
	emu.AddHook("", "GetConsoleWindow", &Hook{
		Parameters: []string{},
		Fn:         SkipFunctionStdCall(true, 0x1337),
	})

}
