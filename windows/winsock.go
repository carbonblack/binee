package windows

func WinsockHooks(emu *WinEmulator) {
	emu.AddHook("", "WSACleanup", &Hook{
		Fn: SkipFunctionStdCall(true, ERROR_SUCCESS),
	})
}
