package windows

func Namedpipeapi(emu *WinEmulator) {
	emu.AddHook("", "CreatePipe", &Hook{
		Parameters: []string{"hReadPipe", "hWritePipe", "lpPipeAttributes", "nSize"},
		Fn:         SkipFunctionStdCall(true, 0x1337),
	})
	emu.AddHook("", "DisconnectNamedPipe", &Hook{
		Parameters: []string{"hNamedPipe"},
		Fn:         SkipFunctionStdCall(true, 0x1337),
	})
	emu.AddHook("", "PeekNamedPipe", &Hook{
		Parameters: []string{"hNamedPipe", "lpBuffer", "nBufferSize", "lpBytesRead", "lpTotalBytesAvail", "lpBytesLeftThisMessage"},
		Fn:         SkipFunctionStdCall(true, 0x1337),
	})

}
