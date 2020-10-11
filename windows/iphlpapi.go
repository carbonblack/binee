package windows

func IphlpapiHooks(emu *WinEmulator) {
	emu.AddHook("", "GetIpForwardTable", &Hook{
		Parameters: []string{"pIpForwardTable", "pdwSize", "bOrder"},
		Fn:         SkipFunctionStdCall(true, 0x122),
	})
}
