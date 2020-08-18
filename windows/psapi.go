package windows

func PsapiHooks(emu *WinEmulator) {
	emu.AddHook("", "K32GetModuleInformation", &Hook{
		Parameters: []string{"hProcess", "hModule", "lpmodeinfo", "cb"},
		Fn:         SkipFunctionStdCall(true, 0x1337),
	})
}
