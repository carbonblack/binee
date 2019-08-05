package windows

func PowrProf(emu *WinEmulator) {
	emu.AddHook("", "PowerReplaceDefaultPowerSchemes", &Hook{
		Parameters: []string{},
		Fn:         SkipFunctionStdCall(true, 0x0),
	})
}
