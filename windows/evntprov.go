package windows

func EvntprovHooks(emu *WinEmulator) {
	emu.AddHook("", "EventRegister", &Hook{
		Parameters: []string{"ProviderId", "EnableCallback", "CallbackContext", "RegHandle"},
		Fn:         SkipFunctionStdCall(true, 0x0),
	})
	emu.AddHook("", "EventSetInformation", &Hook{
		Parameters: []string{"RegHandle", "InformationClass", "EventInformation", "InformationLength"},
		Fn:         SkipFunctionStdCall(true, 0x0),
	})
}
