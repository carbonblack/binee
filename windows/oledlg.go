package windows

func OledlgHooks(emu *WinEmulator) {
	emu.AddHook("", "OleUIUpdateLinksA", &Hook{
		Parameters: []string{"lpOleUILinkCntr", "hwndParent", "lpszTitle", "cLinks"},
		Fn:         SkipFunctionStdCall(true, 0x1),
	})
}
