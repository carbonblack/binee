package windows

func OleHooks(emu *WinEmulator) {
	emu.AddHook("", "OleLoadFromStream", &Hook{
		Parameters: []string{"LPOLESTREAM", "a:LPCSTR", "LPOLECLIENT", "LHCLIENTDOC", "a:LPCSTR", "LPOLEOBJECT"},
		Fn:         SkipFunctionStdCall(true, 0x1),
	})
}
