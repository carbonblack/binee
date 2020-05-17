package windows

func User32Hooks(emu *WinEmulator) {
	emu.AddHook("", "GetWindowRect", &Hook{Parameters: []string{"hWnd", "lpRect"}, Fn: SkipFunctionStdCall(true, 0x1)})
	emu.AddHook("", "CreateDialogParamA", &Hook{Parameters: []string{"hInstance", "a:lpTemplateName", "hWndParent", "lpDialogFunc", "dwInitParam"}, Fn: SkipFunctionStdCall(true, 0x1)})
	emu.AddHook("", "MapWindowPoints", &Hook{Parameters: []string{"hWndFrom", "hWndTo", "lpPoints", "cPoints"}, Fn: SkipFunctionStdCall(true, 0x1)})
	emu.AddHook("", "NtUserGetThreadState", &Hook{
		Parameters: []string{"Routine"},
	})
	emu.AddHook("", "ShowWindow", &Hook{Parameters: []string{"hWnd", "nCmdShow"}, Fn: SkipFunctionStdCall(true, 0x1)})
	emu.AddHook("", "SendMessageA", &Hook{Parameters: []string{"hWnd", "Msg", "wParam", "lParam"}, Fn: SkipFunctionStdCall(true, 0x1)})
	emu.AddHook("", "SetCursorPos", &Hook{Parameters: []string{"X", "Y"}, Fn: SkipFunctionStdCall(true, 0x1)})
	emu.AddHook("", "SetTimer", &Hook{Parameters: []string{"hWnd", "nIDEvent", "uElapse", "lpTimerFunc"}, Fn: SkipFunctionStdCall(true, 0x1)})
	emu.AddHook("", "wsprintfA", &Hook{
		Parameters: []string{"lpstr", "a:lpcstr"},
	})
	emu.AddHook("", "wvsprintfA", &Hook{
		Parameters: []string{"lpstr", "a:lpcstr", "arglist"},
	})

	emu.AddHook("", "DialogBoxParamA", &Hook{
		Parameters: []string{"hInstance", "a:lpTemplateName", "hWndParent", "lpDialogFunc", "dwInitParam"},
		Fn:         SkipFunctionStdCall(true, 1),
	})
}
