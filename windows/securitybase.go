package windows

func SecuritybaseHooks(emu *WinEmulator) {
	emu.AddHook("", "AdjustTokenPrivileges", &Hook{
		Parameters: []string{"TokenHandle", "DisableAllPrivileges", "NewState", "BufferLength", "PreviousState", "ReturnLength"},
		Fn:         SkipFunctionStdCall(true, 0x1),
	})
}
