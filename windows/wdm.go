package windows

func WdmHooks(emu *WinEmulator) {
	emu.AddHook("", "InterlockedExchange", &Hook{
		Parameters: []string{"Target", "Value"},
	})

	emu.AddHook("", "DbgPrint", &Hook{
		Parameters: []string{"a:format"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			_ = in.vfprintfHelper(0)

			return SkipFunctionCdecl(true, STATUS_SUCCESS)(emu, in)
		},
	})
}
