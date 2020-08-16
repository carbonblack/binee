package windows

func Ktmw32Hooks(emu *WinEmulator) {

	emu.AddHook("", "CreateTransaction", &Hook{
		Parameters: []string{"lpTransactionAttributes", "UOW", "CreateOptions", "IsolationLevel", "Timeout", "a:Description"},
		Fn:         SkipFunctionStdCall(true, 0x1373),
	})

	emu.AddHook("", "CreateFileTransactedA", &Hook{
		Parameters: []string{"a:lpFileName", "dwDesiredAccess",
			"dwShareMode", "lpSecurityAttributes", "dwCreationDisposition",
			"dwFlagsAndAttributes", "hTemplateFile", "hTransaction", "pusMiniVersion", "lpExtendedParameter"},
		Fn: SkipFunctionStdCall(true, 0x13),
	})
	emu.AddHook("", "CreateFileTransactedW", &Hook{
		Parameters: []string{"w:lpFileName", "dwDesiredAccess",
			"dwShareMode", "lpSecurityAttributes", "dwCreationDisposition",
			"dwFlagsAndAttributes", "hTemplateFile", "hTransaction", "pusMiniVersion", "lpExtendedParameter"},
		Fn: SkipFunctionStdCall(true, 0x13),
	})

	emu.AddHook("", "RollBackTransaction", &Hook{
		Parameters: []string{"TransactionHandle"},
		Fn:         SkipFunctionStdCall(true, 0x1),
	})
}
