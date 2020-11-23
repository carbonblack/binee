package windows

func Internal(emu *WinEmulator) {
	emu.AddHook("", "__getmainargs", &Hook{
		Parameters: []string{"_Argc", "_Argv", "_Env", "_DoWildCard", "_StartInfo"},
		Fn:         SkipFunctionCdecl(true, 0),
	})
	emu.AddHook("", "__wgetmainargs", &Hook{
		Parameters: []string{"_Argc", "_Argv", "_Env", "_DoWildCard", "_StartInfo"},
		Fn:         SkipFunctionCdecl(true, 0),
	})
}
