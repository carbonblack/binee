package windows

func SecuritybaseHooks(emu *WinEmulator) {
	emu.AddHook("", "AdjustTokenPrivileges", &Hook{
		Parameters: []string{"TokenHandle", "DisableAllPrivileges", "NewState", "BufferLength", "PreviousState", "ReturnLength"},
		Fn:         SkipFunctionStdCall(true, 0x1),
	})
	emu.AddHook("", "InitializeAcl", &Hook{
		Parameters: []string{"pAcl", "nAclLength", "dwAclRevision"},
		Fn:         SkipFunctionStdCall(true, 1),
	})

	emu.AddHook("", "SetSecurityInfo", &Hook{
		Parameters: []string{"handle", "ObjectType", "SecurityInfo", "psidOwner", "psidGroup", "pDacl", "pSacl"},
		Fn:         SkipFunctionStdCall(true, ERROR_SUCCESS),
	})
}
