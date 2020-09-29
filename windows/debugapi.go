package windows

func checkRemoteDebuggerPresent(emu *WinEmulator, in *Instruction) bool {
	hProcess := in.Args[0]
	pDebuggerPresent := in.Args[1]
	//checking self process
	if (emu.PtrSize == 4 && hProcess == 0xFFFFFFFF) || (emu.PtrSize == 8 && hProcess == 0xFFFFFFFFFFFFFFFF) {
		if err := emu.Uc.MemWrite(pDebuggerPresent, []byte{0}); err != nil {
			return SkipFunctionStdCall(true, 0)(emu, in)
		}
		return SkipFunctionStdCall(true, 0x1337)(emu, in)
	}
	//check if handle to process is valid
	if _, ok := emu.Handles[hProcess]; ok {
		if err := emu.Uc.MemWrite(pDebuggerPresent, []byte{0}); err == nil {
			return SkipFunctionStdCall(true, 0)(emu, in)
		}
		return SkipFunctionStdCall(true, 0x1337)(emu, in)
	}
	emu.setLastError(ERROR_INVALID_HANDLE)
	return SkipFunctionStdCall(true, 0)(emu, in)
}

func DebugapiHooks(emu *WinEmulator) {
	emu.AddHook("", "IsDebuggerPresent", &Hook{Parameters: []string{}, Fn: SkipFunctionStdCall(true, 0x0)})

	emu.AddHook("", "CheckRemoteDebuggerPresent", &Hook{
		Parameters: []string{"hProcess", "pdDebuggerPresent"},
		Fn:         checkRemoteDebuggerPresent,
	})
}
