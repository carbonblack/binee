package windows

func SyncapiHooks(emu *WinEmulator) {
	emu.AddHook("", "AcquireSRWLockExclusive", &Hook{
		Parameters: []string{"SRWLock"},
		Fn:         SkipFunctionStdCall(false, 0x0),
	})
	emu.AddHook("", "CreateEventA", &Hook{
		Parameters: []string{"lpEventAttributes", "bManualReset", "bInitialState", "a:lpName"},
		Fn:         SkipFunctionStdCall(false, 0x1),
	})
	emu.AddHook("", "CreateEventW", &Hook{
		Parameters: []string{"lpEventAttributes", "bManualReset", "bInitialState", "w:lpName"},
		Fn:         SkipFunctionStdCall(false, 0x1),
	})
	emu.AddHook("", "CreateMutexA", &Hook{
		Parameters: []string{"lpMutexAttributes", "bInitialOwner", "a:lpName"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			handle := emu.Heap.Malloc(emu.PtrSize)
			return SkipFunctionStdCall(true, handle)(emu, in)
		},
	})
	emu.AddHook("", "CreateMutexW", &Hook{
		Parameters: []string{"lpMutexAttributes", "bInitialOwner", "w:lpName"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			handle := emu.Heap.Malloc(emu.PtrSize)
			return SkipFunctionStdCall(true, handle)(emu, in)
		},
	})
	emu.AddHook("", "OpenMutexA", &Hook{
		Parameters: []string{"lpMutexAttributes", "bInitialOwner", "a:lpName"},
		Fn:         SkipFunctionStdCall(true, 0),
	})
	emu.AddHook("", "OpenMutexW", &Hook{
		Parameters: []string{"lpMutexAttributes", "bInitialOwner", "w:lpName"},
		Fn:         SkipFunctionStdCall(true, 0),
	})
	emu.AddHook("", "ReleaseSRWLockExclusive", &Hook{
		Parameters: []string{"SRWLock"},
		Fn:         SkipFunctionStdCall(false, 0x0),
	})
	emu.AddHook("", "SleepEx", &Hook{
		Parameters: []string{"dwMilliSeconds", "bAlertable"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			emu.Ticks += in.Args[0]
			return SkipFunctionStdCall(false, 0x0)(emu, in)
		},
	})

	emu.AddHook("", "ReleaseMutex", &Hook{
		Parameters: []string{"hMutex"},
		Fn:         SkipFunctionStdCall(true, 0),
	})
}
