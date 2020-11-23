package windows

func VcRuntimeHooks(emu *WinEmulator) {
	emu.AddHook("", "_lock", &Hook{
		Parameters: []string{"locknum"},
		Fn:         SkipFunctionCdecl(false, 0x0),
	})
	emu.AddHook("", "memset", &Hook{Parameters: []string{"dest", "char", "count"}})
	emu.AddHook("", "memcpy", &Hook{Parameters: []string{"dest", "char", "count"}})
	emu.AddHook("", "wmemcpy", &Hook{Parameters: []string{"dest", "char", "count"}})
	emu.AddHook("", "malloc", &Hook{
		Parameters: []string{"size"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			return SkipFunctionCdecl(true, emu.Heap.Malloc(in.Args[0]))(emu, in)
		},
	})
	emu.AddHook("", "free", &Hook{
		Parameters: []string{"memblock"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			emu.Heap.Free(in.Args[0])
			return SkipFunctionCdecl(false, 0)(emu, in)
		},
	})
	emu.AddHook("", "__telemetry_main_return_trigger", &Hook{})
	emu.AddHook("", "__vcrt_InitializeCriticalSectionEx", &Hook{
		Parameters: []string{"lpCriticalSection", "dwSpinCount", "Flags"},
	})
	emu.AddHook("", "_except_handler4_common", &Hook{Parameters: []string{}})
	emu.AddHook("", "_unlock", &Hook{
		Parameters: []string{"locknum"},
		Fn:         SkipFunctionCdecl(false, 0x0),
	})
	emu.AddHook("", "__crtLCMapStringA", &Hook{
		Parameters: []string{"lcid", "mapflags", "srclen", "src", "dstlen", "dst", "codepage", "xflag"},
		NoLog:      true,
	})
}
