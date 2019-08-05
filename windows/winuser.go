package windows

func WinuserHooks(emu *WinEmulator) {
	emu.AddHook("", "CharNextA", &Hook{
		Parameters: []string{"lpsz"},
	})
	emu.AddHook("", "CharPrevA", &Hook{
		Parameters: []string{"lpszStart", "lpszCurrent"},
	})
	emu.AddHook("", "DestroyWindow", &Hook{
		Parameters: []string{"hWnd"},
		Fn:         SkipFunctionStdCall(true, 0x1),
	})
	emu.AddHook("", "DrawEdge", &Hook{
		Parameters: []string{"hdc", "qrc", "edge", "grfFlags"},
		Fn:         SkipFunctionStdCall(true, 0x1),
	})
	emu.AddHook("", "GetKeyboardType", &Hook{
		Parameters: []string{"nTypeFlag"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			switch in.Args[0] {
			case 0:
				return SkipFunctionStdCall(true, uint64(emu.Opts.KeyboardType))(emu, in)
			case 1:
				return SkipFunctionStdCall(true, uint64(emu.Opts.KeyboardSubType))(emu, in)
			case 2:
				return SkipFunctionStdCall(true, uint64(emu.Opts.KeyboardFuncKeys))(emu, in)
			}
			return SkipFunctionStdCall(true, 0)(emu, in)
		},
	})
	emu.AddHook("", "GetSystemMetrics", &Hook{
		Parameters: []string{"nIndex"},
	})
	emu.AddHook("", "LoadAcceleratorsA", &Hook{
		Parameters: []string{"hInstance", "a:lpTableName"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			handle := emu.Heap.Malloc(emu.PtrSize)
			return SkipFunctionStdCall(true, handle)(emu, in)
		},
	})
	emu.AddHook("", "LoadAcceleratorsW", &Hook{
		Parameters: []string{"hInstance", "w:lpTableName"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			handle := emu.Heap.Malloc(emu.PtrSize)
			return SkipFunctionStdCall(true, handle)(emu, in)
		},
	})
	emu.AddHook("", "LoadCursorA", &Hook{
		Parameters: []string{"hInstance", "a:lpCursorName"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			handle := emu.Heap.Malloc(32 * 4)
			return SkipFunctionStdCall(true, handle)(emu, in)
		},
	})
	emu.AddHook("", "LoadCursorW", &Hook{
		Parameters: []string{"hInstance", "w:lpCursorName"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			handle := emu.Heap.Malloc(32 * 4)
			return SkipFunctionStdCall(true, handle)(emu, in)
		},
	})
	emu.AddHook("", "LoadIconA", &Hook{
		Parameters: []string{"hInstance", "a:lpIconName"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			handle := emu.Heap.Malloc(32 * 4)
			return SkipFunctionStdCall(true, handle)(emu, in)
		},
	})
	emu.AddHook("", "LoadIconW", &Hook{
		Parameters: []string{"hInstance", "w:lpIconName"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			handle := emu.Heap.Malloc(32 * 4)
			return SkipFunctionStdCall(true, handle)(emu, in)
		},
	})
	emu.AddHook("", "LoadStringA", &Hook{
		Parameters: []string{"hInstance", "uID", "lpBuffer", "cchBufferMax"},
		Fn:         SkipFunctionStdCall(true, 0x1),
	})
	emu.AddHook("", "MapVirtualKeyW", &Hook{
		Parameters: []string{"uCode", "uMapType"},
	})
	emu.AddHook("", "MessageBoxA", &Hook{
		Parameters: []string{"hWnd", "a:lpText", "a:lpCaption", "uType"},
		Fn:         SkipFunctionStdCall(true, 11),
	})
	emu.AddHook("", "MessageBoxIndirectA", &Hook{
		Parameters: []string{"lpmbp"},
		Fn:         SkipFunctionStdCall(true, 11),
	})
	emu.AddHook("", "PeekMessageA", &Hook{
		Parameters: []string{"lpMsg", "hWnd", "wMsgFilterMin", "wMsgFilterMax", "wRemoveMsg"},
		Fn:         SkipFunctionStdCall(true, 0x0),
	})
	emu.AddHook("", "RegisterClassA", &Hook{
		Parameters: []string{"lpWndClass"},
		Fn:         SkipFunctionStdCall(true, 0x1),
	})
	emu.AddHook("", "RegisterClipboardFormatA", &Hook{
		Parameters: []string{"a:lpszFormat"},
		Fn:         SkipFunctionStdCall(true, 0xC000),
	})
	emu.AddHook("", "RegisterClipboardFormatW", &Hook{
		Parameters: []string{"w:lpszFormat"},
		Fn:         SkipFunctionStdCall(true, 0xC000),
	})
	emu.AddHook("", "RegisterWindowMessageA", &Hook{
		Parameters: []string{"a:lpString"},
		Fn:         SkipFunctionStdCall(true, 0xC001),
	})
	emu.AddHook("", "RegisterWindowMessageW", &Hook{
		Parameters: []string{"w:lpString"},
		Fn:         SkipFunctionStdCall(true, 0xC001),
	})
	emu.AddHook("", "MsgWaitForMultipleObjects", &Hook{
		Parameters: []string{"nCount", "pHandles", "fWaitAll", "dwMilliseconds", "dwWakeMask"},
		Fn:         SkipFunctionStdCall(true, 0x0),
	})

}
