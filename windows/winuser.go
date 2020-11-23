package windows

import (
	"encoding/binary"
	"github.com/carbonblack/binee/pefile"
)

func loadString(emu *WinEmulator, in *Instruction) bool {
	wide := in.Hook.Name[len(in.Hook.Name)-1] == 'W'
	if in.Args[0] == emu.MemRegions.ImageAddress {
		resourceID := uint32(((in.Args[1] & 0xFFFF) >> 4) + 1)
		typeID := uint32(6) //An enum should be added
		dataEntry := pefile.FindResource(emu.ResourcesRoot, resourceID, typeID)
		stringNum := in.Args[1] & 0x000f
		if dataEntry == nil {
			return SkipFunctionStdCall(true, 0)(emu, in)
		}
		bytes, _ := emu.Uc.MemRead(uint64(dataEntry.OffsetToData)+emu.MemRegions.ImageAddress, uint64(dataEntry.Size))
		index := uint64(0)
		//Strings in the resource are stored in a specific structure
		//we can assume it is {length: 2bytes, actualString:(length)bytes}
		//so to reach the wanted string we have to iterate on every length
		//and seek that length.
		for i := uint64(0); i < stringNum; i++ {
			index += (uint64(binary.LittleEndian.Uint16(bytes[index:index+2])) + 1) * 2
		}
		offset := uint64(dataEntry.OffsetToData) + emu.MemRegions.ImageAddress + index //stringNum is multiplied by 2 because its wide chars.

		if in.Args[3] == 0 {
			addr := make([]byte, 4)
			//TODO Enums should be added to represent size of data types.
			binary.LittleEndian.PutUint32(addr, uint32(offset+2))
			emu.Uc.MemWrite(in.Args[2], addr)

		}
		bytes, ok := emu.Uc.MemRead(offset, uint64(2))
		length := uint64(binary.LittleEndian.Uint16(bytes))
		if in.Args[3] > length {
			if ok == nil {
				bytes, ok = emu.Uc.MemRead(offset+2, length*2) //Multiplied by 2 because its a unicode string.
				if ok == nil {
					if !wide {
						actualString := pefile.WideStringToString(bytes, int(length*2))
						emu.Uc.MemWrite(in.Args[2], []byte(actualString))
						emu.Uc.MemWrite(in.Args[2]+length, []byte{0}) //Write null byte
					} else {
						emu.Uc.MemWrite(in.Args[2], bytes)
						emu.Uc.MemWrite(in.Args[2]+(2*length), []byte{0}) //Write null byte
					}
					return SkipFunctionStdCall(true, length)(emu, in)
				}
			}

		} else {
			bytes, ok := emu.Uc.MemRead(offset, in.Args[3])
			if ok != nil {
				emu.Uc.MemWrite(in.Args[2], bytes)
				return SkipFunctionStdCall(true, in.Args[3])(emu, in)
			}
		}
	} else {

		//This should be handled too
		//Loading for another module

	}
	return SkipFunctionStdCall(true, 0)(emu, in)
}

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

	emu.AddHook("", "LoadStringA", &Hook{
		Parameters: []string{"hInstance", "uID", "lpBuffer", "cchBufferMax"},
		Fn:         loadString,
	})
	emu.AddHook("", "LoadStringW", &Hook{
		Parameters: []string{"hInstance", "uID", "lpBuffer", "cchBufferMax"},
		Fn:         loadString,
	})

	emu.AddHook("", "GetSystemMetrics", &Hook{
		Parameters: []string{"nIndex"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			return SkipFunctionStdCall(true, 1)(emu, in)
		},
	})
	emu.AddHook("", "LoadBitmapA", &Hook{
		Parameters: []string{"hInstance", "a:lpBitmapName"},
		Fn:         SkipFunctionStdCall(true, 0x1337),
	})
	emu.AddHook("", "LoadBitmapW", &Hook{
		Parameters: []string{"hInstance", "w:lpBitmapName"},
		Fn:         SkipFunctionStdCall(true, 0x1337),
	})

	emu.AddHook("", "RegisterClassExA", &Hook{
		Parameters: []string{"arg1"},
		Fn:         SkipFunctionStdCall(true, 0x1337),
	})
	emu.AddHook("", "CreateWindowExA", &Hook{
		Parameters: []string{"dwExStyle", "a:lpClassName", "a:lpWindowName", "dwStyle", "X", "Y", "nWidth", "nHeight", "hWndParent", "hMenu", "hInstance", "lParam"},
		Fn:         SkipFunctionStdCall(true, 0x1337),
	})

	emu.AddHook("", "UpdateWindow", &Hook{
		Parameters: []string{"HWND"},
		Fn:         SkipFunctionStdCall(true, 0x13),
	})

	emu.AddHook("", "GetMessageA", &Hook{
		Parameters: []string{"lpMsg", "hWnd", "wMsgFilterMin", "wMsgFilterMax"},
		Fn:         SkipFunctionStdCall(true, 0),
	})

	emu.AddHook("", "GetWindowLongA", &Hook{
		Parameters: []string{"hWnd", "nIndex"},
		Fn:         SkipFunctionStdCall(true, 0x1337),
	})
	emu.AddHook("", "GetWindowLongW", &Hook{
		Parameters: []string{"hWnd", "nIndex"},
		Fn:         SkipFunctionStdCall(true, 0x1337),
	})
	emu.AddHook("", "GetWindowLongA", &Hook{
		Parameters: []string{"hWnd", "nIndex"},
		Fn:         SkipFunctionStdCall(true, 0x1337),
	})
	emu.AddHook("", "GetWindowLongW", &Hook{
		Parameters: []string{"hWnd", "nIndex"},
		Fn:         SkipFunctionStdCall(true, 0x1337),
	})

	emu.AddHook("", "SetWindowLongA", &Hook{
		Parameters: []string{"hWnd", "nIndex", "dwNewLong"},
		Fn:         SkipFunctionStdCall(true, 0x1337),
	})
	emu.AddHook("", "SetWindowLongW", &Hook{
		Parameters: []string{"hWnd", "nIndex", "dwNewLong"},
		Fn:         SkipFunctionStdCall(true, 0x1337),
	})

	emu.AddHook("", "SendNotifyMessageA", &Hook{
		Parameters: []string{"hWnd", "Msg", "wParam", "lParam"},
		Fn:         SkipFunctionStdCall(true, 0x1337),
	})

	emu.AddHook("", "SendInput", &Hook{
		Parameters: []string{"cInputs", "pInputs", "cbSize"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			return SkipFunctionStdCall(true, in.Args[2])(emu, in)
		},
	})

	emu.AddHook("", "PostMessageA", &Hook{
		Parameters: []string{"hWnd", "Msg", "wParam", "lParam"},
		Fn:         SkipFunctionStdCall(true, 1),
	})

	emu.AddHook("", "FindWindowA", &Hook{
		Parameters: []string{"a:lpClassName", "a:lpWindowName"},
		Fn:         SkipFunctionStdCall(true, 0x1337),
	})

	emu.AddHook("", "GetWindowThreadProcessId", &Hook{
		Parameters: []string{"hWnd", "lpdwProcessId"},
		Fn:         SkipFunctionStdCall(true, 0x1337),
	})

	emu.AddHook("", "GetDlgItem", &Hook{
		Parameters: []string{"hDlg", "nIDDlgItem"},
		Fn:         SkipFunctionStdCall(true, 0x1337),
	})

	emu.AddHook("", "GetPropA", &Hook{
		Parameters: []string{"hWnd", "a:lpString"},
		Fn:         SkipFunctionStdCall(true, 0x1337),
	})

	emu.AddHook("", "SetPropA", &Hook{
		Parameters: []string{"hWnd", "a:lpString", "hData"},
	})

	emu.AddHook("", "PostMessageW", &Hook{
		Parameters: []string{"hWnd", "Msg", "wParam", "lParam"},
		Fn:         SkipFunctionStdCall(true, 1),
	})

}
