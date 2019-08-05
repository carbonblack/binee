package windows

import (
	"binee/util"
	"strings"
)

func WinbaseHooks(emu *WinEmulator) {
	emu.AddHook("", "AddAtomA", &Hook{
		Parameters: []string{"a:lpString"},
	})
	emu.AddHook("", "AddAtomW", &Hook{
		Parameters: []string{"w:lpString"},
	})
	emu.AddHook("", "GetEnvironmentVariableA", &Hook{
		Parameters: []string{"a:lpName", "lpBuffer", "nSize"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			key := util.ReadAscii(emu.Uc, in.Args[0], int(in.Args[2]))
			key = strings.Trim(key, "\x00")
			key = strings.Trim(key, "\u0000")

			var val string
			for _, data := range emu.Opts.Env {
				if data.Key == key {
					val = data.Value
					break
				}
			}

			if val != "" {
				buf := []byte(val)
				emu.Uc.MemWrite(in.Args[1], buf)
				return SkipFunctionStdCall(true, uint64(len(val)))(emu, in)
			}

			// set last error to 0xcb
			emu.SetLastError(0xcb)
			return SkipFunctionStdCall(true, 0x0)(emu, in)
		},
	})
	emu.AddHook("", "GetEnvironmentVariableW", &Hook{
		Parameters: []string{"w:lpName", "lpBuffer", "nSize"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			key := util.ReadWideChar(emu.Uc, in.Args[0], int(in.Args[2]))
			key = strings.Trim(key, "\x00")
			key = strings.Trim(key, "\u0000")

			var val string
			for _, data := range emu.Opts.Env {
				if data.Key == key {
					val = data.Value
					break
				}
			}

			if val != "" {
				buf := util.AsciiToWinWChar(val)
				emu.Uc.MemWrite(in.Args[1], buf)
				return SkipFunctionStdCall(true, uint64(len(val)))(emu, in)
			}

			// set last error to 0xcb
			emu.SetLastError(0xcb)
			return SkipFunctionStdCall(true, 0x0)(emu, in)
		},
	})
	emu.AddHook("", "GlobalAlloc", &Hook{
		Parameters: []string{"uFlags", "dwBytes"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			addr := emu.Heap.Malloc(in.Args[1])
			return SkipFunctionCdecl(true, addr)(emu, in)
		},
	})
	emu.AddHook("", "IsBadReadPtr", &Hook{
		Parameters: []string{"lp", "ucb"},
	})
	emu.AddHook("", "LocalAlloc", &Hook{
		Parameters: []string{"uFlags", "uBytes"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			addr := emu.Heap.Malloc(in.Args[1])
			return SkipFunctionStdCall(true, addr)(emu, in)
		},
	})
	emu.AddHook("", "lstrcatA", &Hook{
		Parameters: []string{"a:lpString1", "a:lpString2"},
	})
	emu.AddHook("", "lstrcpyA", &Hook{
		Parameters: []string{"a:lpString1", "a:lpString2"},
	})
	emu.AddHook("", "lstrcpynA", &Hook{
		Parameters: []string{"lpString1", "a:lpString1", "iMaxLength"},
	})
	emu.AddHook("", "SetEnvironmentVariableA", &Hook{
		Parameters: []string{"a:lpName", "a:lpValue"},
		Fn:         SkipFunctionStdCall(true, 0x1),
	})
	emu.AddHook("", "strcpy", &Hook{
		Parameters: []string{"strDest", "a:strSource"},
	})
	emu.AddHook("", "strncpy", &Hook{
		Parameters: []string{"strDest", "a:strSource", "count"},
	})
	emu.AddHook("", "strlen", &Hook{
		Parameters: []string{"a:str"},
	})
	emu.AddHook("", "strnlen", &Hook{
		Parameters: []string{"a:str", "len"},
	})
	emu.AddHook("", "strrchr", &Hook{
		Parameters: []string{"a:str", "c"},
	})
	emu.AddHook("", "VerifyVersionInfoW", &Hook{
		Parameters: []string{"lpVersionInformation", "dwTypeMask", "dwlConditionMask"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			return SkipFunctionStdCall(true, 0x1)(emu, in)
		},
	})
	emu.AddHook("", "Wow64EnableWow64FsRedirection", &Hook{
		Parameters: []string{"Wow64FsEnableRedirection"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			return SkipFunctionStdCall(true, 0x1)(emu, in)
		},
	})

}
