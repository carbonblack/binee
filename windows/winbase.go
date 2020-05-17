package windows

import (
	"github.com/carbonblack/binee/pefile"
	"strconv"
	"strings"

	"github.com/carbonblack/binee/util"
)

func FindResource(emu *WinEmulator, in *Instruction) bool {
	var resourceName interface{}
	var resourceType interface{}
	wide := in.Hook.Name[len(in.Hook.Name)-1] == 'W'
	resourceNameArg := in.Args[1]
	resourceTypeArg := in.Args[2]
	resourceName = uint32(resourceNameArg)
	resourceType = uint32(resourceTypeArg)
	if (resourceNameArg >> 16) > 0 {
		if wide {
			resourceName = util.ReadWideChar(emu.Uc, resourceNameArg, 0)
		} else {
			resourceName = util.ReadASCII(emu.Uc, resourceNameArg, 0)
		}
		if resourceName.(string)[0] == '#' {
			var err error
			resourceName, err = strconv.Atoi(resourceName.(string)[1:])
			if err != nil {
				return SkipFunctionStdCall(true, 0)(emu, in) //Failed to parse
			}
		}
	}
	if (resourceTypeArg >> 16) > 0 {
		if wide {
			resourceType = util.ReadWideChar(emu.Uc, resourceTypeArg, 0)
		} else {
			resourceType = util.ReadASCII(emu.Uc, resourceTypeArg, 0)
		}
		if resourceType.(string)[0] == '#' {
			var err error
			resourceType, err = strconv.Atoi(resourceType.(string)[1:])
			if err != nil {
				return SkipFunctionStdCall(true, 0)(emu, in) //Failed to parse
			}
		}
	}

	handle := in.Args[0]
	if handle == emu.MemRegions.ImageAddress || handle == 0 {
		dataEntry := pefile.FindResource(emu.ResourcesRoot, resourceName, resourceType)
		if dataEntry == nil {
			return SkipFunctionStdCall(true, 0)(emu, in)
		}
		addr := emu.Heap.Malloc(4)
		handle := &Handle{ResourceDataEntry: dataEntry}
		emu.Handles[addr] = handle
		return SkipFunctionStdCall(true, addr)(emu, in)

	} else {
		//Handle for other loaded files.

	}
	return SkipFunctionStdCall(true, 0)(emu, in)
}

func emuResourceNames(emu *WinEmulator, in *Instruction) bool {
	var resourceType interface{}
	resourceTypeRaw := in.Args[1]
	resourceType = uint32(resourceTypeRaw)
	if (resourceTypeRaw >> 16) > 0 { //(IS_INTRESOURCE)
		wide := in.Hook.Name[0] == 'W'
		if wide {
			resourceType = util.ReadWideChar(emu.Uc, resourceTypeRaw, 0)
		} else {
			resourceType = util.ReadASCII(emu.Uc, resourceTypeRaw, 0)
		}
		if resourceType.(string)[0] == '#' {
			resourceType, _ = strconv.Atoi(resourceType.(string)[1:])
		}
	}
	SkipFunctionStdCall(true, 1)(emu, in) //Skip current function.
	lpFunction := in.Args[2]
	lParam := in.Args[3]
	//Its the same process handle
	if in.Args[0] == 0 {
		entriesParent := pefile.FindResourceType(emu.ResourcesRoot, resourceType)
		var parameters []uint64
		for _, entry := range entriesParent.Entries {
			if entry.Name != "" {
				length := len(entry.Name)
				addr := emu.Heap.Malloc(uint64(length))
				rawEntry := []byte(entry.Name)
				rawEntry = append(rawEntry, 0)
				emu.Uc.MemWrite(addr, rawEntry)
				parameters = []uint64{in.Args[0], in.Args[1], addr, lParam}
			} else {
				parameters = []uint64{in.Args[0], in.Args[1], uint64(entry.ID), lParam}
			}
			CallStdFunction(emu, lpFunction, parameters)
		}
	}
	return true
}

func getCurrentDirectory(emu *WinEmulator, in *Instruction) bool {
	wide := in.Hook.Name[len(in.Hook.Name)-1] == 'W'
	workingDir := "c:\\windows"
	maxLength := in.Args[0]
	if maxLength <= uint64(len(workingDir)) { //we added or equal because we need a character for termination
		return SkipFunctionStdCall(true, 0)(emu, in) //Failed
	}
	var rawBytes []byte
	if wide {
		rawBytes = append(util.ASCIIToWinWChar(workingDir), 0, 0)

	} else {
		rawBytes = append([]byte(workingDir), 0)
	}
	emu.Uc.MemWrite(in.Args[1], rawBytes)
	return SkipFunctionStdCall(true, uint64(len(workingDir)))(emu, in)
}

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
			key := util.ReadASCII(emu.Uc, in.Args[0], int(in.Args[2]))
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
			emu.setLastError(0xcb)
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
				buf := util.ASCIIToWinWChar(val)
				emu.Uc.MemWrite(in.Args[1], buf)
				return SkipFunctionStdCall(true, uint64(len(val)))(emu, in)
			}

			// set last error to 0xcb
			emu.setLastError(0xcb)
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

	emu.AddHook("", "FindResourceA", &Hook{
		Parameters: []string{"hModule", "a:lpName", "a:lpType"},
		Fn:         FindResource,
	})
	emu.AddHook("", "FindResourceW", &Hook{
		Parameters: []string{"hModule", "a:lpName", "a:lpType"},
		Fn:         FindResource,
	})

	emu.AddHook("", "EnumResourceNamesA", &Hook{
		Parameters: []string{"hModule", "a:lpType", "lpEnumFunc", "lParam"},
		Fn:         emuResourceNames,
	})
	emu.AddHook("", "EnumResourceNamesW", &Hook{
		Parameters: []string{"hModule", "w:lpType", "lpEnumFunc", "lParam"},
		Fn:         emuResourceNames,
	})

	emu.AddHook("", "LocalFree", &Hook{
		Parameters: []string{"hMem"},
		Fn:         SkipFunctionStdCall(true, 0),
	})

	emu.AddHook("", "GetCurrentDirectoryA", &Hook{
		Parameters: []string{"nBufferLength", "lpBuffer"},
		Fn:         getCurrentDirectory,
	})
	emu.AddHook("", "GetCurrentDirectoryW", &Hook{
		Parameters: []string{"nBufferLength", "lpBuffer"},
		Fn:         getCurrentDirectory,
	})

}
