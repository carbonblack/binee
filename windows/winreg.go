package windows

import "github.com/carbonblack/binee/util"

func newRegKeyHandle(handle uint64, hkey string, name string) *Handle {
	return &Handle{
		Path:   "",
		Access: 0,
		File:   nil,
		Info:   nil,
		RegKey: &RegKey{hkey, name},
	}
}

func openRegKey(emu *WinEmulator, in *Instruction, hkey string, name string, outAddr uint64) func(emu *WinEmulator, in *Instruction) bool {
	// update print view
	in.Hook.Values[0] = hkeyMap(in.Args[0])
	in.Hook.Parameters[0] = "s:hKey"

	// check if the value actually exists
	if _, err := emu.Registry.Get(hkey, name); err != nil {
		return SkipFunctionStdCall(true, 0x1)
	}

	// create new handle
	handleAddr := emu.Heap.Malloc(4)
	handle := newRegKeyHandle(handleAddr, hkey, name)
	emu.Handles[handleAddr] = handle

	// write key handle to output result
	util.PutPointer(emu.Uc, emu.PtrSize, outAddr, handleAddr)

	return SkipFunctionStdCall(true, ERROR_SUCCESS)
}

func createRegKey(emu *WinEmulator, in *Instruction, hkey string, subkey string) func(emu *WinEmulator, in *Instruction) bool {
	reg := &Reg{hkey + "\\" + subkey, "", make(map[string]*Reg)}
	if err := emu.Registry.Insert(hkey, subkey, reg); err != nil {
		return SkipFunctionStdCall(true, 0x57)
	}
	return SkipFunctionStdCall(true, ERROR_SUCCESS)
}

func WinregHooks(emu *WinEmulator) {
	emu.AddHook("", "RegCloseKey", &Hook{
		Parameters: []string{"key"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			return SkipFunctionStdCall(true, ERROR_SUCCESS)(emu, in)
		},
	})

	emu.AddHook("", "RegCreateKeyA", &Hook{
		Parameters: []string{"hkey", "a:lpSubKey", "phkResult"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			in.Hook.Values[0] = hkeyMap(in.Args[0])
			in.Hook.Parameters[0] = "s:hKey"
			hkey := hkeyMap(in.Args[0])
			subkey := util.ReadASCII(emu.Uc, in.Args[1], 0)
			return createRegKey(emu, in, hkey, subkey)(emu, in)
		},
	})

	emu.AddHook("", "RegCreateKeyExA", &Hook{
		Parameters: []string{"hkey", "a:lpSubKey", "phkResult"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			in.Hook.Values[0] = hkeyMap(in.Args[0])
			in.Hook.Parameters[0] = "s:hKey"
			hkey := hkeyMap(in.Args[0])
			subkey := util.ReadASCII(emu.Uc, in.Args[1], 0)
			return createRegKey(emu, in, hkey, subkey)(emu, in)
		},
	})

	emu.AddHook("", "RegDeleteKeyA", &Hook{
		Parameters: []string{"hkey", "a:lpSubKey"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			in.Hook.Values[0] = hkeyMap(in.Args[0])
			in.Hook.Parameters[0] = "s:hKey"
			return SkipFunctionStdCall(true, ERROR_SUCCESS)(emu, in)
		},
	})

	emu.AddHook("", "RegDeleteKeyExA", &Hook{
		Parameters: []string{"hkey", "a:lpSubKey"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			in.Hook.Values[0] = hkeyMap(in.Args[0])
			in.Hook.Parameters[0] = "s:hKey"
			return SkipFunctionStdCall(true, ERROR_SUCCESS)(emu, in)
		},
	})

	emu.AddHook("", "RegEnumKeyExW", &Hook{
		Parameters: []string{"hKey", "dwIndex", "lpName", "lpcchName", "lpReserved", "lpClass", "lpcchClass", "lpftLastWriteTime"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			//get handle for hKey
			if keyHandle, ok := emu.Handles[in.Args[0]]; ok {
				if keyHandle.RegKey != nil {
					in.Hook.Values[0] = keyHandle.RegKey.Hkey + "\\" + keyHandle.RegKey.Name
					in.Hook.Parameters[0] = "s:hKey"
					// get index of key and write to pointers
					if reg, err := emu.Registry.Enum(keyHandle.RegKey.Hkey, keyHandle.RegKey.Name, int(in.Args[1])); err == nil {
						data, size := reg.Bytes()
						emu.Uc.MemWrite(in.Args[2], data)
						util.PutPointer(emu.Uc, 4, in.Args[3], uint64(size))
						return SkipFunctionStdCall(true, ERROR_SUCCESS)(emu, in)
					}
				}
			}

			return SkipFunctionStdCall(true, ERROR_NO_MORE_ITEMS)(emu, in)
		},
	})

	emu.AddHook("", "RegEnumValueA", &Hook{
		Parameters: []string{"hKey", "dwIndex", "a:lpValueName", "lpcchValueName", "lpreserved", "lpType", "lpData", "lpcbData"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			in.Hook.Values[0] = hkeyMap(in.Args[0])
			in.Hook.Parameters[0] = "s:hKey"
			return SkipFunctionStdCall(true, ERROR_SUCCESS)(emu, in)
		},
	})

	emu.AddHook("", "RegOpenKeyA", &Hook{
		Parameters: []string{"hKey", "a:lpSubKey", "phkResult"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			// update print view
			in.Hook.Values[0] = hkeyMap(in.Args[0])
			in.Hook.Parameters[0] = "s:hKey"

			// get hkey
			hkey := hkeyMap(in.Args[0])
			name := util.ReadASCII(emu.Uc, in.Args[1], 0)
			return openRegKey(emu, in, hkey, name, in.Args[2])(emu, in)
		},
	})

	emu.AddHook("", "RegOpenKeyEx", &Hook{
		Parameters: []string{"hKey", "a:lpSubKey", "ulOptions", "samDesired", "phkResult"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			// update print view
			in.Hook.Values[0] = hkeyMap(in.Args[0])
			in.Hook.Parameters[0] = "s:hKey"

			// get hkey
			hkey := hkeyMap(in.Args[0])
			name := util.ReadWideChar(emu.Uc, in.Args[1], 0)
			return openRegKey(emu, in, hkey, name, in.Args[2])(emu, in)
		},
	})

	emu.AddHook("", "RegOpenKeyExA", &Hook{
		Parameters: []string{"hKey", "a:lpSubKey", "ulOptions", "samDesired", "phkResult"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			// update print view
			in.Hook.Values[0] = hkeyMap(in.Args[0])
			in.Hook.Parameters[0] = "s:hKey"

			// get hkey
			hkey := hkeyMap(in.Args[0])
			name := util.ReadASCII(emu.Uc, in.Args[1], 0)
			return openRegKey(emu, in, hkey, name, in.Args[4])(emu, in)
		},
	})

	emu.AddHook("", "RegOpenKeyExW", &Hook{
		Parameters: []string{"hKey", "w:lpSubKey", "ulOptions", "samDesired", "phkResult"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			// update print view
			in.Hook.Values[0] = hkeyMap(in.Args[0])
			in.Hook.Parameters[0] = "s:hKey"

			// get hkey
			hkey := hkeyMap(in.Args[0])
			name := util.ReadWideChar(emu.Uc, in.Args[1], 0)
			return openRegKey(emu, in, hkey, name, in.Args[4])(emu, in)
		},
	})

	emu.AddHook("", "RegQueryValueExA", &Hook{
		Parameters: []string{"key", "a:lpValueName", "lpReserved", "lpType", "lpData", "lpcbData"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			key := emu.Handles[in.Args[0]]
			if key == nil {
				return SkipFunctionStdCall(true, 0x1)(emu, in)
			}
			name := util.ReadASCII(emu.Uc, in.Args[1], 0)

			if value, err := emu.Registry.Get(key.RegKey.Hkey, key.RegKey.Name+"\\"+name); err != nil {
				return SkipFunctionStdCall(true, 0x1)(emu, in)
			} else {
				valueBytes, valueType := value.Bytes()
				// write the registry type
				util.PutPointer(emu.Uc, 4, in.Args[3], uint64(valueType))
				// write the data
				emu.Uc.MemWrite(in.Args[4], valueBytes)
				// write the data size
				util.PutPointer(emu.Uc, 4, in.Args[5], uint64(len(valueBytes)))
				return SkipFunctionStdCall(true, ERROR_SUCCESS)(emu, in)
			}
		},
	})

	emu.AddHook("", "RegQueryValueExW", &Hook{
		Parameters: []string{"key", "w:lpValueName", "lpReserved", "lpType", "lpData", "lpcbData"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			key := emu.Handles[in.Args[0]]
			name := util.ReadWideChar(emu.Uc, in.Args[1], 0)

			if value, err := emu.Registry.Get(key.RegKey.Hkey, key.RegKey.Name+"\\"+name); err != nil {
				return SkipFunctionStdCall(true, 0x1)(emu, in)
			} else {
				valueBytes, valueType := value.Bytes()
				// write the registry type
				util.PutPointer(emu.Uc, 4, in.Args[3], uint64(valueType))
				// write the data
				emu.Uc.MemWrite(in.Args[4], valueBytes)
				// write the data size
				util.PutPointer(emu.Uc, 4, in.Args[5], uint64(len(valueBytes)))
				return SkipFunctionStdCall(true, ERROR_SUCCESS)(emu, in)
			}
		},
	})

	emu.AddHook("", "RegSetValueA", &Hook{
		Parameters: []string{"hKey", "a:lpSubKey", "dwType", "lpDate", "cbData"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			// update print view
			in.Hook.Values[0] = hkeyMap(in.Args[0])
			in.Hook.Parameters[0] = "s:hKey"
			hkey := hkeyMap(in.Args[0])
			subKey := util.ReadASCII(emu.Uc, in.Args[1], 0)
			value := util.ReadASCII(emu.Uc, in.Args[3], 0)
			reg := &Reg{hkey + "\\" + subKey, value, make(map[string]*Reg)}
			if err := emu.Registry.Insert(hkey, subKey, reg); err != nil {
				return SkipFunctionStdCall(true, 0x57)(emu, in)
			}
			return SkipFunctionStdCall(true, ERROR_SUCCESS)(emu, in)
		},
	})
	emu.AddHook("", "RegSetValueExA", &Hook{
		Parameters: []string{"hKey", "a:lpValueName", "Reserved", "dwType", "a:lpData", "cbData"},
		Fn:         SkipFunctionStdCall(true, ERROR_SUCCESS),
	})

	emu.AddHook("", "RegUnLoadKeyW", &Hook{
		Parameters: []string{"hKey", "lpSubKey"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			// update print view
			in.Hook.Values[0] = hkeyMap(in.Args[0])
			in.Hook.Parameters[0] = "s:hKey"
			return SkipFunctionStdCall(true, 0x0)(emu, in)
		},
	})

}
