package windows

import (
	"bytes"
	"encoding/binary"
	"github.com/carbonblack/binee/pefile"
	"github.com/carbonblack/binee/util"
	"io"
	"strconv"
	"strings"
)

func getProcAddress(emu *WinEmulator, baseAddress uint64, wantedFuncName string, wantedFuncOrdinal uint16) uint64 {

	raw, err := emu.Uc.MemRead(baseAddress, 4096)
	if err != nil {
		return 0
	}

	imageDosHeader := &pefile.DosHeader{}
	r := bytes.NewReader(raw)
	if err = binary.Read(r, binary.LittleEndian, imageDosHeader); err != nil {
		return 0
	}

	// move offset to CoffHeader
	if _, err = r.Seek(int64(imageDosHeader.AddressExeHeader)+4, io.SeekStart); err != nil {
		return 0
	}

	// advance reader to start of OptionalHeader(32|32+)
	if _, err = r.Seek(int64(imageDosHeader.AddressExeHeader)+4+int64(binary.Size(pefile.CoffHeader{})), io.SeekStart); err != nil {
		return 0
	}

	// check if pe or pe+, read 2 bytes to get Magic then seek backward two bytes
	var _magic uint16
	if err := binary.Read(r, binary.LittleEndian, &_magic); err != nil {
		return 0
	}
	var PeType uint16
	// check magic, must be a PE or PE+
	if _magic == 0x10b {
		PeType = 32
	} else if _magic == 0x20b {
		PeType = 64
	} else {
		return 0
	}

	if _, err = r.Seek(int64(imageDosHeader.AddressExeHeader)+4+int64(binary.Size(pefile.CoffHeader{})), io.SeekStart); err != nil {
		return 0
	}

	var peOptionalHeader interface{}
	// copy the optional headers into their respective structs
	if PeType == 32 {
		peOptionalHeader = &pefile.OptionalHeader32{}
		if err = binary.Read(r, binary.LittleEndian, peOptionalHeader); err != nil {
			return 0
		}
	} else {
		peOptionalHeader = &pefile.OptionalHeader32P{}
		if err = binary.Read(r, binary.LittleEndian, peOptionalHeader); err != nil {
			return 0
		}
	}

	var rawExportDirectory []byte
	var exportRva, size uint32
	var ordinal uint16
	if PeType == 32 {
		exportDirectory := peOptionalHeader.(*pefile.OptionalHeader32).DataDirectories[0]
		exportRva = exportDirectory.VirtualAddress
		size = exportDirectory.Size
		rawExportDirectory, _ = emu.Uc.MemRead(uint64(exportRva)+baseAddress, uint64(exportDirectory.Size))
		r = bytes.NewReader(rawExportDirectory)

	} else {
		exportDirectory := peOptionalHeader.(*pefile.OptionalHeader32P).DataDirectories[0]
		exportRva = exportDirectory.VirtualAddress
		size = exportDirectory.Size
		rawExportDirectory, _ = emu.Uc.MemRead(uint64(exportRva)+baseAddress, uint64(size))
		r = bytes.NewReader(rawExportDirectory)
	}
	exportDirectory := pefile.ExportDirectory{}
	if err := binary.Read(r, binary.LittleEndian, &exportDirectory); err != nil {
		return 0
	}
	namesTableRVA := exportDirectory.NamesRva - exportRva
	ordinalsTableRVA := exportDirectory.OrdinalsRva - exportRva
	for i := 0; i < int(exportDirectory.NumberOfNamePointers); i++ {
		// seek to index in names table
		if _, err := r.Seek(int64(namesTableRVA+uint32(i*4)), io.SeekStart); err != nil {
			return 0
		}

		exportAddressTable := pefile.ExportAddressTable{}
		if err := binary.Read(r, binary.LittleEndian, &exportAddressTable); err != nil {
			return 0
		}

		name := pefile.ReadString(rawExportDirectory[exportAddressTable.Rva-exportRva:])
		if name != wantedFuncName && wantedFuncOrdinal == 0 {
			continue //Another check to stop reads that are not helpful
		}

		// get first Name in array
		ordinal = binary.LittleEndian.Uint16(rawExportDirectory[ordinalsTableRVA+uint32(i*2) : ordinalsTableRVA+uint32(i*2)+2])

		// seek to ordinals table
		if _, err := r.Seek(int64(uint32(ordinal)*4+exportDirectory.FunctionsRva-exportRva), io.SeekStart); err != nil {
			return 0
		}

		// get ordinal address table
		exportOrdinalTable := pefile.ExportAddressTable{}
		if err := binary.Read(r, binary.LittleEndian, &exportOrdinalTable); err != nil {
			return 0
		}
		rva := exportOrdinalTable.Rva

		//Check whether its forwarded or not
		if rva < exportRva+size && rva > exportRva && (name == wantedFuncName || (uint32(i)+exportDirectory.OrdinalBase) == uint32(wantedFuncOrdinal)) {
			//Its in the range of exports, its forwarded.
			if _, err := r.Seek(int64(rva-exportRva), io.SeekStart); err != nil {
				return 0
			}
			forwardedExportRaw := pefile.ReadString(rawExportDirectory[rva-exportRva:])
			split := strings.Split(forwardedExportRaw, ".")
			dllName := strings.ToLower(split[0]) + ".dll"
			ordinalNum := 0
			funcName := ""
			var err error
			if split[1][0] == '#' {
				numStr := split[1][1:]
				if ordinalNum, err = strconv.Atoi(numStr); err != nil {
					return 0
				}
			} else {
				funcName = split[1]
			}
			libAddress := emu.LoadedModules[dllName]

			return getProcAddress(emu, libAddress, funcName, uint16(ordinalNum))
		}
		if name == wantedFuncName || uint32(i)+exportDirectory.OrdinalBase == uint32(wantedFuncOrdinal) {
			return uint64(rva) + baseAddress
		}

	}
	return 0

}
func getProcAddressWrapper(emu *WinEmulator, in *Instruction) func(emu *WinEmulator, in *Instruction) bool {
	baseAddr := in.Args[0]
	//The ordinal value might be given and not the function name.
	if in.Args[1] < 65535 { //USHRT_MAX
		ordinalValue := in.Args[1]
		rva := getProcAddress(emu, baseAddr, "", uint16(ordinalValue))
		return SkipFunctionStdCall(true, rva)
	} else {
		name := util.ReadASCII(emu.Uc, in.Args[1], 0)
		rva := getProcAddress(emu, baseAddr, name, 0)
		return SkipFunctionStdCall(true, rva)
	}
}

func loadLibrary(emu *WinEmulator, in *Instruction, wide bool) func(emu *WinEmulator, in *Instruction) bool {
	var err error

	// read the dll that needs to be loaded
	var name string
	var orig string
	if wide {
		orig = util.ReadWideChar(emu.Uc, in.Args[0], 100)
	} else {
		orig = util.ReadASCII(emu.Uc, in.Args[0], 100)
	}
	name = strings.ToLower(orig)
	name = strings.Replace(name, "c:\\windows\\system32\\", "", -1)
	name = strings.Trim(name, "\x00")
	name = strings.Trim(name, "\u0000")

	if strings.Contains(name, ".dll") == false {
		name += ".dll"
	}

	// check if library is already loaded
	if val, ok := emu.LoadedModules[name]; ok {
		return SkipFunctionStdCall(true, val)
	}

	var realdll string
	// load Apisetschema dll for mapping to real dlls
	if apisetPath, err := util.SearchFile(emu.SearchPath, "apisetschema.dll"); err == nil {
		apiset, _ := pefile.LoadPeFile(apisetPath)
		realdll = apiset.ApiSetLookup(name)
	}

	var path string
	if path, err = util.SearchFile(emu.SearchPath, realdll); err != nil {
		if path, err = util.SearchFile(emu.SearchPath, orig); err != nil {
			return SkipFunctionStdCall(true, 0x0)
		}
	}

	if pe, err := pefile.LoadPeFile(path); err != nil {
		return SkipFunctionStdCall(true, 0x0)
	} else {
		pe.SetImageBase(emu.NextLibAddress)
		emu.LoadedModules[name] = emu.NextLibAddress
		//We have to set import address here
		err = emu.Uc.MemWrite(pe.ImageBase(), pe.RawHeaders)
		for i := 0; i < len(pe.Sections); i++ {
			err = emu.Uc.MemWrite(pe.ImageBase()+uint64(pe.Sections[i].VirtualAddress), pe.Sections[i].Raw)
		}

		// get total size of DLL in memory
		peSize := 0
		for i := 0; i < len(pe.Sections); i++ {
			peSize += int(pe.Sections[i].VirtualAddress + pe.Sections[i].Size)
		}

		for _, funcs := range pe.Exports {
			realAddr := uint64(funcs.Rva) + pe.ImageBase()
			if _, ok := emu.libFunctionAddress[name]; !ok {
				emu.libFunctionAddress[name] = make(map[string]uint64)
			}
			if _, ok := emu.libAddressFunction[name]; !ok {
				emu.libAddressFunction[name] = make(map[uint64]string)
			}
			if _, ok := emu.libOrdinalFunction[name]; !ok {
				emu.libOrdinalFunction[name] = make(map[uint16]string)
			}

			emu.libOrdinalFunction[name][funcs.Ordinal] = funcs.Name
			emu.libFunctionAddress[name][funcs.Name] = realAddr
			emu.libAddressFunction[name][realAddr] = funcs.Name
		}

		// set address for next DLL
		for i := 0; i <= peSize; i += 4096 {
			emu.NextLibAddress += 4096
		}

		return SkipFunctionStdCall(true, pe.ImageBase())
	}

}

func LibloaderapiHooks(emu *WinEmulator) {
	emu.AddHook("", "DisableThreadLibraryCalls", &Hook{
		Parameters: []string{"hLibModule"},
		Fn:         SkipFunctionStdCall(true, 0x1),
	})

	emu.AddHook("", "ResolveDelayLoadedAPI", &Hook{
		Parameters: []string{"ParentModuleBase", "DelayloadedDescriptor", "FailureDllHook", "FailureSystemHook", "ThunkAddress", "Flags"},
		Fn:         SkipFunctionStdCall(true, 0x1),
	})

	emu.AddHook("", "SetDefaultDllDirectories", &Hook{
		Parameters: []string{"DirectoryFlags"},
		Fn:         SkipFunctionStdCall(true, 0x1),
	})

	emu.AddHook("", "LoadResource", &Hook{
		Parameters: []string{"hModule", "hResInfo"},
		Fn: func(emulator *WinEmulator, in *Instruction) bool {
			baseAddress := in.Args[0]
			if baseAddress == 0 { //if null then same module
				baseAddress = emu.MemRegions.ImageAddress
			}
			addr := in.Args[1]
			if _, ok := emu.Handles[addr]; !ok {
				return SkipFunctionStdCall(true, 0)(emu, in)
			}
			dataEntry := emu.Handles[addr].ResourceDataEntry
			location := baseAddress + uint64(dataEntry.OffsetToData)
			return SkipFunctionStdCall(true, location)(emu, in)
		},
	})
	emu.AddHook("", "SizeofResource", &Hook{
		Parameters: []string{"hModule", "hResInfo"},
		Fn: func(emulator *WinEmulator, in *Instruction) bool {
			addr := in.Args[1]
			if handle, ok := emu.Handles[addr]; ok {
				return SkipFunctionStdCall(true, uint64(handle.ResourceDataEntry.Size))(emu, in)
			}
			return SkipFunctionStdCall(true, 0)(emu, in)
		},
	})
	emu.AddHook("", "LockResource", &Hook{
		Parameters: []string{"HGlobal"},
		Fn: func(emulator *WinEmulator, in *Instruction) bool {
			return SkipFunctionStdCall(true, in.Args[0])(emu, in)
		},
	})
	emu.AddHook("", "FreeResource", &Hook{
		Parameters: []string{"hResData"},
		Fn: func(emulator *WinEmulator, in *Instruction) bool {
			return SkipFunctionStdCall(true, 0)(emu, in)
		},
	})

	emu.AddHook("", "GetProcAddress", &Hook{
		Parameters: []string{"hModule", "a:lpProcName"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			return getProcAddressWrapper(emu, in)(emu, in)
		},
	})

	emu.AddHook("", "LoadLibraryA", &Hook{
		Parameters: []string{"a:lpFileName"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			return loadLibrary(emu, in, false)(emu, in)
		},
	})
	emu.AddHook("", "LoadLibraryExA", &Hook{
		Parameters: []string{"a:lpFileName", "hFile", "dwFlags"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			return loadLibrary(emu, in, false)(emu, in)
		},
	})
	emu.AddHook("", "LoadLibraryExW", &Hook{
		Parameters: []string{"w:lpFileName", "hFile", "dwFlags"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			return loadLibrary(emu, in, true)(emu, in)
		},
	})
	emu.AddHook("", "LoadLibraryW", &Hook{
		Parameters: []string{"w:lpFileName"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			return loadLibrary(emu, in, true)(emu, in)
		},
	})
}
