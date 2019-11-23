package windows

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"strings"

	"github.com/carbonblack/binee/pefile"
	"github.com/carbonblack/binee/util"

	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
)

const (
	F_GRANULARITY  = 0x8
	F_PROT_32      = 0x4
	F_LONG         = 0x2
	PRESENT        = 0x80
	PRIV_3         = 0x60
	PRIV_2         = 0x40
	PRIV_1         = 0x20
	PRIV_0         = 0x0
	CODE           = 0x10
	DATA           = 0x10
	TSS            = 0x0
	GATE           = 0x00
	EXEC           = 0x8
	DATA_WRITEABLE = 0x2
	CODE_READABLE  = 0x2
	DIR_CON_BIT    = 0x4
	S_GDT          = 0x0
	S_PRIV_3       = 0x3
	S_PRIV_2       = 0x2
	S_PRIV_1       = 0x1
	S_PRIV_0       = 0x0
)

type MemRegions struct {
	ProcInfoSize    uint64
	TibSize         uint64
	GdtSize         uint64
	StackSize       uint64
	HeapSize        uint64
	LibSize         uint64
	ImageSize       uint64
	ProcInfoAddress uint64
	TibAddress      uint64
	GdtAddress      uint64
	StackAddress    uint64
	HeapAddress     uint64
	LibAddress      uint64
	ImageAddress    uint64
	PebAddress      uint64
	TebAddress      uint64
}

//NOP out large chunks of this structure (padding) until needed
type ThreadInformationBlock32 struct {
	CurentSEH                   uint32    //0x00
	StackBaseHigh               uint32    //0x04
	StackLimit                  uint32    //0x08
	SubSystemTib                uint32    //0x0c
	FiberData                   uint32    //0x10
	ArbitraryDataSlock          uint32    //0x14
	LinearAddressOfTEB          uint32    //0x18
	EnvPtr                      uint32    //0x1c
	ProcessId                   uint32    //0x20
	CurrentThreadId             uint32    //0x24
	ActiveRPCHandle             uint32    //0x28
	AddressOfThreadLocalStorage uint32    //0x2c
	AddressOfPEB                uint32    //0x30
	LastErrorNumber             uint32    //0x34
	CountOwnedCriticalSections  uint32    //0x38
	AddressOfCSRClientThread    uint32    //0x3c
	Win32ThreadInformation      uint32    //0x40
	padding1                    [128]byte //0x44-0xc3
	CurrentLocale               uint32    //0xc4
	padding                     [3404]byte
	TLSSlots                    [64]uint32
}

type ProcessEnvironmentBlock32 struct {
	InheritedAddressSpace              byte
	ReadImageFileExecOptions           byte
	BeingDebugged                      byte
	SpareBool                          byte
	Mutant                             uint32
	ImageBaseAddress                   uint32
	Ldr                                uint32
	ProcessParameters                  uint32
	SubSystemData                      uint32
	ProcessHeap                        uint32
	FastPebLock                        uint32
	FastPebLockRoutine                 uint32
	FastPebUnlockRoutine               uint32
	EnvironmentUpdateCount             uint32
	KernelCallbackTable                uint32
	SystemReserved                     [1]uint32
	ExecuteOptionsSpareBits            uint32
	FreeList                           uint32
	TLSExpansionCounter                uint32
	TLSBitmap                          uint32
	TLSBitmapBits                      [2]uint32
	ReadOnlySharedMemoryBase           uint32
	ReadOnlySharedMemoryHeap           uint32
	ReadOnlyStaticServerData           uint32
	AnsiCodePageData                   uint32
	OemCodePageData                    uint32
	UnicodeCaseTableData               uint32
	NumberOfProcessors                 uint32
	NtlGlobalFlag                      uint32
	CriticalSectionTimeout             uint64
	HeapSegmentReserve                 uint32
	HeapSegmentCommit                  uint32
	HeapDeCommitTotalFreeThreshold     uint32
	HeapDeCommitFreeBlockThreshold     uint32
	NumberOfHeaps                      uint32
	MaximumNumberOfHeaps               uint32
	ProcessHeaps                       uint32
	GdiSharedHandleTable               uint32
	ProcessStarterHelper               uint32
	GdiDCAttributeList                 uint32
	LoaderLock                         uint32
	OsMajorVersion                     int32
	OsMinorVersion                     int32
	OsBuildNumber                      uint16
	OsCSDVersion                       uint16
	OSPlatformID                       uint32
	ImageSubsystem                     uint32
	ImageSubsystemMajorVersion         uint32
	ImageSubsystemMinorVersion         uint32
	ImageProcessAffinityMask           uint32
	GdiHandleBuffer                    [34]uint32
	PostProcessInitRoutine             uint32
	TLSExpansionBitmap                 uint32
	TLSExpansionBitmapBits             [32]uint32
	SessionID                          uint32
	AppCompatFlags                     uint64
	AppCompatFlagsUser                 uint64
	ShimData                           uint32
	AppCompatInfo                      uint32
	CSDVersion                         uint64
	ActivationContextData              uint32
	ProcessAssemblyStorageMap          uint32
	SystemDefaultActivationContextData uint32
	SystemAssemblyStorageMap           uint32
	MinimumStackCommit                 uint32
	FlsCallback                        uint32
	FlsListHead                        uint64
	FlsBitmap                          uint32
	FlsBitmapBits                      [4]uint32
	FlsHighIndex                       uint32
	WerRegistrationData                uint32
	WerShipAssertPtr                   uint32
	pContextData                       uint32
	pUnused                            uint32
	pImageHeaderHash                   uint32
	structTracingFlags                 [8]byte
	CsrServerReadOnlySharedMemoryBase  uint64
	TppWorkerListLock                  uint32
	TppWorkerpList                     uint64
	WaitOnAddressHashTable             [0x80]uint32
	TelemetryCoverageHeader            uint32
	CloudFileFlags                     uint32
}

type ClientID struct {
	ProcessHandle uint32
	ThreadHandle  uint32
}

type UnicodeString32 struct {
	Length        uint16
	MaximumLength uint16
	Buffer        uint32
}

type RtlUserProcessParameters32 struct {
	Reserved1     [16]byte
	Reserved2     [10]uint32
	ImagePathName UnicodeString32
	CommandLine   UnicodeString32
}

//https://www.geoffchappell.com/studies/windows/win32/ntdll/structs/ldr_data_table_entry.htm
type PebLdrDataTableEntry32 struct {
	InOrderLinks               [8]byte
	InMemoryOrderLinks         [8]byte
	InInitializationOrderLinks [8]byte
	DllBase                    uint32
	EntryPoint                 uint32
	SizeOfImage                uint32
	FullDllName                UnicodeString32
	BaseDllName                UnicodeString32
	Flags                      uint32
	LoadCount                  uint16 // named ObseleteLoadCount OS6.2+
	TlsIndex                   uint16
	HashLinks                  [8]byte // increase by PVOID+ULONG if <OS6.2
}

//https://www.geoffchappell.com/studies/windows/win32/ntdll/structs/peb_ldr_data.htm
type PebLdrData32 struct {
	Length                          uint32
	Initialized                     uint32 //boolean
	SsHandle                        uint32
	InLoadOrderModuleList           [8]byte
	InMemoryOrderModuleList         [8]byte
	InInitializationOrderModuleList [8]byte
	EntryInProgress                 uint32
	ShutdownInProgress              uint32 //boolean
	ShutdownThreadId                uint32
}

type UserProcessParameters32 struct {
	Reserved1         [16]byte
	Reserved2         [10]uint32
	ImagePathLen      uint16
	ImagePathMaxLen   uint16
	ImagePath         uint32
	CommandLineLen    uint16
	CommandLineMaxLen uint16
	CommandLine       uint32
}

func (emu *WinEmulator) updateImageBase(pe *pefile.PeFile) {

	if pe.SetImageBase(emu.NextLibAddress) != nil {
		fmt.Fprintf(os.Stderr, "error setting image base and/or updating relocations")
	}

	// populate internal mapping of realdll name to base address
	emu.LoadedModules[pe.Name] = emu.NextLibAddress

	// calculate total dll size in memory
	dllSize := 0
	for i := 0; i < len(pe.Sections); i++ {
		dllSize += int(pe.Sections[i].VirtualAddress + pe.Sections[i].Size)
	}

	// set address for next DLL
	for i := 0; i <= dllSize; i += 4096 {
		emu.NextLibAddress += 4096
	}
}

func (emu *WinEmulator) extractExports(pe *pefile.PeFile) {
	name := pe.Name
	for _, funcs := range pe.Exports {
		realAddr := uint64(funcs.Rva) + pe.ImageBase()
		if _, ok := emu.libFunctionAddress[name]; !ok {
			emu.libFunctionAddress[name] = make(map[string]uint64)
		}
		if _, ok := emu.libAddressFunction[name]; !ok {
			emu.libAddressFunction[name] = make(map[uint64]string)
		}
		emu.libFunctionAddress[name][funcs.Name] = realAddr
		emu.libAddressFunction[name][realAddr] = funcs.Name
	}
}

func (emu *WinEmulator) getLdrPointer(baseaddr, offset, length uint64, adjust64 bool) uint64 {
	loc := baseaddr + (offset * (emu.PtrSize / 4))
	if emu.PtrSize == 8 && adjust64 {
		loc = (loc * 2) - 8
	}
	mem, _ := emu.Uc.MemRead(loc, length)
	if emu.PtrSize == 4 {
		mem = append(mem, []byte{0, 0, 0, 0}...)
	}
	ptr := binary.LittleEndian.Uint64(mem)
	return ptr
}

func (emu *WinEmulator) initializeListHead(address uint64) {
	buf := make([]byte, emu.PtrSize)
	if emu.PtrSize == 4 {
		binary.LittleEndian.PutUint32(buf, uint32(address))
	} else {
		binary.LittleEndian.PutUint64(buf, address)
	}
	emu.Uc.MemWrite(address, buf)
	emu.Uc.MemWrite(address+emu.PtrSize, buf)
}

//build an LdrEntry and then write it to the emulator memory
func (emu *WinEmulator) createLdrEntry(lpe *pefile.PeFile, index uint64) uint64 {
	if emu.PtrSize == 4 {
		LdrEntry := PebLdrDataTableEntry32{}
		LdrEntry.BaseDllName = UnicodeString32{}
		LdrEntry.FullDllName = UnicodeString32{}

		wRealDll := util.ASCIIToWinWChar(lpe.RealName)
		nameBuf := bytes.NewBuffer(wRealDll)
		nameLength := len(wRealDll)
		nameAddr := emu.Heap.Malloc(uint64(nameLength))
		emu.Uc.MemWrite(nameAddr, nameBuf.Bytes())
		LdrEntry.BaseDllName.Buffer = uint32(nameAddr)
		LdrEntry.BaseDllName.Length = uint16(nameLength)
		LdrEntry.BaseDllName.MaximumLength = uint16(nameLength)
		LdrEntry.FullDllName.Buffer = uint32(nameAddr)
		LdrEntry.FullDllName.Length = uint16(nameLength)
		LdrEntry.FullDllName.MaximumLength = uint16(nameLength)
		LdrEntry.EntryPoint = uint32(lpe.EntryPoint())
		var imageBase uint32
		switch optHdr := lpe.OptionalHeader.(type) {
		case *pefile.OptionalHeader32:
			imageBase = uint32(optHdr.ImageBase)
		case *pefile.OptionalHeader32P:
			imageBase = uint32(optHdr.ImageBase)
		default:
			panic(fmt.Errorf("support for %T not yet implemented", lpe.OptionalHeader))
		}
		LdrEntry.DllBase = imageBase
		LdrEntry.SizeOfImage = uint32(lpe.ImageSize)
		LdrEntry.TlsIndex = uint16(index)

		LdrBuf := new(bytes.Buffer)
		binary.Write(LdrBuf, binary.LittleEndian, LdrEntry)
		ldrEntryAddress := emu.Heap.Malloc(uint64(binary.Size(LdrEntry)))
		return ldrEntryAddress
	}
	return 0
}

func (emu *WinEmulator) findEndOfListEntry(listHead uint64) uint64 {
	addr := listHead
	var Flink uint64
	//var Blink uint64
	for {
		Flink = emu.getLdrPointer(addr, 0, emu.PtrSize, true)
		//Blink = self.getLdrPointer(addr+(4*(self.PtrSize/4)), 0, self.PtrSize, true)
		if Flink == listHead {
			if addr == listHead {
				return Flink
			} else {
				return addr
			}
		}
		addr = Flink
	}
	return 0
}

//link LdrEntry to end of doubly linked list
func (emu *WinEmulator) writeLdrEntry(ldrEntry uint64, listtype string) {
	lt := map[string]uint64{"Load": 0, "Memory": 1, "Initialization": 2}
	//test this for 64 bit
	index := lt[listtype]
	ldrPtr := emu.getLdrPointer(emu.MemRegions.PebAddress, 0xc, emu.PtrSize, false)
	listHead := ldrPtr + (8 * (index + 1)) + 4
	end := emu.findEndOfListEntry(listHead)
	buf := make([]byte, emu.PtrSize)
	if emu.PtrSize == 4 {
		offset := index * 0x08
		//address of the NEXT pointer
		binary.LittleEndian.PutUint32(buf, uint32(ldrEntry+offset))
		emu.Uc.MemWrite(end, buf)
		emu.Uc.MemWrite(listHead+4, buf)
		//write the header of the list to ldrEntry list forward link, since it is last node
		binary.LittleEndian.PutUint32(buf, uint32(listHead))
		emu.Uc.MemWrite(ldrEntry+offset, buf)
		// write the last node index to the back link
		binary.LittleEndian.PutUint32(buf, uint32(end))
		emu.Uc.MemWrite(ldrEntry+offset+4, buf)
	} else {
		offset := index * 0x10
		binary.LittleEndian.PutUint64(buf, ldrEntry+offset)
		emu.Uc.MemWrite(end, buf)
		emu.Uc.MemWrite(listHead+8, buf)
		binary.LittleEndian.PutUint64(buf, listHead)
		emu.Uc.MemWrite(ldrEntry+offset, buf)
		binary.LittleEndian.PutUint64(buf, end)
		emu.Uc.MemWrite(ldrEntry+offset+8, buf)
	}
}

func retrieveDllFromDisk(cur map[string]*pefile.PeFile, apiset *pefile.PeFile, searchPath []string, name string) {
	var path string
	var pe *pefile.PeFile
	var err error

	// load dll from disk, add extension if missing
	if name[len(name)-4:] != ".dll" {
		name += ".dll"
	}

	realDll := name
	// get realDll name on disk
	// for apiset recurse through each real dll in the apisets list
	if strings.Compare(name[:4], "api-") == 0 {
		if apiset == nil {
			fmt.Fprintf(os.Stderr, "error loading dll %s; unable to locate \"apisetschema.dll\"\n", name)
			return
		}
		apiset_len := len(apiset.Apisets[name[0:len(name)-6]]) - 1
		if apiset_len >= 0 {
			realDll = apiset.Apisets[name[0:len(name)-6]][apiset_len]
		} else {
			return
		}
	}

	// check if name (apiset or realdll is already loaded)
	if _, ok := cur[name]; ok {
		return
	}

	//check if realDll (different from name) is loaded, then assign that PE to the api-set name
	// continue since nothing needs to be done. Apiset and realldll now both point to the same dll
	if _, ok := cur[realDll]; ok {
		cur[name] = cur[realDll]
		return
	}

	// find real dll name on disk
	if path, err = util.SearchFile(searchPath, realDll); err != nil {
		fmt.Fprintf(os.Stderr, "error finding file %s\n", name)
		return
	}

	// load file from disk
	if pe, err = pefile.LoadPeFile(path); err != nil {
		fmt.Fprintf(os.Stderr, "error loading dll %s\n", name)
		return
	}

	//set pe files short name
	pe.Name = name
	pe.RealName = realDll

	// update cur
	cur[realDll] = pe
	cur[name] = pe

	// get all dlls this dll depends on
	for _, dllName := range pe.ImportedDlls() {
		retrieveDllFromDisk(cur, apiset, searchPath, dllName)
	}
}

func (emu *WinEmulator) initCommandLine() error {
	// copy command line args into memory
	if emu.UcMode == uc.MODE_32 {
		// copy argc count into memory and set the Argc pointer
		buf := make([]byte, 4)
		binary.LittleEndian.PutUint32(buf, uint32(len(emu.Args)))
		emu.Uc.MemWrite(emu.MemRegions.ProcInfoAddress+0x1000, buf)
		emu.Argc = emu.MemRegions.ProcInfoAddress + 0x1000

		// copy bytes for each argv parameter into memory
		curAddress := uint32(emu.MemRegions.ProcInfoAddress) + 0x1000 + 4
		// array of pointers to each argv string
		argvAddresses := make([]uint32, 0)

		// loop over each Args and copy those strings into memory, saving the
		// start address for each string into argvAddresses
		for i := 0; i < len(emu.Args); i++ {
			buf := []byte(emu.Args[i])
			emu.Uc.MemWrite(uint64(curAddress), buf)
			argvAddresses = append(argvAddresses, curAddress)
			curAddress += uint32(len(emu.Args) + 1)
		}

		// copy each argvAddress into memory
		argv := curAddress
		for i := 0; i < len(argvAddresses); i++ {
			util.PutPointer(emu.Uc, emu.PtrSize, uint64(curAddress), uint64(argvAddresses[i]))
			curAddress += uint32(emu.PtrSize)
		}

		// copy the address to the start of argv into memory, it is a **char
		buf = make([]byte, 4)
		binary.LittleEndian.PutUint32(buf, argv)
		emu.Uc.MemWrite(uint64(curAddress), buf)
		emu.Argv = uint64(curAddress)

	} else {
		// copy argc count into memory and set the Argc pointer
		buf := make([]byte, 8)
		binary.LittleEndian.PutUint64(buf, uint64(len(emu.Args)))
		emu.Uc.MemWrite(emu.MemRegions.ProcInfoAddress+0x1000, buf)
		emu.Argc = emu.MemRegions.ProcInfoAddress + 0x1000

		// copy bytes for each argv parameter into memory
		curAddress := emu.MemRegions.ProcInfoAddress + 0x1000 + 8
		// array of pointers to each argv string
		argvAddresses := make([]uint64, 0)

		// loop over each Args and copy those strings into memory, saving the
		// start address for each string into argvAddresses
		for i := 0; i < len(emu.Args); i++ {
			buf := []byte(emu.Args[i])
			emu.Uc.MemWrite(curAddress, buf)
			argvAddresses = append(argvAddresses, curAddress)
			curAddress += uint64(len(emu.Args) + 1)
		}

		// copy each argvAddress into memory
		argv := curAddress
		for i := 0; i < len(argvAddresses); i++ {
			buf = make([]byte, 8)
			binary.LittleEndian.PutUint64(buf, argvAddresses[i])
			emu.Uc.MemWrite(curAddress, buf)
			curAddress += 8
		}

		// copy the address to the start of argv into memory, it is a **char
		buf = make([]byte, 8)
		binary.LittleEndian.PutUint64(buf, argv)
		emu.Uc.MemWrite(curAddress, buf)
		emu.Argv = curAddress
	}

	return nil
}

//build our PEB and write it to emulator memory
func (emu *WinEmulator) initPEB(pe *pefile.PeFile) uint64 {
	// LdrData
	pebLdrData := PebLdrData32{}
	pebLdrBuf := new(bytes.Buffer)
	binary.Write(pebLdrBuf, binary.LittleEndian, &pebLdrData)
	pebLdrAddress := emu.Heap.Malloc(uint64(binary.Size(pebLdrData)))
	emu.Uc.MemWrite(pebLdrAddress, pebLdrBuf.Bytes())
	emu.initializeListHead(pebLdrAddress + 0xc)
	emu.initializeListHead(pebLdrAddress + 0x14)
	emu.initializeListHead(pebLdrAddress + 0x1c)

	// PEB
	peb := ProcessEnvironmentBlock32{}
	peb.ProcessHeap = uint32(emu.MemRegions.HeapAddress)
	peb.NumberOfProcessors = uint32(emu.Opts.ProcessorsCount)
	peb.OsMajorVersion = int32(emu.Opts.OsMajorVersion)
	peb.OsMinorVersion = int32(emu.Opts.OsMinorVersion)
	peb.ImageBaseAddress = uint32(pe.ImageBase())
	//peb.ReadOnlySharedMemoryBase = uint32(emu.Heap.Malloc(4096))
	//peb.ReadOnlyStaticServerData = peb.ReadOnlySharedMemoryBase + 0x4b0
	//peb.CsrServerReadOnlySharedMemoryBase = emu.Heap.Malloc(4096)
	peb.Ldr = uint32(pebLdrAddress)
	pebBuf := new(bytes.Buffer)
	binary.Write(pebBuf, binary.LittleEndian, &peb)
	pebAddress := emu.Heap.Malloc(uint64(binary.Size(&peb)))
	emu.MemRegions.PebAddress = pebAddress
	emu.Uc.MemWrite(pebAddress, pebBuf.Bytes())

	return pebAddress
}

// https://github.com/unicorn-engine/unicorn/blob/master/samples/sample_x86_32_gdt_and_seg_regs.c
func (emu *WinEmulator) initGdt(pe *pefile.PeFile) error {

	var ds uint64
	sectionFound := false
	for i := 0; i < int(pe.CoffHeader.NumberOfSections); i++ {
		if pe.Sections[i].Name == ".data\u0000" {
			section := pe.Sections[i]
			ds = uint64(section.VirtualAddress) + emu.MemRegions.ImageAddress
			sectionFound = true
			break
		}
	}

	if sectionFound == false {
		ds = emu.MemRegions.ImageAddress
	}

	if emu.UcMode == uc.MODE_32 {
		gdtr := uc.X86Mmr{}
		gdtr.Base = emu.MemRegions.GdtAddress
		gdtr.Limit = 31*8 - 8
		emu.Uc.RegWriteMmr(uc.X86_REG_GDTR, &gdtr)

		gdt := [31]uint64{}
		// cs | code segment
		gdt[14] = util.NewGdtEntry(0, 0xfffff000, PRESENT|DATA|DATA_WRITEABLE|PRIV_3|DIR_CON_BIT, F_PROT_32)
		// ds | data segment
		gdt[15] = util.NewGdtEntry(0, uint32(ds), PRESENT|DATA|DATA_WRITEABLE|PRIV_3|DIR_CON_BIT, F_PROT_32)
		// fs | data segment
		gdt[16] = util.NewGdtEntry(uint32(emu.MemRegions.TibAddress), 0xfff, PRESENT|DATA|DATA_WRITEABLE|PRIV_3|DIR_CON_BIT, F_PROT_32)
		gdt[17] = util.NewGdtEntry(0, uint32(ds), PRESENT|CODE|CODE_READABLE|PRIV_0|DIR_CON_BIT, F_PROT_32)

		buf := new(bytes.Buffer)
		binary.Write(buf, binary.LittleEndian, &gdt)
		emu.Uc.MemWrite(emu.MemRegions.GdtAddress, buf.Bytes())

		if err := emu.Uc.RegWrite(uc.X86_REG_CS, util.CreateSelector(14, S_GDT|S_PRIV_3)); err != nil {
			return err
		}
		if err := emu.Uc.RegWrite(uc.X86_REG_FS, util.CreateSelector(16, S_GDT|S_PRIV_3)); err != nil {
			return err
		}
		if err := emu.Uc.RegWrite(uc.X86_REG_SS, util.CreateSelector(17, S_GDT|S_PRIV_0)); err != nil {
			return err
		}
		if err := emu.Uc.RegWrite(uc.X86_REG_ES, util.CreateSelector(15, S_GDT|S_PRIV_0)); err != nil {
			return err
		}
		if err := emu.Uc.RegWrite(uc.X86_REG_GS, util.CreateSelector(15, S_GDT|S_PRIV_0)); err != nil {
			return err
		}
		if err := emu.Uc.RegWrite(uc.X86_REG_DS, util.CreateSelector(15, S_GDT|S_PRIV_3)); err != nil {
			return err
		}

		// tls buffer

		// client id
		clientID := ClientID{0x41414141, 0x42424242}
		clientIDBuf := new(bytes.Buffer)
		binary.Write(clientIDBuf, binary.LittleEndian, &clientID)
		clientIDAddress := emu.Heap.Malloc(uint64(binary.Size(&clientID)))
		emu.Uc.MemWrite(clientIDAddress, clientIDBuf.Bytes())

		// PEB
		pebAddress := emu.initPEB(pe)

		// TIB, only 32 bit for now
		tib := ThreadInformationBlock32{}
		tib.ProcessId = 0x1001
		tib.CurrentThreadId = 0x2001
		tib.StackBaseHigh = uint32(emu.MemRegions.StackAddress)
		tib.StackLimit = uint32(emu.MemRegions.StackAddress - emu.MemRegions.StackSize)
		tib.LinearAddressOfTEB = uint32(emu.MemRegions.TibAddress)
		//check this one above, might not be right
		tib.CurrentLocale = uint32(emu.Opts.CurrentLocale)
		tib.AddressOfPEB = uint32(pebAddress)
		tibBuf := new(bytes.Buffer)
		binary.Write(tibBuf, binary.LittleEndian, &tib)
		emu.Uc.MemWrite(emu.MemRegions.TibAddress, tibBuf.Bytes())
	}

	return nil
}

func (emu *WinEmulator) initMemory() error {
	// map all memory
	if err := emu.Uc.MemMap(emu.MemRegions.ProcInfoAddress, emu.MemRegions.ProcInfoSize); err != nil {
		return err
	}

	if err := emu.Uc.MemMap(emu.MemRegions.TibAddress, emu.MemRegions.TibSize); err != nil {
		return err
	}

	if err := emu.Uc.MemMap(emu.MemRegions.GdtAddress, emu.MemRegions.GdtSize); err != nil {
		return err
	}

	if err := emu.Uc.MemMap(emu.MemRegions.StackAddress, emu.MemRegions.StackSize); err != nil {
		return err
	}

	if err := emu.Uc.MemMap(emu.MemRegions.HeapAddress, emu.MemRegions.HeapSize); err != nil {
		return err
	}

	if err := emu.Uc.MemMap(emu.MemRegions.LibAddress, emu.MemRegions.LibSize); err != nil {
		return err
	}

	if err := emu.Uc.MemMap(emu.MemRegions.ImageAddress, emu.MemRegions.ImageSize); err != nil {
		return err
	}

	return nil
}

func (emu *WinEmulator) initRegisters() error {
	if emu.PtrSize == 4 {

		if err := emu.Uc.RegWrite(uc.X86_REG_EDI, emu.EntryPoint); err != nil {
			return err
		}
		if err := emu.Uc.RegWrite(uc.X86_REG_ESI, emu.EntryPoint); err != nil {
			return err
		}

		if err := emu.Uc.RegWrite(uc.X86_REG_ESP, emu.MemRegions.StackAddress+emu.MemRegions.StackSize-0x10000); err != nil {
			return err
		}

		if err := emu.Uc.RegWrite(uc.X86_REG_EAX, emu.MemRegions.StackAddress+0x10000); err != nil {
			return err
		}

		if err := emu.Uc.RegWrite(uc.X86_REG_EDX, emu.EntryPoint); err != nil {
			return err
		}

		if err := emu.Uc.RegWrite(uc.X86_REG_ECX, emu.EntryPoint); err != nil {
			return err
		}

		if err := emu.Uc.RegWrite(uc.X86_REG_EBP, emu.MemRegions.StackAddress+0x10000); err != nil {
			return err
		}

	} else {
		if err := emu.Uc.RegWrite(uc.X86_REG_RSP, emu.MemRegions.StackAddress+0x100); err != nil {
			return err
		}

		if err := emu.Uc.RegWrite(uc.X86_REG_RBP, 0); err != nil {
			return err
		}

		if err := emu.Uc.RegWrite(uc.X86_REG_RAX, emu.MemRegions.StackAddress-0x1000); err != nil {
			return err
		}

		if err := emu.Uc.RegWrite(uc.X86_REG_RDX, emu.MemRegions.StackAddress-0x100); err != nil {
			return err
		}

		if err := emu.Uc.RegWrite(uc.X86_REG_R9, emu.MemRegions.StackAddress-0x100); err != nil {
			return err
		}
	}

	return nil
}

// setupDllMainCallstack Add dll to ropchain for calling DllMain
func (emu *WinEmulator) setupDllMainCallstack(dll *pefile.PeFile) {
	//TODO: make this 64-bit aware, this implementation is only 32 bit currently.
	if emu.PtrSize == 4 {
		hmodule := dll.ImageBase()
		//fmt.Printf("%s (%s) main: 0x%x\n", dll.Name, dll.RealName, hmodule)
		modEntry := uint64(dll.EntryPoint()) + hmodule
		//push arguments
		util.PushStack(emu.Uc, emu.UcMode, 1)       // reserved 1 == static load, 0 == dynamic load
		util.PushStack(emu.Uc, emu.UcMode, 1)       // reason
		util.PushStack(emu.Uc, emu.UcMode, hmodule) // hmodule
		//push eip
		util.PushStack(emu.Uc, emu.UcMode, emu.EntryPoint)
		// update emu.entrypoint to dll entrypoint
		emu.EntryPoint = modEntry
	}
}

func (emu *WinEmulator) initPe(pe *pefile.PeFile, path string, arch, mode int, args []string, calldllmain bool) error {
	var err error

	// load the PE file
	// open each DLL and load into map, adjust base address with NextLibAddress
	emu.EntryPoint = pe.ImageBase() + uint64(pe.EntryPoint())

	if mode == uc.MODE_32 {
		emu.MemRegions.ImageAddress = pe.ImageBase()
	} else {
		emu.MemRegions.ImageAddress = pe.ImageBase()
	}

	if emu.Uc, err = uc.NewUnicorn(emu.UcArch, emu.UcMode); err != nil {
		return err
	}

	if err := emu.initMemory(); err != nil {
		return err
	}

	if err := emu.initRegisters(); err != nil {
		return err
	}

	if err := emu.initGdt(pe); err != nil {
		return err
	}

	if err := emu.initCommandLine(); err != nil {
		return err
	}

	// load Apisetschema dll for mapping to real dlls
	apisetPath, err := util.SearchFile(emu.SearchPath, "apisetschema.dll")
	var apiset *pefile.PeFile
	if err == nil {
		// only load apisetschema.dll if present.
		apiset, _ = pefile.LoadPeFile(apisetPath)
	}

	// create the main map to hold all name/realdll mappings to actual PeFile object
	peMap := make(map[string]*pefile.PeFile)

	// load defatul ntdll/kernel32 and then get all dlls recursively from imports table of Pe
	// TODO ensure that the load order is always ntdll.dll, kernel32.dll, ..., other dlls, ...
	retrieveDllFromDisk(peMap, apiset, emu.SearchPath, "ntdll.dll")
	retrieveDllFromDisk(peMap, apiset, emu.SearchPath, "kernel32.dll")
	for _, dllName := range pe.ImportedDlls() {
		retrieveDllFromDisk(peMap, apiset, emu.SearchPath, dllName)
	}

	//update the image base
	peCheck := make(map[string]bool)
	for _, lpe := range peMap {
		//check if we've already processed this PeFile
		if _, ok := peCheck[lpe.RealName]; ok {
			continue
		}

		emu.updateImageBase(lpe)
		// add PeFile to "already checked" mapping
		peCheck[lpe.RealName] = true
	}

	//extract exports for each, reset peCheck map
	peCheck = make(map[string]bool)
	for _, lpe := range peMap {
		//check if we've already processed this PeFile
		if _, ok := peCheck[lpe.RealName]; ok {
			continue
		}

		emu.extractExports(lpe)
		peCheck[lpe.RealName] = true
	}

	//make an LdrEntry, need to make proper order first
	var ldrList []string
	ldrList = append(ldrList, "ntdll.dll")
	ldrList = append(ldrList, "kernel32.dll")
	//set proper order for LdrEntry creation
	for key := range peCheck {
		if key != "ntdll.dll" && key != "kernel32.dll" {
			ldrList = append(ldrList, key)
		}
	}

	ldrEntry := emu.createLdrEntry(pe, 0)
	emu.writeLdrEntry(ldrEntry, "Memory")
	emu.writeLdrEntry(ldrEntry, "Initialization")
	var lpe *pefile.PeFile
	for i, key := range ldrList {
		lpe = peMap[key]
		ldrEntry = emu.createLdrEntry(lpe, uint64(i+1))
		emu.writeLdrEntry(ldrEntry, "Load")
		emu.writeLdrEntry(ldrEntry, "Memory")
		emu.writeLdrEntry(ldrEntry, "Initialization")
	}

	// update the imports table for the current PE so that imports resolve correctly
	for _, importInfo := range pe.Imports {
		dll := peMap[importInfo.DllName]
		if dll == nil {
			continue
		}

		realAddr := uint64(dll.ExportNameMap[importInfo.FuncName].Rva) + dll.ImageBase()
		pe.SetImportAddress(importInfo, realAddr)
	}

	// resolve imports between dlls, for each loaded dll
	for _, dll := range peMap {

		// loop through current DLL and update all imports
		for _, importInfo := range dll.Imports {

			if importInfo.DllName == dll.Name {
				continue
			}

			importedDll := peMap[importInfo.DllName]
			if importedDll == nil {
				continue
			}

			if importInfo.FuncName != "" {
				realAddr := uint64(importedDll.ExportNameMap[importInfo.FuncName].Rva) + importedDll.ImageBase()
				dll.SetImportAddress(importInfo, realAddr)
			} else {
				realAddr := uint64(importedDll.ExportOrdinalMap[int(importInfo.Ordinal)].Rva) + importedDll.ImageBase()
				dll.SetImportAddress(importInfo, realAddr)
			}

		}
	}

	// write each file into memory
	for name, dll := range peMap {
		// only write real files
		if strings.Contains(name[:4], "api-") {
			continue
		}

		emu.Uc.MemWrite(dll.ImageBase(), dll.RawHeaders)
		for i := 0; i < len(dll.Sections); i++ {
			emu.Uc.MemWrite(dll.ImageBase()+uint64(dll.Sections[i].VirtualAddress), dll.Sections[i].Raw)
		}
	}

	//setup dllmain stack
	if calldllmain {
		//this is the incorrect order, need to make sure kernel32 starts first so it gets called last
		//for _, name := range ldrList {
		for i := len(ldrList) - 1; i >= 0; i-- {
			name := ldrList[i]
			dll := peMap[name]
			if !strings.HasPrefix(name, "api") && !strings.HasPrefix(name, "kernelbase") && !strings.HasPrefix(name, "ucrt") {
				if dll.EntryPoint() != 0 {
					emu.setupDllMainCallstack(dll)
				}
			}
		}
	}

	// write the target PE file to memory
	emu.Uc.MemWrite(pe.ImageBase(), pe.RawHeaders)
	for i := 0; i < len(pe.Sections); i++ {
		emu.Uc.MemWrite(pe.ImageBase()+uint64(pe.Sections[i].VirtualAddress), pe.Sections[i].Raw)
	}

	if pe.CoffHeader.Characteristics&0x2000 == 0x2000 {
		util.PushStack(emu.Uc, emu.UcMode, uint64(emu.Opts.DllLoadReason))
		util.PushStack(emu.Uc, emu.UcMode, pe.ImageBase())
		util.PushStack(emu.Uc, emu.UcMode, pe.ImageBase())
	}
	// give libs back to GC, no longer needed
	return nil
}
