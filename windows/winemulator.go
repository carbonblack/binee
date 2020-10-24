package windows

import (
	"encoding/binary"
	"github.com/carbonblack/binee/util"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"sort"
	"time"

	"gopkg.in/yaml.v2"

	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"

	"github.com/carbonblack/binee/core"
	"github.com/carbonblack/binee/pefile"
)

// Env is the key/value pair for specifying environment variables for the
// emulated process
type Env struct {
	Key   string `yaml:"key"`
	Value string `yaml:"value"`
}

// WinOptions struct contains all the yaml definitions for various supported
// configuration settings. These can be passed to emulation via the `-c` flag.
// If this yaml is passed in, it will be parsed and override ALL the default settings
type WinOptions struct {
	CodePageIdentifier int               `yaml:"code_page_identifier"`
	ComputerName       string            `yaml:"computer_name"`
	CurrentLocale      int               `yaml:"current_locale"`
	DllLoadReason      int               `yaml:"dll_load_reason"`
	Env                []Env             `yaml:"environment"`
	KeyboardType       int               `yaml:"keyboard_type"`
	KeyboardSubType    int               `yaml:"keyboard_subtype"`
	KeyboardFuncKeys   int               `yaml:"keyboard_funckeys"`
	OsMajorVersion     int               `yaml:"os_major_version"`
	OsMinorVersion     int               `yaml:"os_minor_version"`
	ProcessorsCount    int               `yaml:"processors_count"`
	ProcessorType      int               `yaml:"processsor_type"`
	ProcessorLevel     int               `yaml:"processor_level"`
	ProcessorRevision  int               `yaml:"processor_revision"`
	TempRegistry       map[string]string `yaml:"registry"`
	MockRegistry       []Reg
	Root               string `yaml:"root"`
	LocaleSortOrder    int    `yaml:"locale_sort_order"`
	VolumeName         string `yaml:"volume_name"`
	VolumeSerialNumber int    `yaml:"volume_serial_number"`
	VolumeSystemName   string `yaml:"volume_system_name"`
	SystemTime         struct {
		Year        int `yaml:"year"`
		Month       int `yaml:"month"`
		DayOfWeek   int `yaml:"day_of_week"`
		Day         int `yaml:"day"`
		Hour        int `yaml:"hour"`
		Minute      int `yaml:"minute"`
		Second      int `yaml:"second"`
		Millisecond int `yaml:"millisecond"`
	} `yaml:"system_time"`
	Drivers map[int]string
	User    string `yaml:"user"`
}

// WinEmulator type should be a emulator type the eventually will support the
// Emulator interface. This particular emulator is generic to x86 32/64 bit.
type WinEmulator struct {
	UcMode             int
	UcArch             int
	PtrSize            uint64
	Uc                 uc.Unicorn
	Timestamp          int64
	Ticks              uint64
	maxTicks           uint64
	logType            int
	InstructionLog     []*InstructionLog
	Binary             string
	Verbosity          int
	ShowDll            bool
	Args               []string
	Argc               uint64
	Argv               uint64
	SearchPath         []string
	Seed               int
	nameToHook         map[string]*Hook
	libFunctionAddress map[string]map[string]uint64
	libAddressFunction map[string]map[uint64]string
	libOrdinalFunction map[string]map[uint16]string
	libRealLib         map[string]string //set up in loader in loadLibs
	EntryPoint         uint64
	NextLibAddress     uint64
	MemRegions         *MemRegions
	Handles            map[uint64]*Handle
	LoadedModules      map[string]uint64
	LdrIndex           int
	Heap               *core.HeapManager
	Registry           *Registry
	CPU                *core.CpuManager
	Scheduler          *ScheduleManager
	Fls                [64]uint64
	Opts               WinOptions
	ResourcesRoot      pefile.ResourceDirectory
	ProcessManager     *ProcessManager
	// these commands are used to keep state during single step mode
	LastCommand     string
	Breakpoints     map[uint64]uint64
	AutoContinue    bool
	FactFactory     *FactFactory
	GenerateFacts   bool
	GlobalVariables GlobalVariables
	NumMainCallDll  uint //number of dlls whose main are called.
}

//Reference
//https://docs.microsoft.com/en-us/cpp/c-runtime-library/global-variables
type GlobalVariables struct {
	Fmode   uint64
	Commode uint64
}

// AddHook makes a new function hook available to the emulated process
func (emu *WinEmulator) AddHook(lib string, fname string, hook *Hook) {
	emu.nameToHook[fname] = hook
}

// GetHook will get a hook from the list of available hooks, returning the dll,
// function name and hook object
func (emu *WinEmulator) GetHook(addr uint64) (string, string, *Hook) {
	// check if the current address is in some mapped library
	if lib := emu.lookupLibByAddress(addr); lib != "" {
		//check if named function has a hook defined
		if function := emu.libAddressFunction[lib][addr]; function != "" {
			if hook := emu.nameToHook[function]; hook != nil {
				return lib, function, hook
			}
			return lib, function, nil
		}
		return lib, "", nil
	}
	return "", "", nil
}

// defines the basic log types available in winemulator, avaialble to be set via
// command line flags
const (
	LogTypeStdout = iota
	LogTypeJSON
	LogTypeSlice
)

// WinEmulatorOptions will get passed into the WinEmulator
type WinEmulatorOptions struct {
	RootFolder    string
	RunDLLMain    bool
	ConfigPath    string
	VerboseLevel  int
	ShowDLL       bool
	MaxTicks      int64
	LogType       int
	GenerateFacts bool
}

// InitWinEmulatorOptions will build a default option struct to pass into WinEmulator
func InitWinEmulatorOptions() *WinEmulatorOptions {
	return &WinEmulatorOptions{
		RootFolder:    "os/win10_32/",
		RunDLLMain:    false,
		ConfigPath:    "",
		VerboseLevel:  0,
		ShowDLL:       false,
		MaxTicks:      0,
		LogType:       LogTypeStdout,
		GenerateFacts: false,
	}
}

// Load is the entry point for loading a PE file in the emulated environment
func Load(pePath string, args []string, options *WinEmulatorOptions) (*WinEmulator, error) {
	if options == nil {
		options = InitWinEmulatorOptions()
	}

	var err error

	//load the PE
	pe, err := pefile.LoadPeFile(pePath)
	if err != nil {
		return nil, err
	}

	return LoadMem(pe, pePath, args, options)
}

// LoadMem will load a pefile from an already initiated object
func LoadMem(pe *pefile.PeFile, pePath string, args []string, options *WinEmulatorOptions) (*WinEmulator, error) {
	var err error

	emu := &WinEmulator{}
	emu.UcArch = uc.ARCH_X86
	if pe.PeType == pefile.Pe32 {
		emu.UcMode = uc.MODE_32
	} else {
		emu.UcMode = uc.MODE_64
	}
	emu.Timestamp = time.Now().Unix()
	emu.Ticks = 1
	emu.maxTicks = uint64(options.MaxTicks)
	emu.logType = options.LogType
	// log instructions only if the flag is set
	if emu.logType == LogTypeSlice {
		emu.InstructionLog = make([]*InstructionLog, 0)
	}
	emu.Binary = pePath
	emu.Verbosity = options.VerboseLevel
	emu.Args = append([]string{filepath.Base(pePath)}, args...)
	emu.Argc = uint64(len(emu.Args))
	emu.nameToHook = make(map[string]*Hook)
	emu.LoadedModules = make(map[string]uint64)
	emu.libFunctionAddress = make(map[string]map[string]uint64)
	emu.libAddressFunction = make(map[string]map[uint64]string)
	emu.libOrdinalFunction = make(map[string]map[uint16]string)
	emu.libRealLib = make(map[string]string)
	emu.Handles = make(map[uint64]*Handle)
	//this is the first thread
	emu.ShowDll = options.ShowDLL
	emu.MemRegions = &MemRegions{}
	// define each memory section's size
	emu.MemRegions.ProcInfoSize = uint64(4 * 1024 * 1024)
	emu.MemRegions.TibSize = uint64(0x10000)
	emu.MemRegions.GdtSize = uint64(0x10000)
	emu.MemRegions.StackSize = uint64(128 * 1024 * 1024)
	emu.MemRegions.HeapSize = uint64(256 * 1024 * 1024)
	emu.MemRegions.LibSize = uint64(1024 * 1024 * 1024)
	emu.MemRegions.ImageSize = uint64(32 * 1024 * 1024)
	emu.Seed = 1
	emu.ResourcesRoot = pe.ResourceDirectoryRoot
	emu.ProcessManager = InitializeProcessManager(true)
	emu.GenerateFacts = options.GenerateFacts
	if emu.GenerateFacts {
		emu.FactFactory = InitializeFactsFactory()
	}
	if pe.PeType == pefile.Pe32 {
		emu.PtrSize = 4
		emu.MemRegions.GdtAddress = 0xc0000000
		emu.MemRegions.StackAddress = 0xb0000000
		emu.MemRegions.HeapAddress = 0xa0000000
		emu.MemRegions.ProcInfoAddress = 0x7ffdf000
		emu.MemRegions.TibAddress = 0x7efdd000
		emu.MemRegions.LibAddress = 0x20000000
		emu.NextLibAddress = emu.MemRegions.LibAddress
	} else {
		emu.PtrSize = 8
		emu.MemRegions.GdtAddress = 0xc0000000
		emu.MemRegions.StackAddress = 0xfee792a000
		emu.MemRegions.HeapAddress = 0xffe792a000
		emu.MemRegions.ProcInfoAddress = 0x7ffdf000
		emu.MemRegions.TibAddress = 0x7efdd000
		emu.MemRegions.LibAddress = 0x7ff5ce4e0000
		emu.NextLibAddress = emu.MemRegions.LibAddress
	}

	emu.Heap = core.NewHeap(emu.MemRegions.HeapAddress)
	if pe.PeType == pefile.Pe32 {
		emu.GlobalVariables.Fmode = emu.Heap.Malloc(4)
		emu.GlobalVariables.Commode = emu.Heap.Malloc(4)
	} else {
		emu.GlobalVariables.Fmode = emu.Heap.Malloc(8)
		emu.GlobalVariables.Commode = emu.Heap.Malloc(8)
	}
	emu.Breakpoints = make(map[uint64]uint64)

	os.MkdirAll("temp", os.ModePerm)

	emu.Opts = WinOptions{}
	emu.Opts.User = "tbrady"
	emu.Opts.VolumeName = util.RandomName(10)
	emu.Opts.VolumeSerialNumber = 0x6d6e336d
	emu.Opts.VolumeSystemName = "NTFS"
	emu.Opts.CodePageIdentifier = 0x4e4
	emu.Opts.ComputerName = "patriots-12"
	emu.Opts.CurrentLocale = 0x409
	emu.Opts.DllLoadReason = 0x1
	emu.Opts.KeyboardType = 0x7
	emu.Opts.KeyboardSubType = 0x0
	emu.Opts.KeyboardFuncKeys = 0xc
	emu.Opts.OsMajorVersion = 0x0004
	emu.Opts.OsMinorVersion = 0x0
	emu.Opts.ProcessorsCount = 1
	emu.Opts.ProcessorType = 0x24a
	emu.Opts.ProcessorLevel = 0x6
	emu.Opts.ProcessorRevision = 0x4601
	//curTime := time.Now().AddDate(0, 0, -2)
	emu.Opts.SystemTime.Year = time.Now().Year()
	emu.Opts.SystemTime.Month = int(time.Now().Month())
	emu.Opts.SystemTime.Day = time.Now().Day()
	emu.Opts.SystemTime.DayOfWeek = int(time.Now().Weekday())
	emu.Opts.SystemTime.Hour = time.Now().Hour()
	emu.Opts.SystemTime.Minute = time.Now().Minute()
	emu.Opts.SystemTime.Second = time.Now().Second()
	emu.Opts.SystemTime.Millisecond = 14
	emu.Opts.Root = options.RootFolder
	emu.Opts.Env = make([]Env, 20)
	emu.Opts.Env = append(emu.Opts.Env, Env{"ALLUSERSPROFILE", "C:\\ProgramData"})
	emu.Opts.Env = append(emu.Opts.Env, Env{"APPDATA", "C:\\Users\\" + emu.Opts.User + "\\AppData\\roaming"})
	emu.Opts.Env = append(emu.Opts.Env, Env{"CommonProgramFiles", "C:\\Program Files\\Common Files"})
	emu.Opts.Env = append(emu.Opts.Env, Env{"COMPUTERNAME", emu.Opts.ComputerName})
	emu.Opts.Env = append(emu.Opts.Env, Env{"ComSpec", "C:\\Windows\\system32\\cmd.exe"})
	emu.Opts.Env = append(emu.Opts.Env, Env{"HOMEDRIVE", "C:"})
	emu.Opts.Env = append(emu.Opts.Env, Env{"HOMEPATH", "\\Users\\" + emu.Opts.User})
	emu.Opts.Env = append(emu.Opts.Env, Env{"LOCALAPPDATA", "C:\\Users\\" + emu.Opts.User + "\\AppData\\Local"})
	emu.Opts.Env = append(emu.Opts.Env, Env{"LOGONSERVER", "\\" + emu.Opts.ComputerName})
	emu.Opts.Env = append(emu.Opts.Env, Env{"NUMBER_OF_PROCESSORS", string(emu.Opts.ProcessorsCount)})
	emu.Opts.Env = append(emu.Opts.Env, Env{"OneDrive", "C:\\Users\\" + emu.Opts.User + "\\OneDrive"})
	emu.Opts.Env = append(emu.Opts.Env, Env{"OS", "Windows_NT"})
	emu.Opts.Env = append(emu.Opts.Env, Env{"Path", "C:\\Windows\\system32;C:\\Windows;C:\\Windows\\System32\\Wbem;C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\;C:\\Program Files\\dotnet\\;C:\\Users\\" + emu.Opts.User + "\\AppData\\Local\\Microsoft\\WindowsApps;"})
	emu.Opts.Env = append(emu.Opts.Env, Env{"PATHEXT", ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC"})
	emu.Opts.Env = append(emu.Opts.Env, Env{"PROCESSOR_ARCHITECTURE", "x86"})
	emu.Opts.Env = append(emu.Opts.Env, Env{"PROCESSOR_IDENTIFIER", "x86 Family 6 Model 70 Stepping 1, GenuineIntel"})
	emu.Opts.Env = append(emu.Opts.Env, Env{"PROCESSOR_LEVEL", "6"})
	emu.Opts.Env = append(emu.Opts.Env, Env{"PROCESSOR_REVISION", "4601"})
	emu.Opts.Env = append(emu.Opts.Env, Env{"ProgramData", "C:\\ProgramData"})
	emu.Opts.Env = append(emu.Opts.Env, Env{"ProgramFiles", "C:\\Program Files"})
	emu.Opts.Env = append(emu.Opts.Env, Env{"PROMPT", "$P$G"})
	emu.Opts.Env = append(emu.Opts.Env, Env{"PSModulePath", "C:\\Program Files\\WindowsPowerShell\\Modules;C:\\Windows\\system32\\WindowsPowerShell\\v1.0\\Modules"})
	emu.Opts.Env = append(emu.Opts.Env, Env{"PUBLIC", "C:\\Users\\Public"})
	emu.Opts.Env = append(emu.Opts.Env, Env{"SESSIONNAME", "Console"})
	emu.Opts.Env = append(emu.Opts.Env, Env{"SystemDrive", "C:"})
	emu.Opts.Env = append(emu.Opts.Env, Env{"SystemRoot", "C:\\Windows"})
	emu.Opts.Env = append(emu.Opts.Env, Env{"TEMP", "C:\\Users\\" + emu.Opts.User + "\\AppData\\Local\\Temp"})
	emu.Opts.Env = append(emu.Opts.Env, Env{"TMP", "C:\\Users\\" + emu.Opts.User + "\\AppData\\Local\\Temp"})
	emu.Opts.Env = append(emu.Opts.Env, Env{"USERDOMAIN", "patrios-12"})
	emu.Opts.Env = append(emu.Opts.Env, Env{"USERDOMAIN_ROAMINGPROFILE", emu.Opts.ComputerName})
	emu.Opts.Env = append(emu.Opts.Env, Env{"USERNAME", emu.Opts.User})
	emu.Opts.Env = append(emu.Opts.Env, Env{"USERPROFILE", "C:\\Users\\" + emu.Opts.User})
	emu.Opts.Env = append(emu.Opts.Env, Env{"WINDIR", "C:\\Windows"})
	emu.Opts.Env = append(emu.Opts.Env, Env{"COMSPEC", "C:\\Windows\\system32\\cmd.exe"})

	//
	//start default registry
	//
	emu.Opts.TempRegistry = make(map[string]string)
	emu.Opts.TempRegistry["HKEY_LOCAL_MACHINE\\SOFTWARE\\DefaultUserEnvironment\\TEMP"] = "%USERPROFILE%\\AppData\\Local\\Temp"
	emu.Opts.TempRegistry["HKEY_LOCAL_MACHINE\\SOFTWARE\\DefaultUserEnvironment\\TMP"] = "%USERPROFILE%\\AppData\\Local\\Temp"
	emu.Opts.TempRegistry["HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Windows\\ComponentizedBuild"] = "dword:00000001"
	emu.Opts.TempRegistry["HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Windows\\CSDBuildNumber"] = "dword:00000194"
	emu.Opts.TempRegistry["HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Windows\\CSDReleaseType"] = "dword:00000000"
	emu.Opts.TempRegistry["HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Windows\\CSDVersion"] = "dword:00000000"
	emu.Opts.TempRegistry["HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Windows\\Directory"] = "%SystemRoot%"
	emu.Opts.TempRegistry["HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Windows\\ErrorMode"] = "dword:00000000"
	emu.Opts.TempRegistry["HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Windows\\FullProcessInformationSID"] = "hex:01,06,00,00,00,00,00,05,50,00,00,00,5e,f3,0f,b1,81,64,ae,04,b1,4c,a2,29,14,b1,4c,21,a6,56,86,56"
	emu.Opts.TempRegistry["HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Windows\\NoInteraciveServices"] = "dword:00000001"
	emu.Opts.TempRegistry["HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Windows\\ShellErrorMode"] = "dword:00000001"
	emu.Opts.TempRegistry["HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Windows\\SystemDirectory"] = "hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,00,74,00,25,00,5c,00,73,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,00,00"

	emu.Opts.TempRegistry["HKEY_CURRENT_USER\\Software\\AutoIt v3\\AutoIt\\Include"] = "0"
	emu.Opts.TempRegistry["HKEY_CURRENT_USER\\Control Panel\\Mouse\\SwapMouseButtons"] = "0"
	emu.Opts.TempRegistry["HKEY_CURRENT_USER\\Control Panel\\Mouse\\SwapMouseButtons"] = "0"

	emu.Opts.TempRegistry["HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer"] = "0"

	emu.Opts.TempRegistry["HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\PowerShell\\1\\Install"] = "dword:00000001"
	emu.Opts.TempRegistry["HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\PowerShell\\1\\PID"] = "89383-100-0001260-04309"

	var buf []byte
	if buf, err = ioutil.ReadFile(options.ConfigPath); err == nil {
		_ = yaml.Unmarshal(buf, &emu.Opts)
	}
	emu.LdrIndex = 0

	inputSys32Dir := path.Join(emu.Opts.Root, "windows", "system32")
	emu.SearchPath = []string{"temp/", inputSys32Dir, "c:\\Windows\\System32"}

	var mockRegistry *Registry
	if mockRegistry, err = NewRegistry(emu.Opts.TempRegistry); err != nil {
		return nil, err
	}

	emu.Registry = mockRegistry
	emu.Opts.TempRegistry = nil //get GC to clean up temp registry from the config file
	emu.Opts.Drivers = getStubDrivers()
	err = emu.initPe(pe, pePath, emu.UcArch, emu.UcMode, args, options.RunDLLMain)

	emu.CPU = core.NewCpuManager(emu.Uc, emu.UcMode, emu.MemRegions.StackAddress, emu.MemRegions.StackSize, emu.MemRegions.HeapAddress, emu.MemRegions.HeapSize)
	emu.Scheduler = NewScheduleManager(emu)

	return emu, err
}

// ModulePair is used to keep track of the emulator address of a loaded module.
// Used to lookup a certain module in the emulator based on its address in memory.
type ModulePair struct {
	Module  string
	Address uint64
}
type ModuleList []ModulePair

func (m ModuleList) Len() int               { return len(m) }
func (m ModuleList) Less(i int, j int) bool { return m[i].Address < m[j].Address }
func (m ModuleList) Swap(i, j int)          { m[i], m[j] = m[j], m[i] }
func (m ModuleList) Sort()                  { sort.Sort(m) }
func (m ModuleList) Populate(keyvalue map[string]uint64) {
	i := 0
	for k, v := range keyvalue {
		m[i] = ModulePair{k, v}
		i++
	}
}

func CreateModuleList(keyvalue map[string]uint64) ModuleList {
	ml := make(ModuleList, len(keyvalue))
	ml.Populate(keyvalue)
	return ml
}

// lookupLibByAddress Function looks up a dll given a memory address. Scans each
// dll's image base and returns the dll name where the address lives
func (emu *WinEmulator) lookupLibByAddress(addr uint64) string {
	sml := CreateModuleList(emu.LoadedModules)
	sml.Sort()
	for i, tuple := range sml {
		if addr >= tuple.Address {
			//TODO
			// Add condition to last element for if address isn't greater than address space of dll.
			if i == len(sml)-1 {
				return tuple.Module
			}
			if addr < sml[i+1].Address {
				return tuple.Module
			}
		}
	}

	return ""
}

// setLastError will set the error in the proper structure within the emulated
// memory space
func (emu *WinEmulator) setLastError(er uint64) error {
	bs := make([]byte, emu.PtrSize)
	offset := uint64(0x34)
	if emu.PtrSize == 8 {
		offset = uint64(0x68)
		binary.LittleEndian.PutUint64(bs, er)
	} else {
		binary.LittleEndian.PutUint32(bs, uint32(er))
	}
	err := emu.Uc.MemWrite(emu.MemRegions.TibAddress+offset, bs)
	return err
}
func getStubDrivers() map[int]string {
	//Those are drivers taken from Windows10 - 64bit
	drivers := make(map[int]string)
	drivers[0x9200000] = "ntoskrnl.exe"
	drivers[0x9cb6000] = "hal.dll"
	drivers[0xdc00000] = "kd.dll"
	drivers[0xdc10000] = "mcupdate_GenuineIntel.dll"
	drivers[0xde70000] = "msrpc.sys"
	drivers[0xde40000] = "ksecdd.sys"
	drivers[0xde20000] = "werkernel.sys"
	drivers[0xdf10000] = "CLFS.SYS"
	drivers[0xdee0000] = "tm.sys"
	drivers[0xdf80000] = "PSHED.dll"
	drivers[0xdfa0000] = "BOOTVID.dll"
	drivers[0xe110000] = "FLTMGR.SYS"
	drivers[0xe000000] = "clipsp.sys"
	drivers[0xdfb0000] = "cmimcext.sys"
	drivers[0xdfc0000] = "ntosext.sys"
	drivers[0xe190000] = "CI.dll"
	drivers[0xe270000] = "cng.sys"
	drivers[0xe330000] = "Wdf01000.sys"
	drivers[0xdfd0000] = "WDFLDR.SYS"
	drivers[0xe410000] = "WppRecorder.sys"
	drivers[0xdff0000] = "SleepStudyHelper.sys"
	drivers[0xe430000] = "acpiex.sys"
	drivers[0xe460000] = "mssecflt.sys"
	drivers[0xe4b0000] = "SgrmAgent.sys"
	drivers[0xe4d0000] = "lxss.sys"
	drivers[0xe4e0000] = "LXCORE.SYS"
	drivers[0xe600000] = "ACPI.sys"
	drivers[0xe6d0000] = "WMILIB.SYS"
	drivers[0xe6e0000] = "msisadrv.sys"
	drivers[0xe6f0000] = "pci.sys"
	drivers[0xe760000] = "tpm.sys"
	drivers[0xe800000] = "intelpep.sys"
	drivers[0xe7d0000] = "WindowsTrustedRT.sys"
	drivers[0xe7f0000] = "WindowsTrustedRTProxy.sys"
	drivers[0xe860000] = "pcw.sys"
	drivers[0xe880000] = "vdrvroot.sys"
	drivers[0xe8a0000] = "pdc.sys"
	drivers[0xe8e0000] = "CEA.sys"
	drivers[0xe900000] = "partmgr.sys"
	drivers[0xe940000] = "spaceport.sys"
	drivers[0xe9f0000] = "volmgr.sys"
	drivers[0xea10000] = "volmgrx.sys"
	drivers[0xea80000] = "vsock.sys"
	drivers[0xeaa0000] = "vmci.sys"
	drivers[0xeac0000] = "mountmgr.sys"
	drivers[0xeae0000] = "storahci.sys"
	drivers[0xeb10000] = "storport.sys"
	drivers[0xebe0000] = "fileinfo.sys"
	drivers[0xec00000] = "Wof.sys"
	drivers[0xec40000] = "WdFilter.sys"
	drivers[0xecb0000] = "Ntfs.sys"
	drivers[0xef50000] = "Fs_Rec.sys"
	drivers[0xef60000] = "ndis.sys"
	drivers[0xf0e0000] = "NETIO.SYS"
	drivers[0xf180000] = "ksecpkg.sys"
	drivers[0xf1c0000] = "tcpip.sys"
	drivers[0xf4b0000] = "fwpkclnt.sys"
	drivers[0xf530000] = "wfplwfs.sys"
	drivers[0xf570000] = "VmsProxy.sys"
	drivers[0xf590000] = "vmbkmclr.sys"
	drivers[0xf5c0000] = "VmsProxyHNic.sys"
	drivers[0xf5d0000] = "fvevol.sys"
	drivers[0xf6a0000] = "volume.sys"
	drivers[0xf6b0000] = "volsnap.sys"
	drivers[0xf720000] = "rdyboost.sys"
	drivers[0xf770000] = "mup.sys"
	drivers[0xf7a0000] = "iorate.sys"
	drivers[0xf7d0000] = "disk.sys"
	drivers[0xf7f0000] = "CLASSPNP.SYS"
	drivers[0x22f50000] = "crashdmp.sys"
	drivers[0x22040000] = "cdrom.sys"
	drivers[0x22080000] = "filecrypt.sys"
	drivers[0x220a0000] = "tbs.sys"
	drivers[0x220b0000] = "Null.SYS"
	drivers[0x220c0000] = "Beep.SYS"
	drivers[0x220d0000] = "vmkbd.sys"
	drivers[0x220e0000] = "dxgkrnl.sys"
	drivers[0x22460000] = "watchdog.sys"
	drivers[0x22480000] = "BasicDisplay.sys"
	drivers[0x224a0000] = "BasicRender.sys"
	drivers[0x224c0000] = "Npfs.SYS"
	drivers[0x224e0000] = "Msfs.SYS"
	drivers[0x22500000] = "tdx.sys"
	drivers[0x22530000] = "TDI.SYS"
	drivers[0x22550000] = "ws2ifsl.sys"
	drivers[0x22560000] = "netbt.sys"
	drivers[0x225c0000] = "afunix.sys"
	drivers[0x225e0000] = "afd.sys"
	drivers[0x22690000] = "vwififlt.sys"
	drivers[0x226b0000] = "vfpext.sys"
	drivers[0x22820000] = "pacer.sys"
	drivers[0x22850000] = "netbios.sys"
	drivers[0x22870000] = "rdbss.sys"
	drivers[0x228f0000] = "csc.sys"
	drivers[0x22990000] = "nsiproxy.sys"
	drivers[0x229b0000] = "npsvctrig.sys"
	drivers[0x229c0000] = "mssmbios.sys"
	drivers[0x229e0000] = "gpuenergydrv.sys"
	drivers[0x229f0000] = "dfsc.sys"
	drivers[0x22a40000] = "fastfat.SYS"
	drivers[0x22ab0000] = "bam.sys"
	drivers[0x22ad0000] = "ahcache.sys"
	drivers[0x22b20000] = "vmbusr.sys"
	drivers[0x22b70000] = "hvsocket.sys"
	drivers[0x22ba0000] = "winhvr.sys"
	drivers[0x22bc0000] = "vmnetadapter.sys"
	drivers[0x22bd0000] = "VMNET.SYS"
	drivers[0x22be0000] = "Vid.sys"
	drivers[0x22c70000] = "CompositeBus.sys"
	drivers[0x22c90000] = "kdnic.sys"
	drivers[0x22ca0000] = "umbus.sys"
	drivers[0x22cc0000] = "CAD.sys"
	drivers[0x248e0000] = "igdkmd64.sys"
	drivers[0x25530000] = "USBXHCI.SYS"
	drivers[0x23e00000] = "ucx01000.sys"
	drivers[0x23e50000] = "iaLPSS2i_I2C.sys"
	drivers[0x23e80000] = "SpbCx.sys"
	drivers[0x23ea0000] = "TeeDriverW8x64.sys"
	drivers[0x23ef0000] = "atikmpag.sys"
	drivers[0x29a90000] = "atikmdag.sys"
	drivers[0x28c00000] = "Netwbw02.sys"
	drivers[0x28f90000] = "vwifibus.sys"
	drivers[0x28fa0000] = "rt640x64.sys"
	drivers[0x29050000] = "i8042prt.sys"
	drivers[0x29080000] = "kbdclass.sys"
	drivers[0x290a0000] = "mouclass.sys"
	drivers[0x290c0000] = "HDAudBus.sys"
	drivers[0x290f0000] = "portcls.sys"
	drivers[0x29160000] = "drmk.sys"
	drivers[0x29190000] = "ks.sys"
	drivers[0x29210000] = "iaLPSS2i_GPIO2.sys"
	drivers[0x29230000] = "msgpioclx.sys"
	drivers[0x29270000] = "intelppm.sys"
	drivers[0x292b0000] = "acpipagr.sys"
	drivers[0x292c0000] = "wmiacpi.sys"
	drivers[0x292d0000] = "CmBatt.sys"
	drivers[0x292e0000] = "BATTC.SYS"
	drivers[0x29300000] = "DellRbtn.sys"
	drivers[0x29310000] = "mshidkmdf.sys"
	drivers[0x29320000] = "HIDCLASS.SYS"
	drivers[0x29360000] = "HIDPARSE.SYS"
	drivers[0x29380000] = "UEFI.sys"
	drivers[0x29390000] = "vpcivsp.sys"
	drivers[0x293c0000] = "storvsp.sys"
	drivers[0x293f0000] = "NdisVirtualBus.sys"
	drivers[0x29400000] = "swenum.sys"
	drivers[0x29410000] = "rdpbus.sys"
	drivers[0x29420000] = "UsbHub3.sys"
	drivers[0x294c0000] = "USBD.SYS"
	drivers[0x294d0000] = "hidi2c.sys"
	drivers[0x294f0000] = "RTKVHD64.sys"
	drivers[0x29990000] = "ksthunk.sys"
	drivers[0x299a0000] = "IntcDAud.sys"
	drivers[0x29a70000] = "mouhid.sys"
	drivers[0x2cf80000] = "MTConfig.sys"
	drivers[0x2cf90000] = "usbccgp.sys"
	drivers[0x23f90000] = "RtsUer.sys"
	drivers[0x24000000] = "ibtusb.sys"
	drivers[0x2cfd0000] = "BTHUSB.sys"
	drivers[0x24040000] = "bthport.sys"
	drivers[0x241b0000] = "usbvideo.sys"
	drivers[0x24200000] = "dump_diskdump.sys"
	drivers[0x24240000] = "dump_storahci.sys"
	drivers[0x24290000] = "dump_dumpfve.sys"
	drivers[0xcb510000] = "win32k.sys"
	drivers[0xcaa00000] = "win32kfull.sys"
	drivers[0xcadb0000] = "win32kbase.sys"
	drivers[0x24560000] = "dxgmms2.sys"
	drivers[0x24640000] = "monitor.sys"
	drivers[0xcb060000] = "cdd.dll"
	drivers[0x24660000] = "mmcss.sys"
	drivers[0x24680000] = "luafv.sys"
	drivers[0x246b0000] = "wcifs.sys"
	drivers[0x246f0000] = "cldflt.sys"
	drivers[0x24770000] = "storqosflt.sys"
	drivers[0x247b0000] = "p9rdr.sys"
	drivers[0x247d0000] = "vmnetbridge.sys"
	drivers[0x247f0000] = "lltdio.sys"
	drivers[0x24810000] = "mslldp.sys"
	drivers[0x24830000] = "rspndr.sys"
	drivers[0x24850000] = "vmnetuserif.sys"
	drivers[0x24860000] = "wanarp.sys"
	drivers[0x242b0000] = "vmswitch.sys"
	drivers[0x24510000] = "ndisuio.sys"
	drivers[0x22ce0000] = "nwifi.sys"
	drivers[0x24530000] = "condrv.sys"
	drivers[0x24880000] = "winquic.sys"
	drivers[0x22da0000] = "HTTP.sys"
	drivers[0x255c0000] = "bowser.sys"
	drivers[0x248c0000] = "mpsdrv.sys"
	drivers[0x22f70000] = "mrxsmb.sys"
	drivers[0x8fe0000] = "mrxsmb20.sys"
	drivers[0x9030000] = "vwifimp.sys"
	drivers[0x9050000] = "vmx86.sys"
	drivers[0x9080000] = "hcmon.sys"
	drivers[0x90a0000] = "srvnet.sys"
	drivers[0x9100000] = "mqac.sys"
	drivers[0x8800000] = "srv2.sys"
	drivers[0x88d0000] = "Ndu.sys"
	drivers[0x8900000] = "npf.sys"
	drivers[0x8910000] = "peauth.sys"
	drivers[0x89f0000] = "tcpipreg.sys"
	drivers[0x8a10000] = "vstor2-x64.sys"
	drivers[0x8a20000] = "rassstp.sys"
	drivers[0x8a40000] = "NDProxy.sys"
	drivers[0x8a90000] = "AgileVpn.sys"
	drivers[0x8ac0000] = "rasl2tp.sys"
	drivers[0x8af0000] = "raspptp.sys"
	drivers[0x8b20000] = "raspppoe.sys"
	drivers[0x8b40000] = "ndistapi.sys"
	drivers[0x8b50000] = "ndiswan.sys"
	drivers[0x8b90000] = "WdNisDrv.sys"
	drivers[0x8bb0000] = "bindflt.sys"
	drivers[0x8cc0000] = "USBSTOR.SYS"
	drivers[0x8d10000] = "WUDFRd.sys"
	drivers[0x8d70000] = "WpdUpFltr.sys"
	return drivers
}
