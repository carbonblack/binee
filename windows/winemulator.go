package windows

import (
	"encoding/binary"
	"io/ioutil"
	"os"
	"time"

	"github.com/carbonblack/binee/pefile"
	"gopkg.in/yaml.v2"

	//import "regexp"
	cs "github.com/kgwinnup/gapstone"

	"sort"

	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"

	core "github.com/carbonblack/binee/core"
)

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
	User string `yaml:"user"`
}

// WinEmulator type should be a emulator type the eventually will support the
// Emulator interface. This particular emulator is generic to x86 32/64 bit.
type WinEmulator struct {
	UcMode             int
	UcArch             int
	PtrSize            uint64
	Uc                 uc.Unicorn
	Cs                 cs.Engine
	Timestamp          int64
	Ticks              uint64
	Binary             string
	Verbosity          int
	AsJson             bool
	ShowDll            bool
	Args               []string
	Argc               uint64
	Argv               uint64
	SearchPath         []string
	Seed               int
	nameToHook         map[string]*Hook
	libFunctionAddress map[string]map[string]uint64
	libAddressFunction map[string]map[uint64]string
	libRealLib         map[string]string //set up in loader in loadLibs
	EntryPoint         uint64
	NextLibAddress     uint64
	MemRegions         *MemRegions
	Handles            map[uint64]*Handle
	LoadedModules      map[string]uint64
	Heap               *core.HeapManager
	Registry           *Registry
	Cpu                *core.CpuManager
	Scheduler          *ScheduleManager
	Fls                [64]uint64
	Opts               WinOptions
	// these commands are used to keep state during single step mode
	LastCommand  string
	Breakpoints  map[uint64]uint64
	AutoContinue bool
}

func (self *WinEmulator) AddHook(lib string, fname string, hook *Hook) {
	self.nameToHook[fname] = hook
}

func (self *WinEmulator) GetHook(addr uint64) (string, string, *Hook) {
	// check if the current address is in some mapped library
	if lib := self.LookupLibByAddress(addr); lib != "" {
		//check if named function has a hook defined
		if function := self.libAddressFunction[lib][addr]; function != "" {
			if hook := self.nameToHook[function]; hook != nil {
				return lib, function, hook
			}
			return lib, function, nil
		}
		return lib, "", nil
	}
	return "", "", nil
}

// WinEmulatorOptions will get passed into the WinEmulator
type WinEmulatorOptions struct {
	RootFolder   string
	RunDLLMain   bool
	ConfigPath   string
	VerboseLevel int
	ShowDLL      bool
}

// InitWinEmulatorOptions will build a default option struct to pass into WinEmulator
func InitWinEmulatorOptions() *WinEmulatorOptions {
	return &WinEmulatorOptions{
		RootFolder:   "os/win10_32/",
		RunDLLMain:   false,
		ConfigPath:   "",
		VerboseLevel: 0,
		ShowDLL:      false,
	}
}

func New(path string, arch, mode int, args []string, options *WinEmulatorOptions) (*WinEmulator, error) {
	if options == nil {
		options = InitWinEmulatorOptions()
	}

	var err error
	emu := WinEmulator{}
	emu.UcMode = mode
	emu.UcArch = arch
	emu.Timestamp = time.Now().Unix()
	emu.Ticks = 1
	emu.Binary = path
	emu.Verbosity = options.VerboseLevel
	emu.Args = args
	emu.Argc = uint64(len(args))
	emu.nameToHook = make(map[string]*Hook)
	emu.LoadedModules = make(map[string]uint64)
	emu.libFunctionAddress = make(map[string]map[string]uint64)
	emu.libAddressFunction = make(map[string]map[uint64]string)
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

	if mode == uc.MODE_32 {
		emu.PtrSize = 4

		if emu.Cs, err = cs.New(cs.CS_ARCH_X86, cs.CS_MODE_32); err != nil {
			return nil, err
		}

		emu.MemRegions.GdtAddress = 0xc0000000
		emu.MemRegions.StackAddress = 0xb0000000
		emu.MemRegions.HeapAddress = 0xa0000000
		emu.MemRegions.ProcInfoAddress = 0x7ffdf000
		emu.MemRegions.TibAddress = 0x7efdd000
		emu.MemRegions.LibAddress = 0x20000000
		emu.NextLibAddress = emu.MemRegions.LibAddress

	} else {
		emu.PtrSize = 8

		if emu.Cs, err = cs.New(cs.CS_ARCH_X86, cs.CS_MODE_64); err != nil {
			return nil, err
		}

		emu.MemRegions.ProcInfoAddress = 0x7ffdf000
		emu.MemRegions.GdtAddress = 0xc0000000
		emu.MemRegions.StackAddress = 0xfee792a000
		emu.MemRegions.HeapAddress = 0xffe792a000
		emu.MemRegions.LibAddress = 0x7ff5ce4e0000
		emu.NextLibAddress = emu.MemRegions.LibAddress
	}

	emu.Heap = core.NewHeap(emu.MemRegions.HeapAddress)
	emu.Breakpoints = make(map[uint64]uint64)

	os.MkdirAll("temp", os.ModePerm)

	emu.Opts = WinOptions{}
	emu.Opts.User = "tbrady"
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
	emu.Opts.Env = append(emu.Opts.Env, Env{"windir", "C:\\Windows"})

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

	emu.SearchPath = []string{"temp/", emu.Opts.Root + "windows/system32/", "c:\\Windows\\System32"}

	var mockRegistry *Registry
	if mockRegistry, err = NewRegistry(emu.Opts.TempRegistry); err != nil {
		return &emu, err
	} else {
		emu.Registry = mockRegistry
		emu.Opts.TempRegistry = nil //get GC to clean up temp registry from the config file
	}

	//load the PE
	pe, err := pefile.LoadPeFile(emu.Binary)
	if err != nil {
		return nil, err
	}
	err = emu.initPe(pe, path, arch, mode, args, options.RunDLLMain)

	emu.Cpu = core.NewCpuManager(emu.Uc, emu.UcMode, emu.MemRegions.StackAddress, emu.MemRegions.StackSize, emu.MemRegions.HeapAddress, emu.MemRegions.HeapSize)
	emu.Scheduler = NewScheduleManager(&emu)

	return &emu, err
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

// Function looks up a dll given a memory address. Scans each dll's image base
// and returns the dll name where the address lives
func (emu *WinEmulator) LookupLibByAddress(addr uint64) string {
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

// helper function for SetLastError hook in kernel32, winbase
func (emu *WinEmulator) SetLastError(e uint64) error {
	bs := make([]byte, emu.PtrSize)
	offset := uint64(0x34)
	if emu.PtrSize == 8 {
		offset = uint64(0x68)
		binary.LittleEndian.PutUint64(bs, e)
	} else {
		binary.LittleEndian.PutUint32(bs, uint32(e))
	}
	err := emu.Uc.MemWrite(emu.MemRegions.TibAddress+offset, bs)
	return err
}
