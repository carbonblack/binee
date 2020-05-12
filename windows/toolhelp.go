package windows

import (
	"github.com/carbonblack/binee/util"
	"unsafe"
)

// #define TH32CS_SNAPHEAPLIST 0x1
// #define TH32CS_SNAPPROCESS  0x2
// #define TH32CS_SNAPTHREAD   0x4
// #define TH32CS_SNAPMODULE   0x8
// #define TH32CS_SNAPALL  (TH32CS_SNAPHEAPLIST|TH32CS_SNAPPROCESS|TH32CS_SNAPTHREAD|TH32CS_SNAPMODULE)
// #define TH32CS_INHERIT  0x80000000

const (
	Th32csSnapheaplist = 0x1
	Th32csSnapprocess  = 0x2
	Th32csSnapthread   = 0x4
	Th32csSnapmodule   = 0x8
	Th32csSnapall      = Th32csSnapheaplist | Th32csSnapprocess | Th32csSnapthread | Th32csSnapmodule
	Th32csInherit      = 0x80000000
)

type Snapshot struct {
	/* Heap list */
	//ULONG HeapListCount;
	//ULONG HeapListIndex;
	//ULONG_PTR HeapListOffset;
	///* Module list */
	//ULONG ModuleListCount;
	//ULONG ModuleListIndex;
	//ULONG_PTR ModuleListOffset;
	/* Process list */
	ProcessListCount uint64
	ProcessListIndex uint64
	ProcessList      []ProcessEntry
	/* Thread list */
	//ULONG ThreadListCount;
	//ULONG ThreadListIndex;
	//ULONG_PTR ThreadListOffset;
}
type ProcessEntryW struct {
	dwSize              uint32
	cntUsage            uint32
	the32ProcessID      uint32
	th32DefaultHeapID   uint32
	th32ModuleID        uint32
	cntThreads          uint32
	th32ParentProcessID uint32
	pcPriClassBase      int32
	dwFlags             uint32
	szExeFile           [260 * 2]byte
}
type ProcessEntry struct {
	dwSize              uint32
	cntUsage            uint32
	the32ProcessID      uint32
	th32DefaultHeapID   uint32
	th32ModuleID        uint32
	cntThreads          uint32
	th32ParentProcessID uint32
	pcPriClassBase      int32
	dwFlags             uint32
	szExeFile           [260]byte
}

func (p ProcessEntry) toWide() *ProcessEntryW {
	wideProcess := &ProcessEntryW{}
	wideProcess.dwSize = uint32(unsafe.Sizeof(ProcessEntryW{}))
	wideProcess.cntUsage = p.cntUsage
	wideProcess.the32ProcessID = p.the32ProcessID
	wideProcess.th32DefaultHeapID = p.th32DefaultHeapID
	wideProcess.th32ModuleID = p.th32ModuleID
	wideProcess.cntThreads = p.cntThreads
	wideProcess.th32ParentProcessID = p.th32ParentProcessID
	wideProcess.pcPriClassBase = p.pcPriClassBase
	wideProcess.dwFlags = p.dwFlags
	for i := 0; i < 260*2; i += 2 {
		if p.szExeFile[i/2] == 0 {
			wideProcess.szExeFile[i] = 0
			wideProcess.szExeFile[i+1] = 0
			break
		}
		wideProcess.szExeFile[i] = p.szExeFile[i/2]
		wideProcess.szExeFile[i+1] = 0
	}
	return wideProcess
}

func createToolhelp32Snapshot(emu *WinEmulator, in *Instruction) func(emu *WinEmulator, in *Instruction) bool {
	dwFlags := in.Args[0]
	snapshotHandle := &Handle{
		Snapshot: &Snapshot{ProcessListCount: 0},
	}
	if dwFlags&Th32csSnapprocess > 1 {
		snapshotHandle.Snapshot.ProcessList = emu.ProcessManager.getProcessEntries()
		snapshotHandle.Snapshot.ProcessListCount = emu.ProcessManager.numberOfProcesses

	}
	handleAddr := emu.Heap.Malloc(4)
	emu.Handles[handleAddr] = snapshotHandle
	return SkipFunctionStdCall(true, handleAddr)
}

func process32First(emu *WinEmulator, in *Instruction, wide bool) func(emu *WinEmulator, in *Instruction) bool {
	if emu.Handles[in.Args[0]].Snapshot == nil {
		return SkipFunctionStdCall(true, 0)
	}
	snapshot := emu.Handles[in.Args[0]].Snapshot
	snapshot.ProcessListIndex = 1
	returnAddress := in.Args[1]
	var process interface{}
	if wide {
		process = snapshot.ProcessList[0].toWide()
	} else {
		process = snapshot.ProcessList[0]
	}
	util.StructWrite(emu.Uc, returnAddress, process)
	return SkipFunctionStdCall(true, 1)
}
func process32Next(emu *WinEmulator, in *Instruction, wide bool) func(emu *WinEmulator, in *Instruction) bool {
	if emu.Handles[in.Args[0]].Snapshot == nil {
		return SkipFunctionStdCall(true, 0)
	}
	snapshot := emu.Handles[in.Args[0]].Snapshot
	index := snapshot.ProcessListIndex
	if index == snapshot.ProcessListCount {
		return SkipFunctionStdCall(true, 0)
	}
	returnAddress := in.Args[1]
	var process interface{}
	if wide {
		process = snapshot.ProcessList[index].toWide()
	} else {
		process = snapshot.ProcessList[index]
	}
	util.StructWrite(emu.Uc, returnAddress, process)
	snapshot.ProcessListIndex++
	return SkipFunctionStdCall(true, 1)
}

func ToolHelpHooks(emu *WinEmulator) {
	emu.AddHook("", "CreateToolhelp32Snapshot", &Hook{
		Parameters: []string{"dwFlags", "the32ProceessID"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			return createToolhelp32Snapshot(emu, in)(emu, in)
		},
	})

	emu.AddHook("", "Process32First", &Hook{
		Parameters: []string{"hSnapshot", "lppe"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			return process32First(emu, in, false)(emu, in)
		},
	})
	emu.AddHook("", "Process32FirstW", &Hook{
		Parameters: []string{"hSnapshot", "lppe"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			return process32First(emu, in, true)(emu, in)
		},
	})
	emu.AddHook("", "Process32Next", &Hook{
		Parameters: []string{"hSnapshot", "lppe"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			return process32Next(emu, in, false)(emu, in)
		},
	})
	emu.AddHook("", "Process32NextW", &Hook{
		Parameters: []string{"hSnapshot", "lppe"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			return process32Next(emu, in, true)(emu, in)
		},
	})

	emu.AddHook("", "GetTokenInformation", &Hook{
		Parameters: []string{"TokenHandle", "TokenInformationClass", "TokenInformation", "TokenInformationLength", "ReturnLength"},
		Fn:         SkipFunctionStdCall(true, 0),
	})
}
