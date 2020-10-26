package windows

import (
	"fmt"
	"math"
	"unsafe"
)

type ProcessManager struct {
	numberOfProcesses uint64
	processList       []Process
	processMap        map[uint32]Process
	currentPid        uint32
	remoteThreadMap   map[uint32]RemoteThread
	atomicRThreadNum  uint32 //base number for remote thread ids 0xca7

}
type Process struct {
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

	//Other features might be added
	remoteThreadIds []uint32
}
type RemoteThread struct {
	remoteThreadID   uint32
	ownerProcessID   uint32
	creatorProcessID uint32
	dwCreationFlags  uint32
	lpStartAddress   uint32
	lpParameter      uint32
	dwStackSize      uint32
	currentState     byte
	stackAddress     uint32
	stackSize        uint32
	//lpThreadAttributes	uint32 //

	//thread 				Thread   // todo for future development

}

func InitializeProcessManager(addStub bool) *ProcessManager {
	newProcessManager := &ProcessManager{numberOfProcesses: 0}
	newProcessManager.processMap = make(map[uint32]Process)
	newProcessManager.currentPid = 0
	newProcessManager.remoteThreadMap = make(map[uint32]RemoteThread)
	if addStub {
		newProcessManager.addStubProcesses()
	}
	return newProcessManager
}

func (p *ProcessManager) addStubProcesses() {
	stub := make(map[string]interface{})
	//This data is extracted from a windows 10-64bit os.
	stub["szExeFile"] = "[System Process]"
	stub["cntThreads"] = uint32(0)
	stub["th32ParentProcessID"] = uint32(2)
	stub["pcPriClassBase"] = int32(0)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "System"
	stub["cntThreads"] = uint32(4)
	stub["th32ParentProcessID"] = uint32(118)
	stub["pcPriClassBase"] = int32(0)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "Registry"
	stub["cntThreads"] = uint32(88)
	stub["th32ParentProcessID"] = uint32(4)
	stub["pcPriClassBase"] = int32(4)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "smss.exe"
	stub["cntThreads"] = uint32(352)
	stub["th32ParentProcessID"] = uint32(2)
	stub["pcPriClassBase"] = int32(4)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "csrss.exe"
	stub["cntThreads"] = uint32(468)
	stub["th32ParentProcessID"] = uint32(10)
	stub["pcPriClassBase"] = int32(456)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "csrss.exe"
	stub["cntThreads"] = uint32(548)
	stub["th32ParentProcessID"] = uint32(11)
	stub["pcPriClassBase"] = int32(540)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "wininit.exe"
	stub["cntThreads"] = uint32(556)
	stub["th32ParentProcessID"] = uint32(2)
	stub["pcPriClassBase"] = int32(456)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "winlogon.exe"
	stub["cntThreads"] = uint32(624)
	stub["th32ParentProcessID"] = uint32(4)
	stub["pcPriClassBase"] = int32(540)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "services.exe"
	stub["cntThreads"] = uint32(688)
	stub["th32ParentProcessID"] = uint32(9)
	stub["pcPriClassBase"] = int32(556)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "lsass.exe"
	stub["cntThreads"] = uint32(704)
	stub["th32ParentProcessID"] = uint32(8)
	stub["pcPriClassBase"] = int32(556)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "svchost.exe"
	stub["cntThreads"] = uint32(808)
	stub["th32ParentProcessID"] = uint32(19)
	stub["pcPriClassBase"] = int32(688)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "fontdrvhost.exe"
	stub["cntThreads"] = uint32(848)
	stub["th32ParentProcessID"] = uint32(5)
	stub["pcPriClassBase"] = int32(624)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "fontdrvhost.exe"
	stub["cntThreads"] = uint32(844)
	stub["th32ParentProcessID"] = uint32(5)
	stub["pcPriClassBase"] = int32(556)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "WUDFHost.exe"
	stub["cntThreads"] = uint32(872)
	stub["th32ParentProcessID"] = uint32(8)
	stub["pcPriClassBase"] = int32(688)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "svchost.exe"
	stub["cntThreads"] = uint32(980)
	stub["th32ParentProcessID"] = uint32(12)
	stub["pcPriClassBase"] = int32(688)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "dwm.exe"
	stub["cntThreads"] = uint32(420)
	stub["th32ParentProcessID"] = uint32(13)
	stub["pcPriClassBase"] = int32(624)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "WUDFHost.exe"
	stub["cntThreads"] = uint32(432)
	stub["th32ParentProcessID"] = uint32(8)
	stub["pcPriClassBase"] = int32(688)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "svchost.exe"
	stub["cntThreads"] = uint32(308)
	stub["th32ParentProcessID"] = uint32(9)
	stub["pcPriClassBase"] = int32(688)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "svchost.exe"
	stub["cntThreads"] = uint32(1036)
	stub["th32ParentProcessID"] = uint32(16)
	stub["pcPriClassBase"] = int32(688)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "svchost.exe"
	stub["cntThreads"] = uint32(1072)
	stub["th32ParentProcessID"] = uint32(17)
	stub["pcPriClassBase"] = int32(688)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "svchost.exe"
	stub["cntThreads"] = uint32(1240)
	stub["th32ParentProcessID"] = uint32(3)
	stub["pcPriClassBase"] = int32(688)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "svchost.exe"
	stub["cntThreads"] = uint32(1300)
	stub["th32ParentProcessID"] = uint32(25)
	stub["pcPriClassBase"] = int32(688)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "svchost.exe"
	stub["cntThreads"] = uint32(1344)
	stub["th32ParentProcessID"] = uint32(58)
	stub["pcPriClassBase"] = int32(688)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "svchost.exe"
	stub["cntThreads"] = uint32(1460)
	stub["th32ParentProcessID"] = uint32(21)
	stub["pcPriClassBase"] = int32(688)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "Memory Compression"
	stub["cntThreads"] = uint32(1476)
	stub["th32ParentProcessID"] = uint32(62)
	stub["pcPriClassBase"] = int32(4)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "svchost.exe"
	stub["cntThreads"] = uint32(1624)
	stub["th32ParentProcessID"] = uint32(10)
	stub["pcPriClassBase"] = int32(688)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "svchost.exe"
	stub["cntThreads"] = uint32(1708)
	stub["th32ParentProcessID"] = uint32(4)
	stub["pcPriClassBase"] = int32(688)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "svchost.exe"
	stub["cntThreads"] = uint32(1716)
	stub["th32ParentProcessID"] = uint32(6)
	stub["pcPriClassBase"] = int32(688)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "spoolsv.exe"
	stub["cntThreads"] = uint32(1832)
	stub["th32ParentProcessID"] = uint32(7)
	stub["pcPriClassBase"] = int32(688)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "svchost.exe"
	stub["cntThreads"] = uint32(1868)
	stub["th32ParentProcessID"] = uint32(12)
	stub["pcPriClassBase"] = int32(688)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "svchost.exe"
	stub["cntThreads"] = uint32(1940)
	stub["th32ParentProcessID"] = uint32(16)
	stub["pcPriClassBase"] = int32(688)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "svchost.exe"
	stub["cntThreads"] = uint32(2004)
	stub["th32ParentProcessID"] = uint32(15)
	stub["pcPriClassBase"] = int32(688)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "svchost.exe"
	stub["cntThreads"] = uint32(1528)
	stub["th32ParentProcessID"] = uint32(16)
	stub["pcPriClassBase"] = int32(688)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "svchost.exe"
	stub["cntThreads"] = uint32(1488)
	stub["th32ParentProcessID"] = uint32(4)
	stub["pcPriClassBase"] = int32(688)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "svchost.exe"
	stub["cntThreads"] = uint32(2124)
	stub["th32ParentProcessID"] = uint32(12)
	stub["pcPriClassBase"] = int32(688)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "dllhost.exe"
	stub["cntThreads"] = uint32(2232)
	stub["th32ParentProcessID"] = uint32(5)
	stub["pcPriClassBase"] = int32(688)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "PresentationFontCache.exe"
	stub["cntThreads"] = uint32(2240)
	stub["th32ParentProcessID"] = uint32(4)
	stub["pcPriClassBase"] = int32(688)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "coherence.exe"
	stub["cntThreads"] = uint32(2264)
	stub["th32ParentProcessID"] = uint32(3)
	stub["pcPriClassBase"] = int32(688)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "sqlwriter.exe"
	stub["cntThreads"] = uint32(2276)
	stub["th32ParentProcessID"] = uint32(2)
	stub["pcPriClassBase"] = int32(688)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "MsMpEng.exe"
	stub["cntThreads"] = uint32(2288)
	stub["th32ParentProcessID"] = uint32(25)
	stub["pcPriClassBase"] = int32(688)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "prl_tools_service.exe"
	stub["cntThreads"] = uint32(2300)
	stub["th32ParentProcessID"] = uint32(7)
	stub["pcPriClassBase"] = int32(688)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "dasHost.exe"
	stub["cntThreads"] = uint32(2496)
	stub["th32ParentProcessID"] = uint32(3)
	stub["pcPriClassBase"] = int32(1072)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "prl_tools.exe"
	stub["cntThreads"] = uint32(2552)
	stub["th32ParentProcessID"] = uint32(9)
	stub["pcPriClassBase"] = int32(2300)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "dllhost.exe"
	stub["cntThreads"] = uint32(2784)
	stub["th32ParentProcessID"] = uint32(10)
	stub["pcPriClassBase"] = int32(688)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "msdtc.exe"
	stub["cntThreads"] = uint32(2880)
	stub["th32ParentProcessID"] = uint32(9)
	stub["pcPriClassBase"] = int32(688)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "coherence.exe"
	stub["cntThreads"] = uint32(2536)
	stub["th32ParentProcessID"] = uint32(3)
	stub["pcPriClassBase"] = int32(2264)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "coherence.exe"
	stub["cntThreads"] = uint32(3828)
	stub["th32ParentProcessID"] = uint32(3)
	stub["pcPriClassBase"] = int32(2536)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "sihost.exe"
	stub["cntThreads"] = uint32(4476)
	stub["th32ParentProcessID"] = uint32(11)
	stub["pcPriClassBase"] = int32(1344)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "svchost.exe"
	stub["cntThreads"] = uint32(4512)
	stub["th32ParentProcessID"] = uint32(13)
	stub["pcPriClassBase"] = int32(688)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "taskhostw.exe"
	stub["cntThreads"] = uint32(4612)
	stub["th32ParentProcessID"] = uint32(9)
	stub["pcPriClassBase"] = int32(1344)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "explorer.exe"
	stub["cntThreads"] = uint32(4940)
	stub["th32ParentProcessID"] = uint32(62)
	stub["pcPriClassBase"] = int32(4912)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "svchost.exe"
	stub["cntThreads"] = uint32(5072)
	stub["th32ParentProcessID"] = uint32(12)
	stub["pcPriClassBase"] = int32(688)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "StartMenuExperienceHost.exe"
	stub["cntThreads"] = uint32(5180)
	stub["th32ParentProcessID"] = uint32(16)
	stub["pcPriClassBase"] = int32(808)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "RuntimeBroker.exe"
	stub["cntThreads"] = uint32(5280)
	stub["th32ParentProcessID"] = uint32(5)
	stub["pcPriClassBase"] = int32(808)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "SearchUI.exe"
	stub["cntThreads"] = uint32(5380)
	stub["th32ParentProcessID"] = uint32(43)
	stub["pcPriClassBase"] = int32(808)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "SearchIndexer.exe"
	stub["cntThreads"] = uint32(5400)
	stub["th32ParentProcessID"] = uint32(19)
	stub["pcPriClassBase"] = int32(688)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "RuntimeBroker.exe"
	stub["cntThreads"] = uint32(5520)
	stub["th32ParentProcessID"] = uint32(14)
	stub["pcPriClassBase"] = int32(808)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "SkypeApp.exe"
	stub["cntThreads"] = uint32(5960)
	stub["th32ParentProcessID"] = uint32(15)
	stub["pcPriClassBase"] = int32(808)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "SkypeBackgroundHost.exe"
	stub["cntThreads"] = uint32(5968)
	stub["th32ParentProcessID"] = uint32(4)
	stub["pcPriClassBase"] = int32(808)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "ApplicationFrameHost.exe"
	stub["cntThreads"] = uint32(5988)
	stub["th32ParentProcessID"] = uint32(3)
	stub["pcPriClassBase"] = int32(808)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "MicrosoftEdge.exe"
	stub["cntThreads"] = uint32(6032)
	stub["th32ParentProcessID"] = uint32(25)
	stub["pcPriClassBase"] = int32(808)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "YourPhone.exe"
	stub["cntThreads"] = uint32(6072)
	stub["th32ParentProcessID"] = uint32(16)
	stub["pcPriClassBase"] = int32(808)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "browser_broker.exe"
	stub["cntThreads"] = uint32(6180)
	stub["th32ParentProcessID"] = uint32(3)
	stub["pcPriClassBase"] = int32(808)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "RuntimeBroker.exe"
	stub["cntThreads"] = uint32(6188)
	stub["th32ParentProcessID"] = uint32(1)
	stub["pcPriClassBase"] = int32(808)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "MicrosoftEdgeSH.exe"
	stub["cntThreads"] = uint32(6372)
	stub["th32ParentProcessID"] = uint32(9)
	stub["pcPriClassBase"] = int32(6188)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "MicrosoftEdgeCP.exe"
	stub["cntThreads"] = uint32(6416)
	stub["th32ParentProcessID"] = uint32(16)
	stub["pcPriClassBase"] = int32(808)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "prl_cc.exe"
	stub["cntThreads"] = uint32(6640)
	stub["th32ParentProcessID"] = uint32(31)
	stub["pcPriClassBase"] = int32(2552)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "ctfmon.exe"
	stub["cntThreads"] = uint32(6680)
	stub["th32ParentProcessID"] = uint32(8)
	stub["pcPriClassBase"] = int32(1072)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "TabTip.exe"
	stub["cntThreads"] = uint32(6704)
	stub["th32ParentProcessID"] = uint32(6)
	stub["pcPriClassBase"] = int32(1072)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "WindowsInternal.ComposableShell.Experiences.TextInput.InputApp.exe"
	stub["cntThreads"] = uint32(7116)
	stub["th32ParentProcessID"] = uint32(11)
	stub["pcPriClassBase"] = int32(808)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "RuntimeBroker.exe"
	stub["cntThreads"] = uint32(7320)
	stub["th32ParentProcessID"] = uint32(4)
	stub["pcPriClassBase"] = int32(808)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "SecurityHealthSystray.exe"
	stub["cntThreads"] = uint32(7420)
	stub["th32ParentProcessID"] = uint32(1)
	stub["pcPriClassBase"] = int32(4940)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "SecurityHealthService.exe"
	stub["cntThreads"] = uint32(7448)
	stub["th32ParentProcessID"] = uint32(7)
	stub["pcPriClassBase"] = int32(688)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "RuntimeBroker.exe"
	stub["cntThreads"] = uint32(7540)
	stub["th32ParentProcessID"] = uint32(3)
	stub["pcPriClassBase"] = int32(808)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "OneDrive.exe"
	stub["cntThreads"] = uint32(7580)
	stub["th32ParentProcessID"] = uint32(26)
	stub["pcPriClassBase"] = int32(4940)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "jusched.exe"
	stub["cntThreads"] = uint32(7960)
	stub["th32ParentProcessID"] = uint32(2)
	stub["pcPriClassBase"] = int32(7596)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "RuntimeBroker.exe"
	stub["cntThreads"] = uint32(8036)
	stub["th32ParentProcessID"] = uint32(2)
	stub["pcPriClassBase"] = int32(808)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "SecurityHealthHost.exe"
	stub["cntThreads"] = uint32(3020)
	stub["th32ParentProcessID"] = uint32(1)
	stub["pcPriClassBase"] = int32(808)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "ShellExperienceHost.exe"
	stub["cntThreads"] = uint32(5032)
	stub["th32ParentProcessID"] = uint32(14)
	stub["pcPriClassBase"] = int32(808)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "RuntimeBroker.exe"
	stub["cntThreads"] = uint32(4164)
	stub["th32ParentProcessID"] = uint32(3)
	stub["pcPriClassBase"] = int32(808)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "SgrmBroker.exe"
	stub["cntThreads"] = uint32(4964)
	stub["th32ParentProcessID"] = uint32(5)
	stub["pcPriClassBase"] = int32(688)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "svchost.exe"
	stub["cntThreads"] = uint32(7900)
	stub["th32ParentProcessID"] = uint32(8)
	stub["pcPriClassBase"] = int32(688)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "WinStore.App.exe"
	stub["cntThreads"] = uint32(5288)
	stub["th32ParentProcessID"] = uint32(16)
	stub["pcPriClassBase"] = int32(808)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "RuntimeBroker.exe"
	stub["cntThreads"] = uint32(820)
	stub["th32ParentProcessID"] = uint32(2)
	stub["pcPriClassBase"] = int32(808)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "jucheck.exe"
	stub["cntThreads"] = uint32(7176)
	stub["th32ParentProcessID"] = uint32(5)
	stub["pcPriClassBase"] = int32(7960)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "svchost.exe"
	stub["cntThreads"] = uint32(1332)
	stub["th32ParentProcessID"] = uint32(3)
	stub["pcPriClassBase"] = int32(688)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "Video.UI.exe"
	stub["cntThreads"] = uint32(1324)
	stub["th32ParentProcessID"] = uint32(18)
	stub["pcPriClassBase"] = int32(808)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "RuntimeBroker.exe"
	stub["cntThreads"] = uint32(5008)
	stub["th32ParentProcessID"] = uint32(2)
	stub["pcPriClassBase"] = int32(808)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "dllhost.exe"
	stub["cntThreads"] = uint32(6140)
	stub["th32ParentProcessID"] = uint32(6)
	stub["pcPriClassBase"] = int32(808)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "taskhostw.exe"
	stub["cntThreads"] = uint32(5044)
	stub["th32ParentProcessID"] = uint32(4)
	stub["pcPriClassBase"] = int32(1344)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "Microsoft.Photos.exe"
	stub["cntThreads"] = uint32(8084)
	stub["th32ParentProcessID"] = uint32(14)
	stub["pcPriClassBase"] = int32(808)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "RuntimeBroker.exe"
	stub["cntThreads"] = uint32(7872)
	stub["th32ParentProcessID"] = uint32(9)
	stub["pcPriClassBase"] = int32(808)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "cmd.exe"
	stub["cntThreads"] = uint32(2856)
	stub["th32ParentProcessID"] = uint32(2)
	stub["pcPriClassBase"] = int32(4940)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "conhost.exe"
	stub["cntThreads"] = uint32(8912)
	stub["th32ParentProcessID"] = uint32(5)
	stub["pcPriClassBase"] = int32(2856)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "SearchProtocolHost.exe"
	stub["cntThreads"] = uint32(4236)
	stub["th32ParentProcessID"] = uint32(7)
	stub["pcPriClassBase"] = int32(5400)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "SearchFilterHost.exe"
	stub["cntThreads"] = uint32(8636)
	stub["th32ParentProcessID"] = uint32(5)
	stub["pcPriClassBase"] = int32(5400)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "backgroundTaskHost.exe"
	stub["cntThreads"] = uint32(5496)
	stub["th32ParentProcessID"] = uint32(14)
	stub["pcPriClassBase"] = int32(808)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "svchost.exe"
	stub["cntThreads"] = uint32(4664)
	stub["th32ParentProcessID"] = uint32(4)
	stub["pcPriClassBase"] = int32(688)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "RuntimeBroker.exe"
	stub["cntThreads"] = uint32(3232)
	stub["th32ParentProcessID"] = uint32(7)
	stub["pcPriClassBase"] = int32(808)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "WmiPrvSE.exe"
	stub["cntThreads"] = uint32(5616)
	stub["th32ParentProcessID"] = uint32(10)
	stub["pcPriClassBase"] = int32(808)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "NisSrv.exe"
	stub["cntThreads"] = uint32(3220)
	stub["th32ParentProcessID"] = uint32(7)
	stub["pcPriClassBase"] = int32(688)
	p.startProcess(stub)

	stub = make(map[string]interface{})
	stub["szExeFile"] = "a.exe"
	stub["cntThreads"] = uint32(8420)
	stub["th32ParentProcessID"] = uint32(2)
	stub["pcPriClassBase"] = int32(2856)
	p.startProcess(stub)

}
func (p *Process) processAsEntry() ProcessEntry {
	return ProcessEntry{p.dwSize, p.cntUsage, p.the32ProcessID, p.th32DefaultHeapID, p.th32ModuleID,
		p.cntThreads, p.th32ParentProcessID, p.pcPriClassBase, p.dwFlags, p.szExeFile}
}

func (p *ProcessManager) getProcessEntries() []ProcessEntry {
	processEntries := make([]ProcessEntry, p.numberOfProcesses)
	for i := range p.processList {
		processEntries[i] = p.processList[i].processAsEntry()
	}
	return processEntries
}
func (p *ProcessManager) terminateProcess(pid uint32) bool {
	status := false
	index := p.findProcess(pid)
	if index == -1 {
		return status
	}
	delete(p.processMap, pid)
	if index >= 0 && uint64(index) < p.numberOfProcesses {
		p.processList = append(p.processList[0:index], p.processList[index+1:]...)
		p.numberOfProcesses -= 1
		status = true
	}
	return status
}
func (p *ProcessManager) findProcess(processID uint32) int {
	for i, proc := range p.processList {
		if proc.the32ProcessID == processID {
			return i
		}
	}
	return -1
}

func (p *ProcessManager) startProcess(parameters map[string]interface{}) bool {
	newProcess := Process{dwSize: uint32(unsafe.Sizeof(ProcessEntry{})), cntUsage: 0, th32DefaultHeapID: 0, th32ModuleID: 0, dwFlags: 0}

	for parameter, value := range parameters {
		//Any new parameter should be added here with no headache of changing the function everywhere.
		switch parameter {
		case "dwSize":
			newProcess.dwSize = value.(uint32)
			continue
		case "cntUsage":
			newProcess.cntUsage = value.(uint32)
			continue
		case "the32ProcessID":
			newProcess.the32ProcessID = value.(uint32)
			continue
		case "th32DefaultHeapID":
			newProcess.th32DefaultHeapID = value.(uint32)
			continue
		case "th32ModuleID":
			newProcess.th32ModuleID = value.(uint32)
			continue
		case "cntThreads":
			newProcess.cntThreads = value.(uint32)
			continue
		case "th32ParentProcessID":
			newProcess.th32ParentProcessID = value.(uint32)
			continue
		case "pcPriClassBase":
			newProcess.pcPriClassBase = value.(int32)
			continue
		case "dwFlags":
			newProcess.dwFlags = value.(uint32)
			continue
		case "szExeFile":
			szExeFile := value.(string)
			var processNameAdjusted [260]byte
			copy(processNameAdjusted[0:259], szExeFile)
			length := math.Min(float64(len(szExeFile)), 259)
			processNameAdjusted[int(length)] = 0
			newProcess.szExeFile = processNameAdjusted
			continue
		default:
			fmt.Errorf("specified parameter [%s] not supported", parameter)
		}

	}
	for i := p.currentPid; i != p.currentPid-1; i += 1 { //check if we reached again meaning there is no available number.
		if i == 65000 { //according to https://techcommunity.microsoft.com/t5/windows-blog-archive/pushing-the-limits-of-windows-processes-and-threads/ba-p/723824
			i = 0 //Maximum number of process is around this number.
		}
		if _, exists := p.processMap[i]; !exists {
			p.currentPid = i
			break
		}
	}
	newProcess.the32ProcessID = p.currentPid
	p.processMap[p.currentPid] = newProcess
	p.numberOfProcesses++
	p.processList = append(p.processList, newProcess)
	return true
}

func (p *ProcessManager) startRemoteThread(parameters map[string]interface{}) uint32 {

	remoteThread := RemoteThread{}
	for parameter, value := range parameters {

		switch parameter {
		case "dwCreationFlags":
			remoteThread.dwCreationFlags = value.(uint64)
			continue
		case "lpParameter":
			remoteThread.lpParameter = value.(uint64)
			continue
		case "creatorProcessID":
			remoteThread.creatorProcessID = value.(uint32)
			continue
		case "ownerProcessID":
			remoteThread.ownerProcessID = value.(uint32)
			continue
		case "lpStartAddress":
			remoteThread.lpStartAddress = value.(uint64)
			continue
		case "stackSize":
			remoteThread.dwStackSize = value.(uint64)
		case "stackAddress":
			remoteThread.stackAddress = value.(uint64)

		default:
			fmt.Errorf("specified parameter [%s] not supported", parameter)
		}

	}

	if p.atomicRThreadNum > 0xca7+1000000 { //max range of remote threads IDs
		p.atomicRThreadNum = 0xca7
	}
	remoteThread.remoteThreadID = p.atomicRThreadNum
	remoteThread.currentState = byte(remoteThread.dwCreationFlags) & 0x04

	if ownerProcess, exists := p.processMap[remoteThread.ownerProcessID]; exists {
		p.remoteThreadMap[p.atomicRThreadNum] = remoteThread
		ownerProcess.remoteThreadIds = append(ownerProcess.remoteThreadIds, remoteThread.remoteThreadID)

	} else {
		//Todo Create Dummy Process
		remoteThread.remoteThreadID = 0xca6 //id for dummy thread
	}
	p.atomicRThreadNum += 1

	return remoteThread.remoteThreadID

}
