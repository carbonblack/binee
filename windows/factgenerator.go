package windows

import (
	"fmt"
)

type FactFactory struct {
	Facts   map[string]uint32        //Acts as set
	Factory map[string]FactGenerator //Function name and used to call
}
type FactGenerator struct {
	Fn func(emu *WinEmulator, in *Instruction) []string
}

func openProcessFacts(emu *WinEmulator, in *Instruction) []string {
	processID := in.Args[2]
	facts := make([]string, 2)
	facts[0] = fmt.Sprintf(FCT_PROCESS, processID)
	facts[1] = fmt.Sprintf(FCT_TARGETS, FCT_SELF_PROCESS_ID, processID)
	return facts
}

func virtualAllocExFacts(emu *WinEmulator, in *Instruction) []string {
	processHandle := in.Args[0]
	facts := make([]string, 1)
	processID, err := emu.getProcessID(processHandle)
	if err != nil {
		return []string{}
	}
	facts[0] = fmt.Sprintf(FCT_ALLOCATED_MEMORY, FCT_SELF_PROCESS_ID, processID)
	return facts
}

func writeProcessMemoryFacts(emu *WinEmulator, in *Instruction) []string {
	processHandle := in.Args[0]
	baseAddress := in.Args[1]
	size := in.Args[3]
	processID, err := emu.getProcessID(processHandle)
	if err != nil {
		return []string{}
	}
	facts := make([]string, 2)
	selfProcess := fmt.Sprintf(FCT_PROCESS_ID_SUFFIX, FCT_SELF_PROCESS_ID)
	otherProcess := fmt.Sprintf(FCT_PROCESS_ID_SUFFIX, processID)
	facts[0] = fmt.Sprintf(FCT_WROTE_BYTES_1, processID, baseAddress, baseAddress+size)
	facts[1] = fmt.Sprintf(FCT_WROTE_BYTES_2, selfProcess, otherProcess)
	return facts
}

func createRemoteThreadFacts(emu *WinEmulator, in *Instruction) []string {
	threadID := in.Hook.Return
	processHandle := in.Args[0]
	processID, err := emu.getProcessID(processHandle)
	if err != nil {
		return []string{}
	}
	startAddress := in.Args[4]
	facts := make([]string, 5)
	facts[0] = fmt.Sprintf(FCT_THREAD, threadID)
	facts[1] = fmt.Sprintf(FCT_OWNS, processID, threadID)
	facts[2] = fmt.Sprintf(FCT_HAS, threadID, startAddress)
	facts[3] = fmt.Sprintf(FCT_CREATED, FCT_SELF_PROCESS_ID, threadID)
	facts[4] = fmt.Sprintf(FCT_THREAD_IS, threadID, "remotely_created")
	return facts
}

func ResumeThreadFacts(emu *WinEmulator, in *Instruction) []string {
	threadId := in.Args[0]
	facts := make([]string, 1)
	facts[0] = fmt.Sprintf(FCT_THREAD_IS, threadId, "is_resumed")
	return facts
}

func OpenThreadFacts(emu *WinEmulator, in *Instruction) []string {
	threadId := in.Hook.Return
	facts := make([]string, 2)
	facts[0] = fmt.Sprintf(FCT_THREAD, threadId)
	ownerID := 0x3 //Just a placeholder for now
	facts[1] = fmt.Sprintf(FCT_OWNS, ownerID, threadId)
	return facts
}

func QueueUserApcFacts(emu *WinEmulator, in *Instruction) []string {
	threadID := in.Args[1]
	facts := make([]string, 2)
	facts[0] = fmt.Sprintf(FCT_HAS_QUEUE, threadID)
	facts[1] = fmt.Sprintf(FCT_QUEUED, FCT_SELF_PROCESS_ID, threadID)
	return facts
}

func CreateProcessAFacts(emu *WinEmulator, in *Instruction) []string {
	//process(pid_<lpProcessInformation->dwProcessId>).
	//	thread(tid_<lpProcessInformation->dwThreadId>).
	//	owns(pid<>, tid_<>).
	//	is(tid_<lpProcessInformation->dwThreadId>, main_suspended).
	//	created(pid_<Process who invoked this API>, tid_<>)
	facts := make([]string, 5)

	//facts[0]=fmt.Sprintf(FCT_PROCESS,proces)
	//facts[1]=

	return facts
}

func FindWindowAFacts(emu *WinEmulator, in *Instruction) []string {
	var facts []string
	windowName := in.Hook.Values[1].(string)
	otherProcessID := FCT_PROCESS_NOTFOUND //maybe changed later
	fact := fmt.Sprintf(FCT_SEARCHES, FCT_SELF_PROCESS_ID, windowName, otherProcessID)
	facts = append(facts, fact)
	fact = fmt.Sprintf(FCT_UUID_NAME_SUFFIX, windowName)
	if otherProcessID != FCT_PROCESS_NOTFOUND { //Later we get the actual process window
		fact = fmt.Sprintf(FCT_TARGETS, FCT_SELF_PROCESS_ID, otherProcessID)
		facts = append(facts, fact)
	}
	for i := 0; i < len(DEBUGGER_PROCESS); i++ {
		if DEBUGGER_PROCESS[i] == windowName {
			fact = fmt.Sprintf(FCT_UUID_IS, windowName, "debugger_app")
			facts = append(facts, fact)
		}
	}
	return facts
}

func ZwSuspendProcessFacts(emu *WinEmulator, in *Instruction) []string {
	processHandle := in.Args[0]
	processID, err := emu.getProcessID(processHandle)
	threadID := 0x1337 //To be implemented
	if err != nil {
		return []string{}
	}
	facts := make([]string, 3)
	facts[0] = fmt.Sprintf(FCT_PROCESS, processID)
	facts[1] = fmt.Sprintf(FCT_PROCESS_IS, processID, "status_suspended")
	facts[2] = fmt.Sprintf(FCT_THREAD_IS, threadID, "status_suspended")
	return facts
}

func SetPropAFacts(emu *WinEmulator, in *Instruction) []string {
	facts := make([]string, 2)
	windowID := in.Args[0]
	pid := fmt.Sprintf(FCT_PROCESS_ID_SUFFIX, FCT_SELF_PROCESS_ID)
	uuid := fmt.Sprintf(FCT_UUID_ID_SUFFIX, windowID)
	facts[0] = fmt.Sprintf(FCT_WROTE_BYTES_2, pid, uuid)
	facts[1] = fmt.Sprintf(FCT_WINDOW, uuid)
	return facts
}

func CreateFileMappingAFacts(emu *WinEmulator, in *Instruction) []string {
	facts := make([]string, 2)
	pid := fmt.Sprintf(FCT_PROCESS_ID_SUFFIX, FCT_SELF_PROCESS_ID)
	uuid := fmt.Sprintf(FCT_UUID_ID_SUFFIX, in.Hook.Return)
	facts[0] = fmt.Sprintf(FCT_CREATED_FILEMAP, pid, uuid)
	facts[1] = fmt.Sprintf(FCT_FILEMAP, uuid)
	return facts
}
func MapViewOfFile(emu *WinEmulator, in *Instruction) []string {
	facts := make([]string, 2)
	pid := fmt.Sprintf(FCT_PROCESS_ID_SUFFIX, FCT_SELF_PROCESS_ID)
	uuid := fmt.Sprintf(FCT_UUID_ID_SUFFIX, in.Args[0])
	pid2 := fmt.Sprintf(FCT_PROCESS_ID_SUFFIX, FCT_SELF_PROCESS_ID)
	facts[0] = fmt.Sprintf(FCT_MAPPEDFILE, pid, uuid, pid2)
	facts[1] = fmt.Sprintf(FCT_FILEMAP, uuid)
	return facts
}

func ZwMapViewOfSectionFacts(emu *WinEmulator, in *Instruction) []string {
	facts := make([]string, 2)
	pid := fmt.Sprintf(FCT_PROCESS_ID_SUFFIX, FCT_SELF_PROCESS_ID)
	uuid := fmt.Sprintf(FCT_UUID_ID_SUFFIX, in.Args[0])
	processID, err := emu.getProcessID(in.Args[1])
	if err != nil {
		return []string{}
	}
	pid2 := fmt.Sprintf(FCT_PROCESS_ID_SUFFIX, processID)
	facts[0] = fmt.Sprintf(FCT_MAPPEDFILE, pid, uuid, pid2)
	facts[1] = fmt.Sprintf(FCT_FILEMAP, uuid)
	return facts
}

func InitializeFactsFactory() *FactFactory {
	factFactory := &FactFactory{Facts: make(map[string]uint32), Factory: make(map[string]FactGenerator)}

	//Initialize Self
	selfProcess := fmt.Sprintf(FCT_PROCESS, FCT_SELF_PROCESS_ID)
	factFactory.Facts[selfProcess] = 1

	/*Process Injection*/
	factFactory.Factory["OpenProcess"] = FactGenerator{openProcessFacts}
	factFactory.Factory["VirtualAllocEx"] = FactGenerator{virtualAllocExFacts}
	factFactory.Factory["WriteProcessMemory"] = FactGenerator{writeProcessMemoryFacts}
	factFactory.Factory["CreateRemoteThread"] = FactGenerator{createRemoteThreadFacts}
	factFactory.Factory["ResumeThread"] = FactGenerator{ResumeThreadFacts}
	factFactory.Factory["OpenThread"] = FactGenerator{OpenThreadFacts}
	factFactory.Factory["QueueUserAPC"] = FactGenerator{QueueUserApcFacts}
	factFactory.Factory["CreateProcessA"] = FactGenerator{CreateProcessAFacts}
	factFactory.Factory["FindWindowA"] = FactGenerator{FindWindowAFacts}
	factFactory.Factory["ZwSuspendProcess"] = FactGenerator{ZwSuspendProcessFacts}
	factFactory.Factory["SetPropA"] = FactGenerator{SetPropAFacts}
	factFactory.Factory["CreateFileMappingA"] = FactGenerator{CreateFileMappingAFacts}
	factFactory.Factory["MapViewOfFile"] = FactGenerator{MapViewOfFile}
	factFactory.Factory["ZwMapViewOfSection"] = FactGenerator{ZwMapViewOfSectionFacts}
	return factFactory
}

func addFact(in *Instruction, emu *WinEmulator) bool {
	if _, ok := emu.FactFactory.Factory[in.Hook.Name]; !ok {
		return false
	}
	facts := emu.FactFactory.Factory[in.Hook.Name].Fn(emu, in)
	for _, i := range facts {
		if _, ok := emu.FactFactory.Facts[i]; !ok {
			emu.FactFactory.Facts[i] = 0
		}
		emu.FactFactory.Facts[i] += 1
	}
	return true
}
