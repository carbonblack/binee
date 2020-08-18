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
	facts[0] = fmt.Sprintf("%s(%s0x%x).", PROCESS, PROCESS_ID_SUFFIX, processID)
	facts[1] = fmt.Sprintf("%s(%s%x,%s0x%x).", TARGETS, PROCESS_ID_SUFFIX, SELF_PROCESS_ID, PROCESS_ID_SUFFIX, processID)
	return facts
}

func virtualAllocExFacts(emu *WinEmulator, in *Instruction) []string {
	processHandle := in.Args[0]
	facts := make([]string, 1)
	processID, err := emu.getProcessID(processHandle)
	if err != nil {
		return []string{}
	}
	facts[0] = fmt.Sprintf("%s(%s0x%x,%s0x%x).", ALLOCATED_MEMORY, PROCESS_ID_SUFFIX, SELF_PROCESS_ID, PROCESS_ID_SUFFIX, processID)
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
	facts[0] = fmt.Sprintf("%s(%s0x%x,0x%x,0x%x).", WROTE_BYTES, PROCESS_ID_SUFFIX, processID, baseAddress, baseAddress+size)
	facts[1] = fmt.Sprintf("%s(%s0x%x,%s0x%x).", WROTE_BYTES, PROCESS_ID_SUFFIX, SELF_PROCESS_ID, PROCESS_ID_SUFFIX, processID)
	return facts
}

func createRemoteThreadFacts(emu *WinEmulator, in *Instruction) []string {
	threadID := in.Hook.Return
	processHandle := in.Args[0]
	processID, err := emu.getProcessID(processHandle)
	if err != nil {
		return []string{}
	}
	startAddress := in.Args[3]
	facts := make([]string, 4)
	facts[0] = fmt.Sprintf("%s(%s0x%x).", THREAD, THREAD_ID_SUFFIX, threadID)
	facts[1] = fmt.Sprintf("%s(%s0x%x,%s0x%x).", OWNS, PROCESS_ID_SUFFIX, processID, THREAD_ID_SUFFIX, threadID)
	facts[2] = fmt.Sprintf("%s(%s0x%x,0x%x).", HAS, THREAD_ID_SUFFIX, threadID, startAddress)
	facts[3] = fmt.Sprintf("%s(%s0x%x,%s0x%x).", CREATED, PROCESS_ID_SUFFIX, SELF_PROCESS_ID, THREAD_ID_SUFFIX, threadID)
	return facts
}

func ResumeThreadFacts(emu *WinEmulator, in *Instruction) []string {
	threadId := in.Args[0]
	facts := make([]string, 1)
	facts[0] = fmt.Sprintf("%s(%s0x%x).", IS, THREAD_ID_SUFFIX, threadId)
	return facts
}

func OpenThreadFacts(emu *WinEmulator, in *Instruction) []string {
	threadId := in.Args[0]
	facts := make([]string, 2)
	facts[0] = fmt.Sprintf("%s(%s0x%x).", THREAD, THREAD_ID_SUFFIX, threadId)
	ownerID := 0x420 //Just a placeholder for now
	facts[1] = fmt.Sprintf("%s(%s0x%x,%s0x%x).", OWNS, PROCESS_ID_SUFFIX, ownerID, THREAD_ID_SUFFIX, threadId)
	return facts
}

func QueueUserApcFacts(emu *WinEmulator, in *Instruction) []string {
	threadID := in.Args[2]
	facts := make([]string, 2)
	facts[0] = fmt.Sprintf("%s(%s0x%x,queue_apc).", HAS, THREAD_ID_SUFFIX, threadID)
	facts[1] = fmt.Sprintf("%s(%s%x,%s0x%x).", QUEUED, PROCESS_ID_SUFFIX, SELF_PROCESS_ID, THREAD_ID_SUFFIX, threadID)
	return facts
}

func InitializeFactsFactory() *FactFactory {
	factFactory := &FactFactory{Facts: make(map[string]uint32), Factory: make(map[string]FactGenerator)}

	//Initialize Self
	selfProcess := fmt.Sprintf("%s(%s%x).", PROCESS, PROCESS_ID_SUFFIX, SELF_PROCESS_ID)
	factFactory.Facts[selfProcess] = 1

	/*Process Injection*/
	factFactory.Factory["OpenProcess"] = FactGenerator{openProcessFacts}
	factFactory.Factory["VirtualAllocEx"] = FactGenerator{virtualAllocExFacts}
	factFactory.Factory["WriteProcessMemory"] = FactGenerator{writeProcessMemoryFacts}
	factFactory.Factory["CreateRemoteThread"] = FactGenerator{createRemoteThreadFacts}
	factFactory.Factory["ResumeThread"] = FactGenerator{ResumeThreadFacts}
	factFactory.Factory["OpenThread"] = FactGenerator{OpenThreadFacts}
	factFactory.Factory["QueueUserAPC"] = FactGenerator{QueueUserApcFacts}
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
