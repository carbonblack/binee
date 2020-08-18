package windows

import (
	"fmt"
	"math"
)

type FactFactory struct {
	Facts   map[string]uint32        //Acts as set
	Factory map[string]FactGenerator //Function name and used to call
}
type FactGenerator struct {
	Fn func(emu *WinEmulator, in *Instruction) []string
}

func writeProcessMemoryFacts(emu *WinEmulator, in *Instruction) []string {

	baseAddress := in.Args[1]
	size := in.Args[3]
	processID := in.Args[0]

	var facts []string
	facts = append(facts, fmt.Sprintf("wroteBytes(pid_0x%x,0x%x,0x%x).", processID, baseAddress, baseAddress+size))
	facts = append(facts, fmt.Sprintf("wroteBytes(0x%x,0x%x).", math.MaxUint32, processID))
	return facts
}

func createRemoteThreadFacts(emu *WinEmulator, in *Instruction) []string {

	threadID := in.Hook.Return
	processID := in.Args[0]
	startAddress := in.Args[3]
	thread := fmt.Sprintf("thread(tid_0x%x).", threadID)
	owns := fmt.Sprintf("owns(pid_0x%x,tid_0x%x).", processID, threadID)
	is := fmt.Sprintf("has(tid_0x%x,0x%x).", threadID, startAddress)
	has := fmt.Sprintf("created(pid_0x%x,tid_0x%x).", math.MaxUint32, threadID)
	facts := []string{thread, owns, is, has}
	return facts
}

func openProcessFacts(emu *WinEmulator, in *Instruction) []string {
	//process(pid_<dwProcessId>).
	//targets(pid_<Process who invoked this API>, pid_<deProcessId>).
	processID := in.Hook.Return
	var facts []string
	facts = append(facts, fmt.Sprintf("process(pid_0x%x).", processID))
	facts = append(facts, fmt.Sprintf("targets(pid_0x%x,pid_0x%x).", math.MaxUint32, processID))
	return facts
}

func virtualAllocExFacts(emu *WinEmulator, in *Instruction) []string {
	processID := in.Args[0]
	baseAddress := in.Hook.Return
	size := in.Args[2]
	var facts []string
	facts = append(facts, fmt.Sprintf("allocatedMemory(pid_0x%x,0x%x,0x%x).", processID, baseAddress, baseAddress+size))
	facts = append(facts, fmt.Sprintf("allocatedMemory(pid_0x%x,pid_0x%x).", math.MaxUint32, processID))
	return facts
}

func InitializeFactsFactory() *FactFactory {
	factFactory := &FactFactory{Facts: make(map[string]uint32), Factory: make(map[string]FactGenerator)}
	factFactory.Factory["CreateRemoteThread"] = FactGenerator{createRemoteThreadFacts}
	factFactory.Factory["WriteProcessMemory"] = FactGenerator{writeProcessMemoryFacts}
	factFactory.Factory["OpenProcess"] = FactGenerator{openProcessFacts}
	factFactory.Factory["VirtualAllocEx"] = FactGenerator{virtualAllocExFacts}
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
