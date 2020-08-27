package windows

import (
	"encoding/binary"
	"github.com/carbonblack/binee/util"
)

func getCommandLine(emu *WinEmulator, in *Instruction) bool {
	//This is a temporary implementation, we should depend on peb.
	wide := in.Hook.Name[len(in.Hook.Name)-1] == 'W'
	length := 0
	cmd := ""
	for i, _ := range emu.Args {
		length += len(emu.Args[i])
		cmd += emu.Args[i] + " "
	}
	cmd = cmd[:len(cmd)-1]
	var raw []byte

	if wide {
		raw = append(util.ASCIIToWinWChar(cmd), 0, 0)
	} else {
		raw = append([]byte(cmd), 0)
	}
	addr := emu.Heap.Malloc(uint64(len(raw)))
	if err := emu.Uc.MemWrite(addr, raw); err != nil {
		return SkipFunctionStdCall(true, 0)(emu, in)
	}
	return SkipFunctionStdCall(true, addr)(emu, in)
}
func pCmdLn(emu *WinEmulator, in *Instruction) bool {
	length := 0
	cmd := ""
	for i, _ := range emu.Args {
		length += len(emu.Args[i])
		cmd += emu.Args[i] + " "
	}
	cmd = cmd[:len(cmd)-1]
	var raw []byte
	var rawWide []byte
	rawWide = append(util.ASCIIToWinWChar(cmd), 0, 0)
	raw = append([]byte(cmd), 0)

	addr := emu.Heap.Malloc(uint64(len(raw)))
	addrW := emu.Heap.Malloc(uint64(len(rawWide)))
	if err := emu.Uc.MemWrite(addr, raw); err != nil {
		return SkipFunctionStdCall(true, 0)(emu, in)
	}
	if err := emu.Uc.MemWrite(addrW, rawWide); err != nil {
		return SkipFunctionStdCall(true, 0)(emu, in)
	}
	var temp uint64
	if emu.PtrSize == 4 {
		temp = emu.Heap.Malloc(8)
		addrBuff := make([]byte, 4)
		binary.LittleEndian.PutUint32(addrBuff, uint32(addr))
		emu.Uc.MemWrite(temp, addrBuff)
		binary.LittleEndian.PutUint32(addrBuff, uint32(addrW))
		emu.Uc.MemWrite(temp+4, addrBuff)

	} else {
		temp = emu.Heap.Malloc(16)
		addrBuff := make([]byte, 8)
		binary.LittleEndian.PutUint64(addrBuff, addr)
		emu.Uc.MemWrite(temp, addrBuff)
		binary.LittleEndian.PutUint64(addrBuff, addrW)
		emu.Uc.MemWrite(temp+4, addrBuff)
	}
	return SkipFunctionStdCall(true, temp)(emu, in)
}

func Processenv(emu *WinEmulator) {
	emu.AddHook("", "GetCommandLineW", &Hook{
		Parameters: []string{},
		Fn:         getCommandLine,
	})
	emu.AddHook("", "GetCommandLineA", &Hook{
		Parameters: []string{},
		Fn:         getCommandLine,
	})
	emu.AddHook("", "__p__acmdln", &Hook{
		Parameters: []string{""},
		Fn:         pCmdLn,
	})
}
