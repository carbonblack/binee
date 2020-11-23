package windows

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"unsafe"
)

type SHELLEXECUTEINFO struct {
	CbSize       uint32
	FMask        uint32
	HWnd         uint32
	LpVerb       uint32
	LpFile       uint32
	LpParameters uint32
	LpDirectory  uint32
	NShow        int32
	HInstApp     uint32
	LpIDList     uint32
	LpClass      uint32
	HkeyClass    uint32
	DwHotKey     uint32
	HIconMonitor uint32
	HProcess     uint32
}

func shellExecuteEx(emu *WinEmulator, in *Instruction) bool {
	wide := in.Hook.Name[len(in.Hook.Name)-1] == 'W'
	addr := in.Args[0]
	raw, _ := emu.Uc.MemRead(addr, uint64(unsafe.Sizeof(SHELLEXECUTEINFO{})))
	r := bytes.NewReader(raw)
	sh := &SHELLEXECUTEINFO{}
	err := binary.Read(r, binary.LittleEndian, sh)
	if err != nil {
		fmt.Errorf("couldn't read SHELLEXECUTEINFO")
		return SkipFunctionStdCall(true, 0)(emu, in)
	}
	//resetting the stack done first before adding parameters
	//as the function SkipFunctionStdCall depends on number of parameters.
	retVal := SkipFunctionStdCall(true, 1)(emu, in)
	if wide {
		in.Hook.Parameters = append(in.Hook.Parameters, "w:lpVerb")
		in.Hook.Parameters = append(in.Hook.Parameters, "w:lpFile")
		in.Hook.Parameters = append(in.Hook.Parameters, "w:lpParameters")
	} else {
		in.Hook.Parameters = append(in.Hook.Parameters, "a:lpVerb")
		in.Hook.Parameters = append(in.Hook.Parameters, "a:lpFile")
		in.Hook.Parameters = append(in.Hook.Parameters, "a:lpParameters")
	}
	in.Hook.Values = append(in.Hook.Values, uint64(sh.LpVerb))
	in.Hook.Values = append(in.Hook.Values, uint64(sh.LpFile))
	in.Hook.Values = append(in.Hook.Values, uint64(sh.LpParameters))
	in.Args = append(in.Args, uint64(sh.LpVerb))
	in.Args = append(in.Args, uint64(sh.LpFile))
	in.Args = append(in.Args, uint64(sh.LpParameters))
	return retVal
}

func ShellapiHooks(emu *WinEmulator) {
	emu.AddHook("", "SHGetFileInfoA", &Hook{
		Parameters: []string{"a:pszPath", "dwFileAttributes", "psfi", "cbFileInfo", "uFlags"},
		Fn:         SkipFunctionStdCall(false, 0),
	})

	emu.AddHook("", "FindExecutableA", &Hook{
		Parameters: []string{"a:lpFile", "a:lpDirectory", "a:lpResult"},
		Fn: func(emulator *WinEmulator, in *Instruction) bool {
			result := "C:\\WINDOWS\\system32\\LaunchWinApp.exe"
			emu.Uc.MemWrite(in.Args[2], append([]byte(result), 0))
			return SkipFunctionStdCall(true, 33)(emu, in)
		},
	})

	emu.AddHook("", "ShellExecuteExW", &Hook{
		Parameters: []string{"pExecInfo"},
		Fn:         shellExecuteEx,
	})
	emu.AddHook("", "ShellExecuteExA", &Hook{
		Parameters: []string{"pExecInfo"},
		Fn:         shellExecuteEx,
	})

	emu.AddHook("", "ShellExecuteW", &Hook{
		Parameters: []string{"hwnd", "w:lpOperation", "w:lpFile", "w:lpParameter", "w:lpDirectory", "nShowCmd"},
		Fn:         SkipFunctionStdCall(true, 33),
	})
	emu.AddHook("", "ShellExecuteA", &Hook{
		Parameters: []string{"hwnd", "a:lpOperation", "a:lpFile", "a:lpParameter", "a:lpDirectory", "nShowCmd"},
		Fn:         SkipFunctionStdCall(true, 33),
	})

}
