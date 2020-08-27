package windows

import (
	"bytes"
	"encoding/binary"
	"math"
	"syscall"
)

func virtualAllocEx(emu *WinEmulator, in *Instruction) bool {
	hProcess := in.Args[0]
	baseAddr := in.Args[1]
	size := in.Args[2]
	if emu.PtrSize == 4 {
		hProcess = uint64(int32(hProcess))
	}
	if hProcess == math.MaxUint64 {
		addr, _ := emu.Heap.MMap(baseAddr, size)
		return SkipFunctionStdCall(true, addr)(emu, in)
	}
	return SkipFunctionStdCall(true, 0x1337)(emu, in)
}
func virtualAlloc(emu *WinEmulator, in *Instruction) bool {
	baseAddr := in.Args[0]
	size := in.Args[1]
	addr, _ := emu.Heap.MMap(baseAddr, size)
	return SkipFunctionStdCall(true, addr)(emu, in)
}
func virtualFree(emu *WinEmulator, in *Instruction) bool {
	start := in.Args[0]
	size := in.Args[1]
	var memType string
	switch in.Args[2] {
	case MEM_RELEASE:
		memType = "MEM_RELEASE"
		break
	case MEM_DECOMMIT:
		memType = "MEM_DECOMMIT"
		break
	case MEM_COALESCE_PLACEHOLDERS:
		memType = "MEM_COALESCE_PLACEHOLDERS"
		break
	case MEM_PRESERVE_PLACEHOLDER:
		memType = "MEM_PRESERVE_PLACEHOLDER"
		break
	}
	in.Hook.Values[2] = memType
	if size == 0 && emu.Heap.Free(start) == 1 {
		return SkipFunctionStdCall(true, 0)(emu, in)
	}
	return SkipFunctionStdCall(true, 0)(emu, in)
}

func writeProcessMemory(emu *WinEmulator, in *Instruction) bool {
	hProcess := in.Args[0]
	lpBaseAddress := in.Args[1]
	lpBuffer := in.Args[2]
	size := in.Args[3]
	bytesWritten := in.Args[4]
	//check if same process
	if emu.PtrSize == 4 {
		if hProcess == 0xFFFFFFFF {
			buffer, _ := emu.Uc.MemRead(lpBuffer, size)
			emu.Uc.MemWrite(lpBaseAddress, buffer)
		}
	} else {
		if hProcess == 0xFFFFFFFFFFFFFFFF {
			buffer, _ := emu.Uc.MemRead(lpBuffer, size)
			emu.Uc.MemWrite(lpBaseAddress, buffer)
		}
	}
	if _, ok := emu.Handles[hProcess]; !ok {
		emu.setLastError(ERROR_INVALID_HANDLE)
		return SkipFunctionStdCall(true, 0)(emu, in) //Failed
	}
	//Make sure the number of bytes written is correct.
	if emu.PtrSize == 4 {
		buf := make([]byte, 4)
		binary.LittleEndian.PutUint32(buf, uint32(size))
		emu.Uc.MemWrite(bytesWritten, buf)
	} else {
		buf := make([]byte, 8)
		binary.LittleEndian.PutUint64(buf, size)
		emu.Uc.MemWrite(bytesWritten, buf)
	}
	return SkipFunctionStdCall(true, 0x1)(emu, in)
}

func virtualQuery(emu *WinEmulator, in *Instruction) bool {
	extended := false
	var baseAddress uint64
	if in.Hook.Name[len(in.Hook.Name)-2:len(in.Hook.Name)] == "Ex" {
		extended = true
	}
	if extended {
		baseAddress = in.Args[1]
	} else {
		baseAddress = in.Args[0]
	}
	if emu.PtrSize == 4 {
		memInfo := struct {
			BaseAddress       uint32
			AllocationBase    uint32
			AllocationProtect uint32
			PartitionId       uint16
			RegionSize        uint16
			State             uint32
			Protect           uint32
			Type              uint32
		}{uint32(baseAddress),
			uint32(baseAddress),
			syscall.PAGE_READWRITE,
			0x1337,
			1024,
			MEM_COMMIT,
			syscall.PAGE_READWRITE,
			MEM_PRIVATE,
		}
		memInfoBuffer := new(bytes.Buffer)
		binary.Write(memInfoBuffer, binary.LittleEndian, &memInfo)
		emu.Uc.MemWrite(in.Args[2], memInfoBuffer.Bytes())
		sz := uint64(len(memInfoBuffer.Bytes()))
		return SkipFunctionStdCall(true, sz)(emu, in)
	}
	return SkipFunctionStdCall(true, 0)(emu, in)

}

func readProcessMemory(emu *WinEmulator, in *Instruction) bool {
	hProcess := in.Args[0]
	if _, ok := emu.Handles[hProcess]; !ok {
		emu.setLastError(ERROR_INVALID_HANDLE)
		return SkipFunctionStdCall(true, 0)(emu, in) //Failed
	}
	return SkipFunctionStdCall(true, 0x1337)(emu, in)
}
func MemoryApiHooks(emu *WinEmulator) {

	emu.AddHook("", "VirtualAlloc", &Hook{
		Parameters: []string{"lpAddress", "dwSize", "flAllocationType", "flProtect"},
		Fn:         virtualAlloc,
	})
	emu.AddHook("", "VirtualFree", &Hook{
		Parameters: []string{"lpAddress", "dwSize", "dwFreeType"},
		Fn:         virtualFree,
	})

	emu.AddHook("", "VirtualAllocEx", &Hook{
		Parameters: []string{"hProcess", "lpAddress", "dwSize", "flAllocationType", "flProtect"},
		Fn:         virtualAllocEx,
	})
	emu.AddHook("", "VirtualProtect", &Hook{
		Parameters: []string{"lpAddress", "dwSize", "flNewProtect", "lpflOldProtect"},
		Fn:         SkipFunctionStdCall(true, 0x1),
	})

	emu.AddHook("", "WriteProcessMemory", &Hook{
		Parameters: []string{"hProcess", "lpBaseAddress", "lpBuffer", "nSize", "lpNumberOfBytesWritten"},
		Fn:         writeProcessMemory,
	})
	emu.AddHook("", "MapViewOfFile", &Hook{
		Parameters: []string{"hFileMappingObject", "dwDesiredAccess", "dwFileOffsetHigh", "dwFileOffsetLow", "duNumberOfBytesToMap"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			addr := emu.Heap.Malloc(1024)
			return SkipFunctionStdCall(true, addr)(emu, in)
		},
	})

	emu.AddHook("", "GlobalAddAtomA", &Hook{
		Parameters: []string{"a:lpString"},
		Fn:         SkipFunctionStdCall(true, 0x2131),
	})

	emu.AddHook("", "ReadProcessMemory", &Hook{
		Parameters: []string{"hProcess", "lpBaseAddress", "lpBuffer", "nSize", "lpNumberOfBytesRead"},
		Fn:         readProcessMemory,
	})

	emu.AddHook("", "VirtualQuery", &Hook{
		Parameters: []string{"lpAddress", "lpBuffer", "dwLength"},
		Fn:         virtualQuery,
	})
	emu.AddHook("", "VirtualQueryEx", &Hook{
		Parameters: []string{"hProcess", "lpAddress", "lpBuffer", "dwLength"},
		Fn:         virtualQuery,
	})
}
