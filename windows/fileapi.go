package windows

import "github.com/carbonblack/binee/util"
import "encoding/binary"

//import "fmt"

func FileapiHooks(emu *WinEmulator) {
	emu.AddHook("", "CreateDirectoryA", &Hook{
		Parameters: []string{"a:lpPathName", "lpSecurityAttributes"},
		Fn:         SkipFunctionStdCall(true, 0x1),
	})
	emu.AddHook("", "DeleteFileA", &Hook{
		Parameters: []string{"a:lpFileName"},
		Fn:         SkipFunctionStdCall(true, 0x1),
	})
	emu.AddHook("", "DeleteFileW", &Hook{
		Parameters: []string{"a:lpFileName"},
		Fn:         SkipFunctionStdCall(true, 0x1),
	})
	emu.AddHook("", "FindClose", &Hook{
		Parameters: []string{"hFindFile"},
		Fn:         SkipFunctionStdCall(true, 0x1),
	})
	emu.AddHook("", "FindFirstFileA", &Hook{
		Parameters: []string{"a:lpFileName", "lpFindFileData"},
		Fn:         SkipFunctionStdCall(true, 0x1),
	})
	emu.AddHook("", "FlushFileBuffers", &Hook{
		Parameters: []string{"hFile"},
		Fn:         SkipFunctionStdCall(true, 0x1),
	})
	emu.AddHook("", "GetShortPathNameA", &Hook{
		Parameters: []string{"a:lpszLongPath", "a:lpszShortPath", "cchBuffer"},
		Fn:         SkipFunctionStdCall(true, 0x10),
	})
	emu.AddHook("", "GetFileAttributesA", &Hook{
		Parameters: []string{"a:lpFileName"},
		Fn:         SkipFunctionStdCall(true, 0x80),
	})
	emu.AddHook("", "GetFileAttributesW", &Hook{
		Parameters: []string{"w:lpFileName"},
		Fn:         SkipFunctionStdCall(true, 0x80),
	})
	emu.AddHook("", "GetFileSize", &Hook{
		Parameters: []string{"hFile", "lpFileSizeHigh"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			handle := emu.Handles[in.Args[0]]
			if handle != nil {
				return SkipFunctionStdCall(true, uint64(handle.Info.Size()))(emu, in)
			}
			return SkipFunctionStdCall(true, 0x0)(emu, in)
		},
	})
	emu.AddHook("", "GetFullPathNameA", &Hook{
		Parameters: []string{"a:lpFileName", "nBufferLength", "lpBuffer", "lpFilePart"},
		Fn:         SkipFunctionStdCall(true, 0x80),
	})
	emu.AddHook("", "GetFullPathNameW", &Hook{
		Parameters: []string{"w:lpFileName", "nBufferLength", "lpBuffer", "lpFilePart"},
		Fn:         SkipFunctionStdCall(true, 0x80),
	})

	emu.AddHook("", "GetTempFileNameA", &Hook{
		Parameters: []string{"a:lpPathName", "a:lpPrefixString", "uUnique", "lpTempFileName"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			s := []byte(util.RandomName(8))
			emu.Uc.MemWrite(in.Args[3], s)
			return SkipFunctionStdCall(true, uint64(len(s)))(emu, in)
		},
	})
	emu.AddHook("", "GetTempPathA", &Hook{
		Parameters: []string{"nBufferLength", "lpBuffer"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			dir := []byte("c:\\temp")
			emu.Uc.MemWrite(in.Args[1], dir)
			return SkipFunctionStdCall(true, uint64(len(dir)))(emu, in)
		},
	})
	emu.AddHook("", "GetTempPathW", &Hook{
		Parameters: []string{"nBufferLength", "lpBuffer"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			dir := util.AsciiToWinWChar("c:\\temp")
			emu.Uc.MemWrite(in.Args[1], dir)
			return SkipFunctionStdCall(true, uint64(len(dir)))(emu, in)
		},
	})
	emu.AddHook("", "ReadFile", &Hook{
		Parameters: []string{"hFile", "lpBuffer", "nNumberOfBytesToRead", "lpNumberOfBytesRead", "lpOverlapped"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			handle := emu.Handles[in.Args[0]]
			if handle != nil {
				buf := make([]byte, in.Args[2])
				num, err := handle.File.Read(buf)
				if err == nil {
					numbuf := make([]byte, 4)
					binary.LittleEndian.PutUint32(numbuf, uint32(num))
					emu.Uc.MemWrite(in.Args[1], buf)
					emu.Uc.MemWrite(in.Args[3], numbuf)
					return SkipFunctionStdCall(true, uint64(handle.Info.Size()))(emu, in)
				}
			}
			return SkipFunctionStdCall(true, 0x0)(emu, in)
		},
	})

	emu.AddHook("", "SetFilePointer", &Hook{
		Parameters: []string{"hFile", "lDistanceToMove", "lpDistanceToMoveHigh", "dwMoveMethod"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			handle := emu.Handles[in.Args[0]]
			if handle != nil {
				// if lpDistanceToMoveHigh is NULL, the distance to move is a 32-bit signed value
				var m int64
				if in.Args[2] == 0 {
					move := int32(in.Args[1])
					m = int64(move)
					// if lpDistanceToMoveHigh is not NULL, the distance to move is a 64-bit signed value
				} else {
					move := int64((in.Args[2] << 32) + in.Args[1])
					m = int64(move)
				}

				whence := int(in.Args[3])
				ret, _ := handle.File.Seek(m, whence)
				//if err != nil {
				//    return SkipFunctionStdCall(true,
				return SkipFunctionStdCall(true, uint64(ret))(emu, in)
			}

			return SkipFunctionStdCall(true, 0x0)(emu, in)

		},
		//Fn:         SkipFunctionStdCall(true, 0x80),
	})
}
