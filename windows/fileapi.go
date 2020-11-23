package windows

import (
	"encoding/binary"
	"math"
	"path/filepath"
	"strings"

	"github.com/carbonblack/binee/util"
)

type FindFileHandle struct {
	NumberOfFiles uint64
	FileNames     []string
	Index         uint64
}
type FILETIME struct {
	DwLowDateTime  uint32
	DwHighDateTime uint32
}
type _WIN32_FIND_DATAA struct {
	DwFileAttributes   uint32
	FtCreationTime     FILETIME
	FtLastAccessTime   FILETIME
	FtLastWriteTime    FILETIME
	NFileSizeHigh      uint32
	NFileSizeLow       uint32
	dwReserved1        uint32
	dwReserved2        uint32
	CFileName          [260]byte
	CAlternateFileName [14]byte
	DwFileType         uint32
	DwCreatorType      uint32
	wFinderFlags       uint16
}

func findFirstFile(emu *WinEmulator, in *Instruction) bool {
	wide := in.Hook.Name[len(in.Hook.Name)-1] == 'W'
	fileName := ""
	if wide {
		fileName = util.ReadWideChar(emu.Uc, in.Args[0], 0)
	} else {
		fileName = util.ReadASCII(emu.Uc, in.Args[0], 0)
	}

	temp := strings.Replace(fileName, "c:", emu.Opts.Root, 1)
	temp = strings.Replace(temp, "C:", emu.Opts.Root, 1)
	temp = strings.Replace(temp, "\\", "/", -1)
	path := filepath.Clean(temp)
	matches, _ := filepath.Glob(path)
	fileNames := make([]string, len(matches))
	path, _ = filepath.Split(fileName)
	for i := range matches {
		_, foundFile := filepath.Split(matches[i])
		fileNames[i] = foundFile
	}
	findFileHandleStruct := &FindFileHandle{
		NumberOfFiles: uint64(len(matches)),
		FileNames:     fileNames,
		Index:         1,
	}
	findFileHandle := &Handle{
		Object: findFileHandleStruct,
	}

	var cFileName [260]byte
	copy(cFileName[0:259], fileNames[0])
	length := math.Min(float64(len(fileNames[0])), 259)
	cFileName[int(length)] = 0
	findData := _WIN32_FIND_DATAA{
		DwFileAttributes: 0x80, //Normal
		CFileName:        cFileName,
	}
	if err := util.StructWrite(emu.Uc, in.Args[1], findData); err != nil {
		return SkipFunctionStdCall(true, uint64(INVALID_HANDLE_32))(emu, in)
	}
	handleAddr := emu.Heap.Malloc(4)
	emu.Handles[handleAddr] = findFileHandle
	return SkipFunctionStdCall(true, handleAddr)(emu, in)
}

func findNextFile(emu *WinEmulator, in *Instruction) bool {
	handleVal := in.Args[0]
	handle, ok := emu.Handles[handleVal]
	if !ok {
		emu.setLastError(ERROR_INVALID_HANDLE)
		return SkipFunctionStdCall(true, 0)(emu, in)
	}
	var findFileHandle *FindFileHandle
	findFileHandle, ok = handle.Object.(*FindFileHandle)
	if !ok {
		emu.setLastError(ERROR_INVALID_HANDLE)
		return SkipFunctionStdCall(true, 0)(emu, in)
	}

	index := findFileHandle.Index
	if index == findFileHandle.NumberOfFiles {
		return SkipFunctionStdCall(true, 0x0)(emu, in)
	}
	fileName := findFileHandle.FileNames[index]
	findFileHandle.Index += 1

	var cFileName [260]byte
	copy(cFileName[0:259], fileName)
	length := math.Min(float64(len(fileName)), 259)
	cFileName[int(length)] = 0
	findData := _WIN32_FIND_DATAA{
		DwFileAttributes: 0x80, //Normal
		CFileName:        cFileName,
	}
	if err := util.StructWrite(emu.Uc, in.Args[1], findData); err != nil {
		return SkipFunctionStdCall(true, 0)(emu, in)
	}
	return SkipFunctionStdCall(true, 1)(emu, in)
}
func getVolumeInformation(emu *WinEmulator, in *Instruction, wide bool) func(emu *WinEmulator, in *Instruction) bool {
	/*The function depends on the given parameters to know what is requested,
	  nulled input means its not required */
	volumeName := emu.Opts.VolumeName
	volumeSerial := emu.Opts.VolumeSerialNumber
	volumeSystemName := emu.Opts.VolumeSystemName
	if wide {
		if in.Args[0] != 0 {
			//This might be used later to assume we have many volumes.
			//rootPathName=util.ReadWideChar(emu.Uc,in.Args[0],0)
		}
		if in.Args[1] != 0 { // Volume name is required.
			if len(volumeName) < int(in.Args[2]) { //Check volume name size
				volumeNameW := util.ASCIIToWinWChar(volumeName)
				err := emu.Uc.MemWrite(in.Args[1], volumeNameW)
				if err != nil {
					return SkipFunctionStdCall(true, 0)
				}
			}
		}
		if in.Args[3] != 0 { //Volume serial is required.
			buf := make([]byte, 4)
			binary.LittleEndian.PutUint32(buf, uint32(volumeSerial))
			err := emu.Uc.MemWrite(in.Args[3], buf)
			if err != nil {
				return SkipFunctionStdCall(true, 0)
			}
		}

		if in.Args[6] != 0 {
			if len(volumeSystemName) < int(in.Args[7]) { //Check volume name size
				volumeSystemNameW := util.ASCIIToWinWChar(volumeSystemName)
				err := emu.Uc.MemWrite(in.Args[6], volumeSystemNameW)
				if err != nil {
					return SkipFunctionStdCall(true, 0)
				}
			}
		}

	} else {

	}
	return SkipFunctionStdCall(true, 0)
}
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
		Fn:         findFirstFile,
	})

	emu.AddHook("", "FindNextFileA", &Hook{
		Parameters: []string{"hFindFile", "lpFindFileData"},
		Fn:         findNextFile,
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
			dir := util.ASCIIToWinWChar("c:\\temp")
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
	emu.AddHook("", "GetVolumeInformationW", &Hook{
		Parameters: []string{"w:lpRootPathName", "w:lpVolumeNameBuffer", "nVolumeNameSize", "lpVolumeSerialNumber", "lpMaximumComponentLength", "lpFileSystemFlags", "w:lpFileSystemNameBuffer", "nFileSystemNameSize"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			return getVolumeInformation(emu, in, true)(emu, in)
		},
	})

	emu.AddHook("", "SetFileAttributesA", &Hook{
		Parameters: []string{"a:lpFileName", "dwFileAttributes"},
		Fn:         SkipFunctionStdCall(true, 1),
	})

	emu.AddHook("", "CopyFileA", &Hook{
		Parameters: []string{"a:lpExistingFileName", "a:lpNewFileName", "bFailIfExists"},
		Fn:         SkipFunctionStdCall(true, 1),
	})

}
