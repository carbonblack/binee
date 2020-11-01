package windows

import (
	"github.com/carbonblack/binee/util"
	"path/filepath"
)

func enumDeviceDrivers(emu *WinEmulator, in *Instruction) func(emu *WinEmulator, in *Instruction) bool {

	if emu.PtrSize == 4 {
		count := uint32(in.Args[1] / 4)
		numberOfDrivers := uint32(len(emu.Opts.Drivers))
		if count < numberOfDrivers {
			//Need more bytes
			util.PutPointer(emu.Uc, emu.PtrSize, in.Args[2], uint64(numberOfDrivers)*4)
			return SkipFunctionStdCall(true, 0) //Fail
		}
		index := in.Args[0]
		i := uint32(0)
		for val, _ := range emu.Opts.Drivers {
			if i == count {
				break
			}
			util.PutPointer(emu.Uc, emu.PtrSize, index, uint64(val))
			index += 4
		}

	}
	return SkipFunctionStdCall(true, 1)
}
func getDeviceDriverBaseName(emu *WinEmulator, in *Instruction) bool {
	ret := 0
	wide := in.Hook.Name[len(in.Hook.Name)-1] == 'W'
	if wide {
		address := in.Args[0]
		driverName := util.ASCIIToWinWChar(emu.Opts.Drivers[int(address)])
		maxSize := in.Args[2]
		ret = len(driverName)
		if int(maxSize+2) < ret {
			driverName = driverName[0 : maxSize-2]
			ret = int(maxSize - 2)
		}
		driverName = append(driverName, 0, 0)
		emu.Uc.MemWrite(in.Args[1], driverName)
	} else {
		address := in.Args[0]
		driverName := []byte(emu.Opts.Drivers[int(address)])
		maxSize := in.Args[2]
		ret = len(driverName)
		if int(maxSize-1) < ret {
			driverName = driverName[0 : maxSize-1]
			ret = int(maxSize)
		}
		driverName = append(driverName, 0)

		emu.Uc.MemWrite(in.Args[1], driverName)
	}
	return SkipFunctionStdCall(true, uint64(ret))(emu, in)
}
func PsapiHooks(emu *WinEmulator) {
	emu.AddHook("", "K32GetModuleInformation", &Hook{
		Parameters: []string{"hProcess", "hModule", "lpmodeinfo", "cb"},
		Fn:         SkipFunctionStdCall(true, 0x1337),
	})
	emu.AddHook("", "EnumDeviceDrivers", &Hook{
		Parameters: []string{"lpImageBase", "cb", "lpcbNeeded"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			return enumDeviceDrivers(emu, in)(emu, in)
		},
	})
	emu.AddHook("", "GetDeviceDriverBaseNameW", &Hook{
		Parameters: []string{"ImageBase", "lpBaseName", "nSize"},
		Fn:         getDeviceDriverBaseName,
	})
	emu.AddHook("", "GetModuleFileNameExW", &Hook{
		Parameters: []string{"hProcess", "hModule", "w:lpFilename", "nSize"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			wide := in.Hook.Name[len(in.Hook.Name)-1] == 'W'
			f := ""
			buffer := in.Args[2]
			handle, ok := emu.Handles[in.Args[0]]
			if !ok || handle.Process == nil {
				emu.setLastError(ERROR_INVALID_HANDLE)
				return SkipFunctionStdCall(true, 0)(emu, in)
			}
			if handle.Process.the32ProcessID == CURRENT_PROC_ID {
				if in.Args[1] == 0x0 {
					if wide {
						f = "C:\\Users\\" + emu.Opts.User + "\\" + filepath.Base(emu.Binary)
						emu.Uc.MemWrite(buffer, util.ASCIIToWinWChar(f))
					} else {
						f = "C:\\Users\\" + emu.Opts.User + "\\" + filepath.Base(emu.Binary)
						emu.Uc.MemWrite(buffer, []byte(f))
					}
				}
			}
			return SkipFunctionStdCall(true, uint64(len(f)+1))(emu, in)
		},
	})

}
