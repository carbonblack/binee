package windows

import "encoding/binary"

func deviceIOControl(emu *WinEmulator, in *Instruction) bool {
	code := in.Args[1]
	outputBuffer := in.Args[4]
	//This is a dirty patch to bypass antianalysis
	if code == 0x7405c { //This is checking for physical disk's size
		size := uint64(0xA00000000)
		buff := make([]byte, 8)
		binary.LittleEndian.PutUint64(buff, size)
		if err := emu.Uc.MemWrite(outputBuffer, buff); err != nil {
			return SkipFunctionStdCall(true, 0x0)(emu, in)
		}
	}
	return SkipFunctionStdCall(true, 0x1)(emu, in)
}

func IOapisetHooks(emu *WinEmulator) {
	emu.AddHook("", "DeviceIoControl", &Hook{
		Parameters: []string{"hDevice", "dwIoControlCode", "lpInBuffer", "nInBufferSize", "lpOutBuffer", "nOutBufferSize", "lpBytesReturned", "lpOverlapped"},
		Fn:         deviceIOControl,
	})
}
