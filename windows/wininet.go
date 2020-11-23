package windows

import (
	"encoding/binary"
	"fmt"
	"github.com/carbonblack/binee/util"
)

func internetReadFile(emu *WinEmulator, in *Instruction) bool {
	numberOfBytes := in.Args[2]
	if numberOfBytes < 0 {
		return SkipFunctionStdCall(true, 0)(emu, in)
	}
	pNumberOfBytesRead := in.Args[3]
	readBuffer := in.Args[1]
	randomData := util.RandomName(int(numberOfBytes))
	if err := emu.Uc.MemWrite(readBuffer, []byte(randomData)); err != nil {
		fmt.Errorf("InternetReadFile read address(%x) pointer is not valid", readBuffer)
		return SkipFunctionStdCall(true, 0)(emu, in)
	}
	var buf []byte
	if emu.PtrSize == 4 {
		buf = make([]byte, 4)
		binary.LittleEndian.PutUint32(buf, uint32(numberOfBytes))
	} else {
		buf = make([]byte, 8)
		binary.LittleEndian.PutUint64(buf, numberOfBytes)
	}
	if err := emu.Uc.MemWrite(pNumberOfBytesRead, buf); err != nil {
		fmt.Errorf("lpdwNumberOfBytesRead(%x) is invalid", pNumberOfBytesRead)
		return SkipFunctionStdCall(true, 0)(emu, in)
	}

	return SkipFunctionStdCall(true, 0x1)(emu, in)
}
func WininetHooks(emu *WinEmulator) {
	emu.AddHook("", "InternetOpenA", &Hook{
		Parameters: []string{"a:lpszAgent", "dwAccessType", "a:lpszProxy", "a:lpszProxyBypass", "dwFlags"},
		Fn:         SkipFunctionStdCall(true, 0x1337),
	})
	emu.AddHook("", "InternetOpenW", &Hook{
		Parameters: []string{"w:lpszAgent", "dwAccessType", "w:lpszProxy", "w:lpszProxyBypass", "dwFlags"},
		Fn:         SkipFunctionStdCall(true, 0x1337),
	})

	emu.AddHook("", "InternetOpenUrlA", &Hook{
		Parameters: []string{"hInternet", "a:lpszUrl", "a:lpszHeaders", "dwHeadersLength", "dwFlags", "dwContext"},
		Fn:         SkipFunctionStdCall(true, 0x1337),
	})
	emu.AddHook("", "InternetOpenUrlW", &Hook{
		Parameters: []string{"hInternet", "w:lpszUrl", "w:lpszHeaders", "dwHeadersLength", "dwFlags", "dwContext"},
		Fn:         SkipFunctionStdCall(true, 0x1337),
	})
	emu.AddHook("", "InternetCloseHandle", &Hook{
		Parameters: []string{"hInternet"},
		Fn:         SkipFunctionStdCall(true, 0x1),
	})

	emu.AddHook("", "InternetReadFile", &Hook{
		Parameters: []string{"hFile", "lpBuffer", "dwNumberOfBytesToRead", "lpdwNumberOfBytesRead"},
		Fn:         internetReadFile,
	})

}
