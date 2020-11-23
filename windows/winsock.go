package windows

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

func inet_ntoa(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(ip>>24), byte(ip>>16), byte(ip>>8),
		byte(ip))
}

func connect(emu *WinEmulator, in *Instruction) bool {
	type sockaddr_in struct {
		Sin_family uint16
		Sin_port   uint16
		Sin_addr   uint32
		Sin_zero   [8]byte
	}
	sockAddr := in.Args[1]
	sockRaw, err := emu.Uc.MemRead(sockAddr, uint64(binary.Size(sockaddr_in{})))
	if err != nil {
		return SkipFunctionStdCall(true, 0xFFFFFFFF)(emu, in)
	}
	s := sockaddr_in{}
	r := bytes.NewReader(sockRaw)
	err = binary.Read(r, binary.LittleEndian, &s)
	if err != nil {
		return SkipFunctionStdCall(true, 0xFFFFFFFF)(emu, in)
	}
	return SkipFunctionStdCall(true, 0)(emu, in)
}

func recv(emu *WinEmulator, in *Instruction) bool {
	return SkipFunctionStdCall(true, in.Args[2])(emu, in)
}

func WinsockHooks(emu *WinEmulator) {
	emu.AddHook("", "WSACleanup", &Hook{
		Fn: SkipFunctionStdCall(true, ERROR_SUCCESS),
	})

	emu.AddHook("", "WSAStartup", &Hook{
		Parameters: []string{"wVersionRequired", "lpWSADATA"},
		Fn:         SkipFunctionStdCall(true, ERROR_SUCCESS),
	})

	emu.AddHook("", "WSASocketA", &Hook{
		Parameters: []string{"af", "type", "protocol", "lpProtocolInfo", "g", "dwFlags"},
		Fn:         SkipFunctionStdCall(true, 0x1337),
	})

	emu.AddHook("", "connect", &Hook{
		Parameters: []string{"s", "name", "namelen"},
		Fn:         connect,
	})

	emu.AddHook("", "recv", &Hook{
		Parameters: []string{"s", "buf", "len", "flags"},
		Fn:         recv,
	})

	emu.AddHook("", "closesocket", &Hook{
		Parameters: []string{"s"},
		Fn:         SkipFunctionStdCall(true, 0),
	})
}
