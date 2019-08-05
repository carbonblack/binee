package windows

import "binee/util"
import uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"

func getLocaleInfo(emu *WinEmulator, in *Instruction) bool {
	lctype := in.Args[1]
	ptr := in.Args[2]

	// from constants.go
	locale := GetLocale(int(in.Args[0]))
	data := []byte(locale[int(lctype)])
	// null terminator
	data = append(data, byte(0))
	// write the new values into memory
	if emu.UcMode == uc.MODE_32 {
		util.StructWrite(emu.Uc, ptr, data)
	} else {
		util.StructWrite(emu.Uc, ptr, data)
	}
	return SkipFunctionStdCall(true, in.Args[3])(emu, in)
}

func WinnlsHooks(emu *WinEmulator) {
	emu.AddHook("", "GetLocaleInfoA", &Hook{
		Parameters: []string{"Locale", "LCType", "a:lpLCData", "cchData"},
		Fn:         getLocaleInfo,
	})
	emu.AddHook("", "GetLocaleInfoW", &Hook{
		Parameters: []string{"Locale", "LCType", "w:lpLCData", "cchData"},
		Fn:         getLocaleInfo,
	})
	emu.AddHook("", "GetThreadLocale", &Hook{
		Parameters: []string{},
		//Fn: func(emu *WinEmulator, in *Instruction) bool {
		//	var ret uint32
		//	ret = uint32(emu.Opts.CurrentLocale)
		//	ret |= uint32(emu.Opts.LocaleSortOrder) << 16
		//	return SkipFunctionStdCall(true, uint64(ret))(emu, in)
		//},
	})
	emu.AddHook("", "SetThreadUILanguage", &Hook{
		Parameters: []string{"langId"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			return SkipFunctionStdCall(true, in.Args[0])(emu, in)
		},
	})
}
