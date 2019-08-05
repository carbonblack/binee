package windows

func Objbase(emu *WinEmulator) {
	emu.AddHook("", "CoInitialize", &Hook{
		Parameters: []string{"pvReserved"},
		Fn:         SkipFunctionStdCall(true, 0x0),
	})
	emu.AddHook("", "CoInitializeEx", &Hook{
		Parameters: []string{"pvReserved", "dwCoInit"},
		Fn:         SkipFunctionStdCall(true, 0x0),
	})
	emu.AddHook("", "CreateFileMoniker", &Hook{
		Parameters: []string{"w:lpszPathName", "ppmk"},
		Fn:         SkipFunctionStdCall(true, 0x0),
	})
}
