package windows

func Wow64apisetHooks(emu *WinEmulator) {
	emu.AddHook("", "IsWow64Process", &Hook{
		Parameters: []string{"hProcess", "Wow64Process"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			if emu.PtrSize == 4 {
				return SkipFunctionStdCall(true, 0x1)(emu, in)
			} else {
				return SkipFunctionStdCall(true, 0x0)(emu, in)
			}
		},
	})
}
