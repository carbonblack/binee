package windows

func Oleaut32Hooks(emu *WinEmulator) {
	emu.AddHook("", "VarCyCmpR8", &Hook{Parameters: []string{"cyLeft", "dblRight"}, Fn: SkipFunctionStdCall(true, 0x1)})
	emu.AddHook("", "VarCyMulI4", &Hook{Parameters: []string{"cyLeft", "lRight", "pcyResult"}})
	emu.AddHook("", "VariantClear", &Hook{Parameters: []string{"pvarg"}})

}
