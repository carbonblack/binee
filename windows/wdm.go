package windows

import "binee/util"

func WdmHooks(emu *WinEmulator) {
	emu.AddHook("", "InterlockedExchange", &Hook{
		Parameters: []string{"Target", "Value"},
	})

	emu.AddHook("", "DbgPrint", &Hook{
		Parameters: []string{"a:format"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			formatStringAddr := util.GetStackEntryByIndex(emu.Uc, emu.UcMode, 1)
			formatString := util.ReadAscii(emu.Uc, formatStringAddr, 0)
			startVarArgsAddr := util.GetStackEntryByIndex(emu.Uc, emu.UcMode, 3)

			numFormatters := util.ParseFormatter(formatString)

			// This updates values and args
			in.VaArgsParse(startVarArgsAddr, len(numFormatters))

			// This updates parameters
			in.FmtToParameters(numFormatters)

			return SkipFunctionCdecl(true, STATUS_SUCCESS)(emu, in)
		},
	})
}
