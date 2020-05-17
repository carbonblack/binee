package windows

import (
	"github.com/unicorn-engine/unicorn/bindings/go/unicorn"
	"strconv"
	"time"

	"github.com/carbonblack/binee/util"
)

func sprintf(emu *WinEmulator, in *Instruction, wide bool) {
	var format string
	if wide {
		format = util.ReadWideChar(emu.Uc, in.Args[0], 0)
	} else {
		format = util.ReadASCII(emu.Uc, in.Args[0], 0)
	}
	parameters := util.ParseFormatter(format)
	var startAddr uint64
	//Get stack address
	if emu.PtrSize == 4 {
		startAddr, _ = emu.Uc.RegRead(unicorn.X86_REG_ESP)
	} else {
		startAddr, _ = emu.Uc.RegRead(unicorn.X86_REG_ESP)
	}
	//Jump 2 entries
	startAddr += 2 * emu.PtrSize
	in.VaArgsParse(startAddr, len(parameters))
	in.FmtToParameters(parameters)
}
func printf(emu *WinEmulator, in *Instruction) bool {
	format := util.ReadASCII(emu.Uc, in.Args[0], 0)
	parameters := util.ParseFormatter(format)
	var startAddr uint64
	//Get stack address
	if emu.PtrSize == 4 {
		startAddr, _ = emu.Uc.RegRead(unicorn.X86_REG_ESP)
	} else {
		startAddr, _ = emu.Uc.RegRead(unicorn.X86_REG_ESP)
	}
	//Jump 2 entries
	startAddr += 2 * emu.PtrSize
	in.VaArgsParse(startAddr, len(parameters))
	in.FmtToParameters(parameters)
	return SkipFunctionCdecl(false, 0)(emu, in)
}

func UcrtBase32Hooks(emu *WinEmulator) {
	emu.AddHook("", "__acrt_iob_func", &Hook{Parameters: []string{}})
	emu.AddHook("", "_controlfp", &Hook{
		Parameters: []string{"unNew", "unMask"},
		Fn:         SkipFunctionCdecl(true, 0),
	})

	emu.AddHook("", "__dllonexit", &Hook{Parameters: []string{"func", "pbegin", "pend"}})
	emu.AddHook("", "__stdio_common_vfprintf", &Hook{
		Parameters: []string{"stream", "_:", "_:", "a:format"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			formatStringAddr := util.GetStackEntryByIndex(emu.Uc, emu.UcMode, 4)
			formatString := util.ReadASCII(emu.Uc, formatStringAddr, 0)
			startVarArgsAddr := util.GetStackEntryByIndex(emu.Uc, emu.UcMode, 6)

			numFormatters := util.ParseFormatter(formatString)

			// This updates values and args
			in.VaArgsParse(startVarArgsAddr, len(numFormatters))

			// This updates parameters
			in.FmtToParameters(numFormatters)

			return SkipFunctionCdecl(false, 0)(emu, in)
		},
	})
	emu.AddHook("", "__p___argc", &Hook{
		Parameters: []string{},
		Fn:         SkipFunctionCdecl(true, emu.Argc),
	})
	emu.AddHook("", "__p___argv", &Hook{
		Parameters: []string{},
		Fn:         SkipFunctionCdecl(true, emu.Argv),
	})
	emu.AddHook("", "__setusermatherr", &Hook{Parameters: []string{"pf"}})
	emu.AddHook("", "__strncnt", &Hook{Parameters: []string{"str", "count"}})
	emu.AddHook("", "_amsg_exit", &Hook{
		Parameters: []string{"retcode"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			return false
		},
	})
	emu.AddHook("", "_calloc_base", &Hook{
		Parameters: []string{"num", "size"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			num := uint64(in.Args[0])
			size := uint64(in.Args[1])
			addr := emu.Heap.Malloc(num * size)
			//zero out the memory
			buf := make([]byte, num*size)
			emu.Uc.MemWrite(addr, buf)
			return SkipFunctionCdecl(true, addr)(emu, in)
		},
	})
	emu.AddHook("", "_cexit", &Hook{Parameters: []string{}})
	emu.AddHook("", "_c_exit", &Hook{Parameters: []string{}})
	emu.AddHook("", "_crt_atexit", &Hook{Parameters: []string{}, Fn: SkipFunctionStdCall(false, 0)})
	emu.AddHook("", "_CrtSetBreakAlloc", &Hook{
		Parameters: []string{},
		//Fn:         SkipFunctionCdecl(true, 0x0),
	})
	emu.AddHook("", "_CrtSetDbgBlockType", &Hook{
		Parameters: []string{},
		//Fn:         SkipFunctionCdecl(false, 0x0),
	})
	emu.AddHook("", "_free_base", &Hook{Parameters: []string{"memblock"}})
	emu.AddHook("", "_execute_onexit_table", &Hook{Parameters: []string{"table"}})
	emu.AddHook("", "_get_initial_narrow_environment", &Hook{Parameters: []string{}, Fn: SkipFunctionStdCall(false, 0)})
	emu.AddHook("", "_initialize_onexit_table", &Hook{Parameters: []string{"table"}})
	emu.AddHook("", "_invalid_parameter_noinfo", &Hook{Parameters: []string{}})
	emu.AddHook("", "_invalid_parameter_noinfo_noreturn", &Hook{Parameters: []string{}})
	emu.AddHook("", "_initterm_e", &Hook{Parameters: []string{"PVFV", "PVFV"}, Fn: SkipFunctionCdecl(true, 0)})
	emu.AddHook("", "_initterm", &Hook{Parameters: []string{"PVPV", "PVPV"}, Fn: SkipFunctionCdecl(false, 0)})
	emu.AddHook("", "_ismbblead", &Hook{
		Parameters: []string{"c"},
	})

	emu.AddHook("", "_malloc_base", &Hook{
		Parameters: []string{"size"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			addr := emu.Heap.Malloc(in.Args[0])
			return SkipFunctionCdecl(true, addr)(emu, in)
		},
	})

	emu.AddHook("", "_msize", &Hook{
		Parameters: []string{"memblock"},
		Fn:         SkipFunctionCdecl(true, 0x0),
	})
	emu.AddHook("", "_register_thread_local_exe_atexit_callback", &Hook{Parameters: []string{}})
	emu.AddHook("", "_set_app_type", &Hook{Parameters: []string{"appType"}})
	emu.AddHook("", "__set_app_type", &Hook{Parameters: []string{"appType"}})
	emu.AddHook("", "_set_fmode", &Hook{Parameters: []string{"mode"}})
	emu.AddHook("", "__p__fmode", &Hook{
		Parameters: []string{"mode"},
		Fn:         SkipFunctionCdecl(true, 0x4000),
	})
	emu.AddHook("", "__p__commode", &Hook{
		Parameters: []string{"mode"},
		Fn:         SkipFunctionCdecl(true, 0x4000),
	})
	emu.AddHook("", "atoi", &Hook{
		Parameters: []string{},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			if n, err := strconv.Atoi(util.ReadASCII(emu.Uc, in.Args[0], 20)); err != nil {
				return SkipFunctionStdCall(true, 0)(emu, in)
			} else {
				return SkipFunctionStdCall(true, uint64(n))(emu, in)
			}
		},
	})
	emu.AddHook("", "exit", &Hook{
		Parameters: []string{},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			return false
		},
	})
	emu.AddHook("", "realloc", &Hook{
		Parameters: []string{"memblock", "size"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			addr, _ := emu.Heap.ReAlloc(in.Args[0], in.Args[1])
			return SkipFunctionCdecl(true, addr)(emu, in)
		},
	})
	emu.AddHook("", "calloc", &Hook{
		Parameters: []string{"num", "size"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			num := uint64(in.Args[0])
			size := uint64(in.Args[1])
			addr := emu.Heap.Malloc(num * size)
			//zero out the memory
			buf := make([]byte, num*size)
			emu.Uc.MemWrite(addr, buf)
			return SkipFunctionCdecl(true, addr)(emu, in)
		},
	})
	emu.AddHook("", "wcslen", &Hook{
		Parameters: []string{"str"},
	})
	emu.AddHook("", "wcsncpy", &Hook{
		Parameters: []string{"strDest", "strSource", "count"},
	})

	emu.AddHook("", "printf", &Hook{
		Parameters: []string{"a:format"},
		Fn:         printf,
	})
	emu.AddHook("", "sprintf", &Hook{
		Parameters: []string{"buffer", "a:format"},
		Fn: func(emulator *WinEmulator, in *Instruction) bool {
			sprintf(emu, in, false)
			return true
		},
	})
	emu.AddHook("", "swprintf", &Hook{
		Parameters: []string{"buffer", "count", "w:format"},
		Fn: func(emulator *WinEmulator, in *Instruction) bool {
			sprintf(emu, in, true)
			return true
		},
	})

	emu.AddHook("", "strcat", &Hook{
		Parameters: []string{"a:string1", "a:string2"},
	})
	emu.AddHook("", "strcmp", &Hook{
		Parameters: []string{"a:string1", "a:string2"},
	})
	emu.AddHook("", "strchr", &Hook{
		Parameters: []string{"pszStart", "wMatch"},
	})
	emu.AddHook("", "srand", &Hook{
		Parameters: []string{"seed"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			emu.Seed = int(in.Args[0])
			return SkipFunctionCdecl(false, 0x0)(emu, in)
		},
	})
	emu.AddHook("", "_time32", &Hook{
		Parameters: []string{"destTime"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			curTime := uint32(time.Now().Unix())
			util.PutPointer(emu.Uc, emu.PtrSize, in.Args[0], uint64(curTime))
			return SkipFunctionCdecl(true, uint64(curTime))(emu, in)
		},
	})
	emu.AddHook("", "_time64", &Hook{
		Parameters: []string{"destTime"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			curTime := uint64(time.Now().Unix())
			util.PutPointer(emu.Uc, emu.PtrSize, in.Args[0], curTime)
			return SkipFunctionCdecl(true, curTime)(emu, in)
		},
	})

	emu.AddHook("", "puts", &Hook{
		Parameters: []string{"a:str"},
		Fn:         SkipFunctionCdecl(true, 0),
	})
	emu.AddHook("", "strncmp", &Hook{
		Parameters: []string{"a:string1", "a:string2", "size"},
	})
}
