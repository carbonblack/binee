package windows

import (
	"bytes"
	"encoding/binary"
	"github.com/unicorn-engine/unicorn/bindings/go/unicorn"
	"strconv"
	"time"

	"github.com/carbonblack/binee/util"
)

func sprintf(emu *WinEmulator, in *Instruction, wide bool) {
	var format string
	if wide {
		format = util.ReadWideChar(emu.Uc, in.Args[1], 0)
	} else {
		format = util.ReadASCII(emu.Uc, in.Args[1], 0)
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
	startAddr += 3 * emu.PtrSize
	in.VaArgsParse(startAddr, parameters)
	in.FmtToParameters(parameters)
}

//int swprintf(
//   wchar_t *buffer,
//   size_t count,
//   const wchar_t *format [,
//   argument]...
//);

func swprintf(emu *WinEmulator, in *Instruction) bool {
	format := util.ReadWideChar(emu.Uc, in.Args[1], 0)
	parameters := util.ParseFormatter(format)
	for i, v := range parameters {
		if v == "s" {
			parameters[i] = "S"
		}
	}
	var startAddr uint64
	//Get stack address
	if emu.PtrSize == 4 {
		startAddr, _ = emu.Uc.RegRead(unicorn.X86_REG_ESP)
	} else {
		startAddr, _ = emu.Uc.RegRead(unicorn.X86_REG_ESP)
	}
	//Jump 3 entries
	startAddr += 3 * emu.PtrSize
	in.VaArgsParse(startAddr, parameters)
	in.FmtToParameters(parameters)
	return true
}

func printf(emu *WinEmulator, in *Instruction) bool {
	wide := in.Hook.Name[0] == 'w'
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
	in.VaArgsParse(startAddr, parameters)
	in.FmtToParameters(parameters)
	return SkipFunctionCdecl(false, 0)(emu, in)
}
func fopen(emu *WinEmulator, in *Instruction) func(emu *WinEmulator, in *Instruction) bool {
	wide := in.Hook.Name[1] == 'w'
	var path string
	if wide {
		path = util.ReadWideChar(emu.Uc, in.Args[0], 0)
	} else {
		path = util.ReadASCII(emu.Uc, in.Args[0], 0)
	}

	if handle, err := emu.OpenFile(path, 0); err == nil {
		addr := emu.Heap.Malloc(256)
		emu.Handles[addr] = handle
		return SkipFunctionStdCall(true, addr)
	} else {
		return SkipFunctionStdCall(true, 0)
	}
}

func fseek(emu *WinEmulator, in *Instruction) func(emu *WinEmulator, in *Instruction) bool {
	addr := in.Args[0]
	offset := in.Args[1]
	origin := in.Args[2]
	handle := emu.Handles[addr]
	if handle == nil {
		return SkipFunctionStdCall(true, 0x1)
	}
	handle.Seek(int64(offset), int(origin))
	return SkipFunctionStdCall(true, 0x0)
}

func ftell(emu *WinEmulator, in *Instruction) func(emu *WinEmulator, in *Instruction) bool {
	addr := in.Args[0]
	handle := emu.Handles[addr]
	if handle == nil {
		return SkipFunctionStdCall(true, 0x0)
	}
	t := handle.Tell()
	return SkipFunctionStdCall(true, uint64(t))
}

func fclose(emu *WinEmulator, in *Instruction) func(emu *WinEmulator, in *Instruction) bool {
	addr := in.Args[0]
	handle := emu.Handles[addr]
	if handle == nil {
		return SkipFunctionStdCall(true, 0x0)
	}
	handle.Close()
	return SkipFunctionStdCall(true, 0x0)
}
func fcloseAll(emu *WinEmulator, in *Instruction) bool {
	numberClosed := 0
	for _, handle := range emu.Handles {
		if handle.File != nil {
			handle.Close()
			numberClosed += 1
		}
	}
	return SkipFunctionStdCall(true, uint64(numberClosed))(emu, in)
}
func fread(emu *WinEmulator, in *Instruction) func(emu *WinEmulator, in *Instruction) bool {
	bufAddr := in.Args[0]
	size := in.Args[1]
	count := in.Args[2]
	handleAddr := in.Args[3]
	handle := emu.Handles[handleAddr]
	if handle == nil {
		return SkipFunctionStdCall(true, 0x0)
	}
	if size == 0 || count == 0 {
		return SkipFunctionStdCall(true, 0x0)
	}
	out := make([]byte, size*count)
	n, _ := handle.Read(out)
	emu.Uc.MemWrite(bufAddr, out)
	return SkipFunctionStdCall(true, uint64(n))
}

func fwrite(emu *WinEmulator, in *Instruction) func(emu *WinEmulator, in *Instruction) bool {
	bufAddr := in.Args[0]
	size := in.Args[1]
	count := in.Args[2]
	handleAddr := in.Args[3]
	handle := emu.Handles[handleAddr]
	if handle == nil {
		return SkipFunctionCdecl(true, 0x0)
	}
	if size == 0 || count == 0 {
		return SkipFunctionCdecl(true, 0x0)
	}
	out, err := emu.Uc.MemRead(bufAddr, size*count)
	if err != nil {
		return SkipFunctionCdecl(true, uint64(0))
	}
	handle.Write(out)
	return SkipFunctionCdecl(true, uint64(len(out))/size)
}

func fputs(emu *WinEmulator, in *Instruction) func(emu *WinEmulator, in *Instruction) bool {
	bufAddr := in.Args[0]
	handleAddr := in.Args[1]
	handle := emu.Handles[handleAddr]
	if handle == nil {
		return SkipFunctionStdCall(true, 0x0)
	}
	out := util.ReadASCII(emu.Uc, bufAddr, 0)
	handle.Write([]byte(out))
	return SkipFunctionStdCall(true, uint64(len(out)))
}

func getenv(emu *WinEmulator, in *Instruction) bool {
	wide := in.Hook.Name[0:2] == "_w"
	var key string
	if wide {
		key = util.ReadWideChar(emu.Uc, in.Args[0], 0)
	} else {
		key = util.ReadASCII(emu.Uc, in.Args[0], 0)
	}

	var val string
	for _, data := range emu.Opts.Env {
		if data.Key == key {
			val = data.Value
			break
		}
	}

	if val != "" {
		buf := []byte(val)
		if wide {
			buf = append(buf, 0, 0)
		} else {
			buf = append(buf, 0)
		}
		addr := emu.Heap.Malloc(uint64(len(buf)))
		if err := emu.Uc.MemWrite(addr, buf); err == nil {
			return SkipFunctionCdecl(true, addr)(emu, in)
		}
	}
	// set last error to 0xcb
	return SkipFunctionCdecl(true, 0x0)(emu, in)
}

func UcrtBase32Hooks(emu *WinEmulator) {
	emu.AddHook("", "__acrt_iob_func", &Hook{Parameters: []string{}, NoLog: true})
	emu.AddHook("", "_controlfp", &Hook{
		Parameters: []string{"unNew", "unMask"},
		Fn:         SkipFunctionCdecl(true, 0),
	})

	emu.AddHook("", "__dllonexit", &Hook{Parameters: []string{"func", "pbegin", "pend"}})
	emu.AddHook("", "__stdio_common_vfprintf", &Hook{
		Parameters: []string{"options", "stream", "a:format64", "a:format32"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			fstring := in.vfprintfHelper(2)
			return SkipFunctionCdecl(true, uint64(len(fstring)))(emu, in)
		},
	})
	emu.AddHook("", "__stdio_common_vsprintf", &Hook{
		Parameters: []string{"options", "buffer", "_:", "a:format64", "a:foo32"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			fstring := in.vfprintfHelper(3)
			emu.Uc.MemWrite(in.Args[1], []byte(fstring))
			return SkipFunctionCdecl(true, uint64(len(fstring)))(emu, in)
		},
	})

	emu.AddHook("", "__stdio_common_vfwprintf", &Hook{
		Parameters: []string{"stream", "_:", "_:", "w:format"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			formatStringAddr := util.GetStackEntryByIndex(emu.Uc, emu.UcMode, 4)
			formatString := util.ReadWideChar(emu.Uc, formatStringAddr, 0)
			startVarArgsAddr := util.GetStackEntryByIndex(emu.Uc, emu.UcMode, 6)
			numFormatters := util.ParseFormatter(formatString)

			// This updates values and args
			in.VaArgsParse(startVarArgsAddr, numFormatters)
			//vfwprintf actually treats %s as wide string
			for i, v := range numFormatters {
				if v == "s" {
					numFormatters[i] = "S"
				}
			}
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
	emu.AddHook("", "_o__initialize_onexit_table", &Hook{
		Parameters: []string{"table"},
		Fn:         SkipFunctionCdecl(true, 0)})

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
		Parameters: []string{""},
		Fn:         SkipFunctionCdecl(true, emu.GlobalVariables.Fmode),
	})
	emu.AddHook("", "__p__commode", &Hook{
		Parameters: []string{""},
		Fn:         SkipFunctionCdecl(true, emu.GlobalVariables.Commode),
	})
	emu.AddHook("", "_Xtime_get_ticks", &Hook{
		Parameters: []string{"lpFileTime"},
	})
	emu.AddHook("", "__crtGetSystemTimePreciseAsFileTime", &Hook{
		Parameters: []string{"lpSystemTimeAsFileTime"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			s1 := time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC)
			s2 := time.Date(1801, 1, 1, 0, 0, 0, 0, time.UTC)
			s3 := time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)
			now := time.Now()
			d1 := s2.Sub(s1)
			d2 := s3.Sub(s2)
			d3 := now.Sub(s3)
			n := uint64(d1.Seconds() + d2.Seconds() + d3.Seconds())
			n *= 10000000
			low := uint32(n)
			high := uint32(n >> 32)
			fileTime := struct {
				Low  uint32
				High uint32
			}{
				low,
				high,
			}
			buf := new(bytes.Buffer)
			binary.Write(buf, binary.LittleEndian, &fileTime)
			emu.Uc.MemWrite(in.Args[0], buf.Bytes())
			return SkipFunctionStdCall(false, 0)(emu, in)

		},
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
	emu.AddHook("", "fopen", &Hook{
		Parameters: []string{"a:filename", "a:mode"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			return fopen(emu, in)(emu, in)
		},
	})
	emu.AddHook("", "_wfopen", &Hook{
		Parameters: []string{"w:filename", "w:mode"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			return fopen(emu, in)(emu, in)
		},
	})
	emu.AddHook("", "fseek", &Hook{
		Parameters: []string{"stream", "offset", "origin"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			return fseek(emu, in)(emu, in)
		},
	})
	emu.AddHook("", "ftell", &Hook{
		Parameters: []string{"stream"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			return ftell(emu, in)(emu, in)
		},
	})
	emu.AddHook("", "fclose", &Hook{
		Parameters: []string{"stream"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			return fclose(emu, in)(emu, in)
		},
	})
	emu.AddHook("", "_fcloseall", &Hook{
		Parameters: []string{""},
		Fn:         fcloseAll,
	})
	emu.AddHook("", "fread", &Hook{
		Parameters: []string{"buffer", "size", "count", "stream"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			return fread(emu, in)(emu, in)
		},
	})
	emu.AddHook("", "fwrite", &Hook{
		Parameters: []string{"buffer", "size", "count", "stream"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			return fwrite(emu, in)(emu, in)
		},
	})
	emu.AddHook("", "fputs", &Hook{
		Parameters: []string{"buffer", "stream"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			return fputs(emu, in)(emu, in)
		},
	})

	emu.AddHook("", "mbstowcs", &Hook{
		Parameters: []string{"w:wcstr", "a:mbstr", "count"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			dst := in.Args[0]
			src := in.Args[1]
			s := util.ReadASCII(emu.Uc, src, 0)
			w := util.ASCIIToWinWChar(s)
			emu.Uc.MemWrite(dst, w)
			return SkipFunctionStdCall(true, 0x0)(emu, in)
		},
	})

	emu.AddHook("", "memmove", &Hook{
		Parameters: []string{"dest", "src", "count"},
	})

	emu.AddHook("", "wcslen", &Hook{
		Parameters: []string{"w:str"},
	})

	emu.AddHook("", "wcslen", &Hook{
		Parameters: []string{"w:str"},
	})
	emu.AddHook("", "wcsncpy", &Hook{
		Parameters: []string{"strDest", "strSource", "count"},
	})

	emu.AddHook("", "printf", &Hook{
		Parameters: []string{"a:format"},
		Fn:         printf,
	})
	emu.AddHook("", "wprintf", &Hook{
		Parameters: []string{"w:format"},
		Fn:         printf,
	})
	emu.AddHook("", "wcsncpy_s", &Hook{
		Parameters: []string{"strDest", "numElements", "strSource", "count"},
	})

	emu.AddHook("", "rand", &Hook{
		Parameters: []string{},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			return SkipFunctionCdecl(true, 0x0)(emu, in)
		},
	})
	emu.AddHook("", "sprintf", &Hook{
		Parameters: []string{"buffer", "a:format"},
		Fn: func(emulator *WinEmulator, in *Instruction) bool {
			sprintf(emu, in, false)
			return true
		},
	})
	emu.AddHook("", "swprintf", &Hook{
		Parameters: []string{"buffer", "w:format"},
		Fn:         swprintf,
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
	emu.AddHook("", "putc", &Hook{
		Parameters: []string{"c:character", "stream"},
		Fn:         SkipFunctionCdecl(true, 1),
	})
	emu.AddHook("", "strncmp", &Hook{
		Parameters: []string{"a:string1", "a:string2", "size"},
	})
	emu.AddHook("", "_setmbcp", &Hook{Parameters: []string{"codepage"}}) //Fn:SkipFunctionCdecl(true,0),

	emu.AddHook("", "_onexit", &Hook{
		Parameters: []string{"function"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			return SkipFunctionCdecl(true, in.Args[0])(emu, in)
		},
	})
	emu.AddHook("", "getchar", &Hook{
		Fn: SkipFunctionCdecl(true, 0x13),
	})

	emu.AddHook("", "toupper", &Hook{
		Parameters: []string{"c:c"},
		NoLog:      true,
	})
	emu.AddHook("", "tolower", &Hook{
		Parameters: []string{"c:c"},
		NoLog:      true,
	})
	emu.AddHook("", "getenv", &Hook{
		Parameters: []string{"a:varname"},
		Fn:         getenv,
	})
	emu.AddHook("", "_wgetenv", &Hook{
		Parameters: []string{"a:varname"},
		Fn:         getenv,
	})
	emu.AddHook("", "_isleadbyte_l", &Hook{
		Parameters: []string{"c"},
		NoLog:      true,
	})

	emu.AddHook("", "atof", &Hook{
		Parameters: []string{"w:string"},
	})
}
