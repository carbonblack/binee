package windows

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"golang.org/x/arch/x86/x86asm"

	"github.com/carbonblack/binee/util"

	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
)

func (emu *WinEmulator) LoadHooks() {
	KernelbaseHooks(emu)
	UcrtBase32Hooks(emu)
	PowrProf(emu)
	ComctlHooks(emu)
	AdvApi32Hooks(emu)
	OleHooks(emu)
	Ole2Hooks(emu)
	Oleaut32Hooks(emu)
	User32Hooks(emu)
	VcRuntimeHooks(emu)
	Comdlg32Hooks(emu)
	NtdllHooks(emu)
	ShellapiHooks(emu)
	WinbaseHooks(emu)
	LibloaderapiHooks(emu)
	WinuserHooks(emu)
	FileapiHooks(emu)
	HeapapiHooks(emu)
	OledlgHooks(emu)
	SyncapiHooks(emu)
	WinregHooks(emu)
	Objbase(emu)
	Sysinfoapi(emu)
	LibloaderapiHooks(emu)
	EvntprovHooks(emu)
	ProcessthreadsapiHooks(emu)
	MmapiHooks(emu)
	WinnlsHooks(emu)
	Wow64apisetHooks(emu)
	WdmHooks(emu)
	UtilapiHooks(emu)
	ShlobjCoreHooks(emu)
	MemoryApiHooks(emu)
	ToolHelpHooks(emu)
	Internal(emu)
	ShlwapiHooks(emu)
	Processenv(emu)
	Ktmw32Hooks(emu)
	PsapiHooks(emu)
	ConsoleApi(emu)
}
func (emu *WinEmulator) SetupHooks() error {
	emu.Uc.HookAdd(uc.HOOK_CODE, HookCode(emu), 1, 0)
	emu.Uc.HookAdd(uc.HOOK_MEM_WRITE_PROT|
		uc.HOOK_MEM_READ_PROT|
		uc.HOOK_MEM_FETCH_PROT|
		uc.HOOK_MEM_UNMAPPED|
		uc.HOOK_MEM_FETCH_UNMAPPED|
		uc.HOOK_MEM_READ_UNMAPPED|
		uc.HOOK_MEM_WRITE_UNMAPPED|
		uc.HOOK_MEM_INVALID|
		uc.HOOK_MEM_READ_INVALID|
		uc.HOOK_MEM_WRITE_INVALID|
		uc.HOOK_MEM_FETCH_INVALID, HookInvalid(emu), 1, 0)
	emu.Uc.HookAdd(uc.HOOK_INTR, HookInterupt(emu), 1, 0)

	emu.LoadHooks()
	return nil
}

// Start will begin emulation at the entry point and continue until error or
// until the end of execution.
func (emu *WinEmulator) Start() error {
	emu.SetupHooks()

	emu.Uc.Start(emu.EntryPoint, 0x0)
	for i, _ := range emu.FactFactory.Facts {
		fmt.Println(i)
	}
	return nil
}

func HookCode(emu *WinEmulator) func(mu uc.Unicorn, addr uint64, size uint32) {
	return func(mu uc.Unicorn, addr uint64, size uint32) {
		emu.Ticks++

		// capture next address, if cur address is a function call, next address is the ret address
		instruction := emu.BuildInstruction(addr, size)

		doContinue := instruction.Hook.Fn(emu, instruction)

		var returns uint64
		if emu.UcMode == uc.MODE_32 {
			returns, _ = emu.Uc.RegRead(uc.X86_REG_EAX)
		} else {
			returns, _ = emu.Uc.RegRead(uc.X86_REG_RAX)
		}

		instruction.Hook.Return = returns
		if !instruction.Hook.NoLog {

			if emu.logType == LogTypeJSON {
				if buf, err := json.Marshal(instruction); err == nil {
					if instruction.Hook.Implemented == true {
						fmt.Println(string(buf))
					}
				} else {
					fmt.Printf("{\"error\":\"%s\"},", err)
				}
			} else if emu.logType == LogTypeSlice {
				if instruction.Hook.Implemented {
					emu.InstructionLog = append(emu.InstructionLog, instruction.Log())
				}
			} else {
				if emu.Verbosity == 2 {
					fmt.Println("---")
					fmt.Println(emu.CPU.ReadRegisters())
					emu.CPU.PrintStack(10)
					fmt.Println(instruction.StringHook())
					fmt.Println(instruction)
				} else if emu.Verbosity == 1 {
					if s := instruction.StringHook(); s != "" {
						fmt.Println(s)
					} else {
						fmt.Println(instruction)
					}
				} else {
					if instruction.Hook.Implemented == true {
						fmt.Println(instruction.StringHook())
					}
				}

			}
		}
		addFact(instruction, emu)
		if doContinue == false {
			mu.Stop()
		}

		if emu.Ticks%10 == 0 || emu.Scheduler.curThread.Status != 0 {
			emu.Scheduler.DoSchedule()
		}

		// check that the emulation only emulates n ticks. If 0, continue
		if emu.maxTicks > 0 && emu.Ticks > emu.maxTicks {
			mu.Stop()
		}
	}
}

func HookInvalid(emu *WinEmulator) func(mu uc.Unicorn, access int, addr uint64, size int, value int64) bool {
	return func(mu uc.Unicorn, access int, addr uint64, size int, value int64) bool {
		switch access {
		case uc.MEM_WRITE, uc.MEM_WRITE_UNMAPPED, uc.MEM_WRITE_PROT:
			fmt.Fprintf(os.Stderr, "Invalid Write: address = 0x%x, size = 0x%x, value = 0x%x\n", addr, size, value)
		case uc.MEM_READ, uc.MEM_READ_UNMAPPED, uc.MEM_READ_PROT:
			fmt.Fprintf(os.Stderr, "Invalid Read: address = 0x%x, size = 0x%x, value = 0x%x\n", addr, size, value)
		case uc.MEM_FETCH, uc.MEM_FETCH_UNMAPPED, uc.MEM_FETCH_PROT:
			fmt.Fprintf(os.Stderr, "Invalid Fetch: addresss = 0x%x, size = 0x%x, value = 0x%x\n", addr, size, value)
		default:
			fmt.Fprintf(os.Stderr, "unknown memory error: address = 0x%x, size = 0x%x, value = 0x%x\n", addr, size, value)
		}
		return true
	}
}

func HookInterupt(emu *WinEmulator) func(mu uc.Unicorn, intnum uint32) {
	return func(mu uc.Unicorn, intnum uint32) {
		emu.Ticks += 1
		var rip uint64
		var reg int
		if emu.UcMode == uc.MODE_32 {
			rip, _ = mu.RegRead(uc.X86_REG_EIP)
			reg = uc.X86_REG_EIP
		} else {
			rip, _ = mu.RegRead(uc.X86_REG_RIP)
			reg = uc.X86_REG_RIP
		}
		rip += 2

		switch intnum {
		case 0x29:
			mu.RegWrite(reg, rip)
		default:
			fmt.Fprintln(os.Stderr, "interupt", intnum)
		}
	}
}

type Hook struct {
	Name        string
	Parameters  []string
	Fn          func(*WinEmulator, *Instruction) bool
	Implemented bool
	Values      []interface{}
	Return      uint64
	HookStatus  string
	Lib         string
	NoLog       bool
}

type Instruction struct {
	Addr     uint64
	Size     uint32
	Args     []uint64
	Stack    []byte
	Hook     *Hook
	emu      *WinEmulator
	ThreadID int
}

// InstructionLog is the exported struct detailing a single instruction. Useful
// for programmatic access to the emulated output
type InstructionLog struct {
	Tid        int           `json:"tid"`
	Addr       uint64        `json:"addr"`
	Size       uint32        `json:"size"`
	Opcode     string        `json:"opcode"`
	Lib        string        `json:"lib,omitempty"`
	Fn         string        `json:"fn,omitempty"`
	Parameters []string      `json:"parameters,omitempty"`
	Values     []interface{} `json:"values,omitempty"`
	Return     uint64        `json:"return,omitempty"`
}

// Log will output a anonymous struct that represents the instruction JSON form
func (i *Instruction) Log() *InstructionLog {
	return &InstructionLog{
		Tid:        i.ThreadID,
		Addr:       i.Addr,
		Size:       i.Size,
		Opcode:     i.Disassemble(),
		Lib:        i.Hook.Lib,
		Fn:         i.Hook.Name,
		Parameters: i.Hook.Parameters,
		Values:     i.Hook.Values,
		Return:     i.Hook.Return,
	}
}

func (i *Instruction) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		Tid        int           `json:"tid"`
		Addr       uint64        `json:"addr"`
		Size       uint32        `json:"size"`
		Opcode     string        `json:"opcode"`
		Lib        string        `json:"lib,omitempty"`
		Fn         string        `json:"fn,omitempty"`
		Parameters []string      `json:"parameters,omitempty"`
		Values     []interface{} `json:"values,omitempty"`
		Return     uint64        `json:"return,omitempty"`
	}{
		Tid:        i.ThreadID,
		Addr:       i.Addr,
		Size:       i.Size,
		Opcode:     i.Disassemble(),
		Lib:        i.Hook.Lib,
		Fn:         i.Hook.Name,
		Parameters: i.Hook.Parameters,
		Values:     i.Hook.Values,
		Return:     i.Hook.Return,
	})
}

func (self *Instruction) Address() string {
	if self.emu.UcMode == uc.MODE_32 {
		return fmt.Sprintf("0x%08x", self.Addr)
	} else {
		return fmt.Sprintf("0x%016x", self.Addr)
	}
}

func (self *Instruction) Disassemble() string {
	buf, _ := self.emu.Uc.MemRead(self.Addr, uint64(self.Size))
	mode := int(8 * self.emu.PtrSize)
	if inst, err := x86asm.Decode(buf, mode); err == nil {
		return strings.ToLower(inst.String())
	}
	return ""
}

func (self *Instruction) ParseValues() {

	for i := 0; i < len(self.Args); i++ {

		if len(self.Hook.Parameters[i]) < 2 {
			self.Hook.Values[i] = self.Args[i]
			continue
		}

		switch self.Hook.Parameters[i][0:2] {
		case "_:":
			self.Hook.Values[i] = ""
		case "w:":
			s := util.ReadWideChar(self.emu.Uc, self.Args[i], 0)
			self.Hook.Values[i] = strings.TrimRight(s, "\u0000")
		case "a:":
			s := util.ReadASCII(self.emu.Uc, self.Args[i], 0)
			self.Hook.Values[i] = strings.TrimRight(s, "\x00")
		case "v:":
			continue
		case "s:":
			continue
		default:
			self.Hook.Values[i] = self.Args[i]
		}
	}
}

// StringInstruction will print the instructino disassembly of the current EIP
// position
func (i *Instruction) String() string {
	return fmt.Sprintf("[%d] %s: %s", i.ThreadID, i.Address(), i.Disassemble())
}

// StringHook will print the hook string value if a hook is implemented,
// otherwise empty string
func (i *Instruction) StringHook() string {
	if i.Hook.Implemented == false {
		return ""
	}

	ret := ""
	ret += fmt.Sprintf("[%d] %s: %s %s(", i.ThreadID, i.Address(), i.Hook.HookStatus, i.Hook.Name)
	for j := range i.Args {

		if len(i.Hook.Parameters[j]) < 2 {
			ret += fmt.Sprintf("%s = 0x%x", i.Hook.Parameters[j], i.Args[j])
			continue
		}

		switch i.Hook.Parameters[j][0:2] {
		case "_:":
			continue
		case "w:":
			s := util.ReadWideChar(i.emu.Uc, i.Args[j], 0)
			ret += fmt.Sprintf("%s = '%s'", i.Hook.Parameters[j][2:], s)
		case "a:":
			s := util.ReadASCII(i.emu.Uc, i.Args[j], 0)
			ret += fmt.Sprintf("%s = '%s'", i.Hook.Parameters[j][2:], s)
		case "v:":
			ret += fmt.Sprintf("%s = %+v", i.Hook.Parameters[j][2:], i.Hook.Values[j])
		case "s:":
			ret += fmt.Sprintf("%s = '%s'", i.Hook.Parameters[j][2:], i.Hook.Values[j])
		case "d:":
			ret += fmt.Sprintf("%s = %d", i.Hook.Parameters[j][2:], uint32(i.Hook.Values[j].(uint64)))
		case "l:":
			ret += fmt.Sprintf("%s = %d", i.Hook.Parameters[j][2:], i.Hook.Values[j])
		default:
			ret += fmt.Sprintf("%s = 0x%x", i.Hook.Parameters[j], i.Args[j])
		}

		if j != len(i.Args)-1 {
			ret += fmt.Sprintf(", ")
		}
	}
	ret += fmt.Sprintf(") = 0x%x", i.Hook.Return)

	return ret
}

func (in *Instruction) vfprintfHelper(offset int) string {
	var formatStringAddr uint64
	var vaArgsAddr uint64
	if in.emu.PtrSize == 4 {
		formatStringAddr = in.Args[offset+1]
		vaArgsAddr = util.GetStackEntryByIndex(in.emu.Uc, in.emu.UcMode, offset+4)
	} else {
		formatStringAddr = in.Args[offset]
		vaArgsAddr = util.GetStackEntryByIndex(in.emu.Uc, in.emu.UcMode, offset+3)
	}

	// grab the format string
	formatString := util.ReadASCII(in.emu.Uc, formatStringAddr, 0)

	// parse the formatters (into a slice)
	formatters := util.ParseFormatter(formatString)

	// This updates values and args
	args := in.VaArgsParse(vaArgsAddr, formatters)

	// evaluate the formatted string
	// important because the printf functions need the length of the final string
	// but %p needs to be replaced by %x to evaluate properly
	temp := strings.ReplaceAll(formatString, "%p", "%x")
	fstring := fmt.Sprintf(temp, args...)

	// This updates parameters
	in.FmtToParameters(formatters)
	return fstring
}

// VaArgsParse will take address to first value, number of values
// and populate instruction args and hook values
func (self *Instruction) VaArgsParse(addr uint64, formatters []string) []interface{} {
	n := len(formatters)
	res := make([]interface{}, n)

	if self.emu.UcMode == uc.MODE_32 {
		for i := 0; i < n; i++ {
			// Pull a pointer off the stack
			ptr, _ := self.emu.Uc.MemRead(addr+uint64(i)*self.emu.PtrSize, self.emu.PtrSize)

			// Convert to a uint64
			ptr_num := uint64(binary.LittleEndian.Uint32(ptr))

			self.Hook.Values = append(self.Hook.Values, ptr_num)
			self.Args = append(self.Args, ptr_num)

			f := formatters[i]
			if f == "s" {
				res[i] = util.ReadASCII(self.emu.Uc, ptr_num, 0)
			} else {
				res[i] = ptr_num
			}
		}
	} else {
		for i := 0; i < n; i++ {
			// Pull a pointer off the stack
			ptr, _ := self.emu.Uc.MemRead(addr+uint64(i)*self.emu.PtrSize, self.emu.PtrSize)

			// Convert to a uint64
			ptr_num := binary.LittleEndian.Uint64(ptr)

			self.Hook.Values = append(self.Hook.Values, ptr_num)
			self.Args = append(self.Args, ptr_num)

			f := formatters[i]
			if f == "d" {
				res[i] = ptr_num & 0xffffffff
			} else if f == "s" {
				res[i] = util.ReadASCII(self.emu.Uc, ptr_num, 0)
			} else {
				res[i] = ptr_num
			}
		}
	}

	return res
}

// FmtToParameters will take formatters and append to self.Hook.Parameters
func (self *Instruction) FmtToParameters(fmts []string) {
	for i, f_type := range fmts {
		param := ""
		switch f_type {
		case "s":
			param = fmt.Sprintf("a:p%d", i)

		case "S":
			param = fmt.Sprintf("w:p%d", i)
		case "d":
			param = fmt.Sprintf("d:p%d", i)
		case "l":
			param = fmt.Sprintf("l:p%d", i)
		default:
			param = fmt.Sprintf("p%d", i)
		}
		self.Hook.Parameters = append(self.Hook.Parameters, param)
	}
}

func (emu *WinEmulator) CaptureParameters(n int) []uint64 {
	ret := make([]uint64, 0, 10)
	if n == 0 {
		return ret
	}

	if emu.UcMode == uc.MODE_32 {
		esp, _ := emu.Uc.RegRead(uc.X86_REG_ESP)
		for i := 1; i < n+1; i++ {
			val, _ := emu.Uc.MemRead(esp+uint64(i*4), 4)
			ret = append(ret, uint64(binary.LittleEndian.Uint32(val)))
		}
		return ret
	} else {
		rsp, _ := emu.Uc.RegRead(uc.X86_REG_RSP)
		for i := 1; i < n+1; i++ {
			var val uint64
			switch i {
			case 1:
				val, _ = emu.Uc.RegRead(uc.X86_REG_RCX)
				break
			case 2:
				val, _ = emu.Uc.RegRead(uc.X86_REG_RDX)
				break
			case 3:
				val, _ = emu.Uc.RegRead(uc.X86_REG_R8)
				break
			case 4:
				val, _ = emu.Uc.RegRead(uc.X86_REG_R9)
				break
			default:
				buf, _ := emu.Uc.MemRead(rsp+uint64((i-4)*8), 8)
				ret = append(ret, binary.LittleEndian.Uint64(buf))
				continue
			}
			ret = append(ret, val)
		}
	}

	return ret
}

func NopHook() *Hook {
	return &Hook{"",
		make([]string, 0, 0),
		func(_ *WinEmulator, _ *Instruction) bool { return true },
		false,
		make([]interface{}, 0, 0),
		0x0,
		"",
		"",
		false,
	}
}

func (emu *WinEmulator) BuildInstruction(addr uint64, size uint32) *Instruction {
	instruction := Instruction{addr, size, make([]uint64, 0, 0), nil, nil, emu, emu.Scheduler.CurThreadId()}
	instruction.Hook = NopHook()

	if emu.UcMode == uc.MODE_32 {
		esp, _ := emu.Uc.RegRead(uc.X86_REG_ESP)
		instruction.Stack, _ = emu.Uc.MemRead(esp, 40)
	} else {
		rsp, _ := emu.Uc.RegRead(uc.X86_REG_RSP)
		instruction.Stack, _ = emu.Uc.MemRead(rsp, 80)
	}

	name, function, hook := emu.GetHook(addr)
	if name != "" && function != "" {
		if hook != nil {
			// check if the current address is in some mapped library
			l := len(hook.Parameters)
			// sometimes these values can change depending on when/where the function is called or how many times
			instruction.Hook.Parameters = make([]string, l)
			copy(instruction.Hook.Parameters[:], hook.Parameters[:])

			instruction.Hook.Values = make([]interface{}, l)
			copy(instruction.Hook.Values[:], hook.Values[:])

			instruction.Hook.Lib = name

			// get parameters of the hooked function and call function implementation
			instruction.Args = emu.CaptureParameters(l)

			// execute hooked implementation if it exists
			if hook.Fn == nil {
				hook.HookStatus = "P"
				instruction.Hook.Fn = func(_ *WinEmulator, _ *Instruction) bool { return true }
				//hook.Fn = func(_ *WinEmulator, _ *Instruction) bool { return true }
			} else {
				hook.HookStatus = "F"
				instruction.Hook.Fn = hook.Fn
			}
			instruction.Hook.HookStatus = hook.HookStatus

			if emu.ShowDll {
				instruction.Hook.Name = name + ":" + function
			} else {
				instruction.Hook.Name = function
			}
			instruction.ParseValues()
			instruction.Hook.NoLog = hook.NoLog
		} else {
			// function does not have a hook defined, add name to NOP hook
			instruction.Hook = NopHook()
			if emu.ShowDll {
				instruction.Hook.Name = "**" + name + ":" + function + "**"
			} else {
				instruction.Hook.Name = "**" + function + "**"
			}
		}

		instruction.Hook.Implemented = true
	}

	return &instruction

}

// SkipFunctionAdj will step over a function by adjusting the stack
// accordingly. The set_return and ret parameters will set the RAX/EAX values
// if nessesary, and the stackadj will adjust the stack properly. Stackadj is
// used in the appropriate calling convention.
func SkipFunctionCdecl(set_return bool, ret uint64) func(emu *WinEmulator, instruction *Instruction) bool {
	return func(emu *WinEmulator, instruction *Instruction) bool {

		if set_return == true {
			if emu.UcMode == uc.MODE_32 {
				emu.Uc.RegWrite(uc.X86_REG_EAX, ret)
			} else {
				emu.Uc.RegWrite(uc.X86_REG_RAX, ret)
			}
		}

		if emu.UcMode == uc.MODE_32 {
			// get value of esp, should be the return address
			esp, _ := emu.Uc.RegRead(uc.X86_REG_ESP)
			// get the return address from CALL that was pushed onto the stack
			eip, _ := emu.Uc.MemRead(uint64(esp), 4)
			//write RET address into EIP
			emu.Uc.RegWrite(uc.X86_REG_EIP, uint64(binary.LittleEndian.Uint32(eip)))
			// reset stack by popping off RET
			esp = esp + 4
			emu.Uc.RegWrite(uc.X86_REG_ESP, esp)
		} else {
			// get value of esp, should be the return address
			rsp, _ := emu.Uc.RegRead(uc.X86_REG_RSP)
			// get the return address from CALL that was pushed onto the stack
			rip, _ := emu.Uc.MemRead(rsp, 8)
			//write RET address into EIP
			emu.Uc.RegWrite(uc.X86_REG_RIP, binary.LittleEndian.Uint64(rip))
			// reset stack by popping off RET
			rsp = rsp + 8
			emu.Uc.RegWrite(uc.X86_REG_RSP, rsp)
		}

		return true
	}
}

func SkipFunctionStdCall(set_return bool, ret uint64) func(emu *WinEmulator, instruction *Instruction) bool {
	return func(emu *WinEmulator, instruction *Instruction) bool {

		if set_return == true {
			if emu.UcMode == uc.MODE_32 {
				emu.Uc.RegWrite(uc.X86_REG_EAX, ret)
			} else {
				emu.Uc.RegWrite(uc.X86_REG_RAX, ret)
			}
		}

		if emu.UcMode == uc.MODE_32 {
			esp, _ := emu.Uc.RegRead(uc.X86_REG_ESP)
			eipBytes, _ := emu.Uc.MemRead(esp, 4)
			eip := uint64(binary.LittleEndian.Uint32(eipBytes))
			emu.Uc.RegWrite(uc.X86_REG_EIP, eip)
			emu.Uc.RegWrite(uc.X86_REG_ESP, esp+4+uint64(4*len(instruction.Hook.Parameters)))
		} else {
			// TODO, fix stack adjustment to reflect parameters passed in registers
			rsp, _ := emu.Uc.RegRead(uc.X86_REG_RSP)
			ripBytes, _ := emu.Uc.MemRead(rsp, 8)
			rip := binary.LittleEndian.Uint64(ripBytes)
			emu.Uc.RegWrite(uc.X86_REG_RIP, rip)
			numParams := len(instruction.Hook.Parameters) - 4
			if numParams < 0 {
				numParams = 0
			}
			//emu.Uc.RegWrite(uc.X86_REG_RSP, rsp+4+uint64(4*len(instruction.Hook.Parameters)))
			emu.Uc.RegWrite(uc.X86_REG_RSP, rsp+8+uint64(8*numParams))
		}

		return true
	}
}

func CallStdFunction(emu *WinEmulator, functionAddress uint64, parameters []uint64) {
	var currentIP uint64
	if emu.UcMode == uc.MODE_32 {
		currentIP, _ = emu.Uc.RegRead(uc.X86_REG_EIP)
	} else {
		currentIP, _ = emu.Uc.RegRead(uc.X86_REG_RIP)
	}

	if emu.UcMode == uc.MODE_32 {
		i := len(parameters) - 1
		for i >= 0 {
			util.PushStack(emu.Uc, emu.UcMode, parameters[i])
			i -= 1
		}
	} else {

	}

	util.PushStack(emu.Uc, emu.UcMode, currentIP) //returns to this after it exits

	if emu.UcMode == uc.MODE_32 {
		emu.Uc.RegWrite(uc.X86_REG_EIP, functionAddress)
	} else {
		emu.Uc.RegWrite(uc.X86_REG_RIP, functionAddress)
	}
}
