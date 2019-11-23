package windows

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/carbonblack/binee/util"
	"github.com/chzyer/readline"

	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
)

func execCurrentInstr(emu *WinEmulator, addr uint64, size uint32) (bool, *Instruction) {
	instruction := emu.BuildInstruction(addr, size)
	doContinue := instruction.Hook.Fn(emu, instruction)
	var returns uint64
	if emu.UcMode == uc.MODE_32 {
		returns, _ = emu.Uc.RegRead(uc.X86_REG_EAX)
	} else {
		returns, _ = emu.Uc.RegRead(uc.X86_REG_RAX)
	}
	instruction.Hook.Return = returns
	return doContinue, instruction
}

/* func resolveBreakpoint(emu *WinEmulator, bp string) (uint64, error) {
	if res := emu.NameToAddress[bp]; res != 0 {
		return res, nil
	}

	if addr, err := strconv.ParseInt(bp, 0, 64); err != nil {
		return 0, err
	} else {
		return uint64(addr), nil
	}

} */

var completer = []readline.PrefixCompleterInterface{
	readline.PcItem("quit"),
	readline.PcItem("next"),
	readline.PcItem("run"),
	readline.PcItem("setreg"),
	readline.PcItem("show",
		readline.PcItem("breakpoints"),
		readline.PcItem("registers"),
		readline.PcItem("stack")),
}

func filterInput(r rune) (rune, bool) {
	switch r {
	case readline.CharCtrlZ:
		return r, false
	}
	return r, true
}

func HookCodeStep(emu *WinEmulator) func(mu uc.Unicorn, addr uint64, size uint32) {
	return func(mu uc.Unicorn, addr uint64, size uint32) {
		doContinue := true
		var instr *Instruction
		emu.Ticks += 1

		// set up readline cli parser
		l, err := readline.NewEx(&readline.Config{
			Prompt:              "binee > ",
			HistoryFile:         TempDir() + "/binee.tmp",
			AutoComplete:        readline.NewPrefixCompleter(completer...),
			InterruptPrompt:     "^C",
			EOFPrompt:           "exit",
			HistorySearchFold:   true,
			FuncFilterInputRune: filterInput,
		})

		if err != nil {
			panic(err)
		}
		l.SetVimMode(true)
		defer l.Close()

		for {
			// check if breakpoint hit
			if bp := emu.Breakpoints[addr]; bp != 0 {
				emu.AutoContinue = false
			}

			// check if we are in "run" mode
			if emu.AutoContinue {
				doContinue, instr = execCurrentInstr(emu, addr, size)
				//fmt.Println(instr)
				break
			}

			fmt.Print("binee > ")
			in, _ := l.Readline()
			in = strings.TrimSuffix(in, "\n")
			if len(in) == 0 {
				in = emu.LastCommand
			}

			words := strings.Split(in, " ")
			// remove last element if empty
			// case happens when someone tab completes and hits enter, there is an extra whitespace
			if len(words) > 0 && words[len(words)-1] == "" {
				words = words[:len(words)-1]
			}

			if len(words) == 1 {
				if words[0] == "q" || words[0] == "quit" || words[0] == "exit" {
					fmt.Println("quitting...")
					os.Exit(0)
				} else if words[0] == "next" || words[0] == "n" {
					doContinue, instr = execCurrentInstr(emu, addr, size)
					fmt.Println(instr)
					emu.LastCommand = in
					break
				} else if words[0] == "r" || words[0] == "run" {
					emu.AutoContinue = true
				}
			} else if len(words) == 2 {
				if (words[0] == "show" || words[0] == "s") && words[1] == "registers" {
					r := emu.Cpu.ReadRegisters()
					fmt.Println(r)
				} else if (words[0] == "show" || words[0] == "s") && words[1] == "stack" {
					emu.Cpu.PrintStack(10)
				} else if (words[0] == "show" || words[0] == "s") && words[1] == "breakpoints" {
					fmt.Println("Current breakpoints:")
					for _, v := range emu.Breakpoints {
						fmt.Printf("  0x%x\n", v)
					}
				} else if words[0] == "breakpoint" || words[0] == "bp" {
					//if bp, err := resolveBreakpoint(emu, words[1]); err != nil {
					//	fmt.Println("Error setting breakpoint at:", words[1])
					//} else {
					//	fmt.Printf("Breakpoint set at: 0x%x\n", bp)
					//	emu.Breakpoints[bp] = bp
					//}
				}
			} else if len(words) == 3 {
				if words[0] == "setreg" || words[0] == "sr" {
					if d, err := strconv.ParseInt(words[2], 0, 64); err != nil {
						fmt.Println("error parsing value:", words[2])
					} else {
						if reg, err := util.ResolveRegisterByName(words[1]); err != nil {
							fmt.Println(err)
						} else {
							emu.Uc.RegWrite(reg, uint64(d))
						}
					}
				}
			}

		}

		if doContinue == false {
			mu.Stop()
		}

	}
}
