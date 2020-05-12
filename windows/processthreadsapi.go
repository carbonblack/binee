package windows

import "github.com/carbonblack/binee/util"

func ProcessthreadsapiHooks(emu *WinEmulator) {
	emu.AddHook("", "CreateProcessA", &Hook{
		Parameters: []string{"a:lpApplicationName", "a:lpCommandLine", "lpProcessAttributes", "lpThreadAttributes", "bInheritHandles", "dwCreationFlags", "lpEnvironment", "lpCurrentDirectory", "lpStartupInfo", "lpProcessInformation"},
		Fn:         SkipFunctionStdCall(true, 0x1),
	})
	emu.AddHook("", "CreateProcessW", &Hook{
		Parameters: []string{"w:lpApplicationName", "w:lpCommandLine", "lpProcessAttributes", "lpThreadAttributes", "bInheritHandles", "dwCreationFlags", "lpEnvironment", "lpCurrentDirectory", "lpStartupInfo", "lpProcessInformation"},
		Fn:         SkipFunctionStdCall(true, 0x1),
	})
	emu.AddHook("", "CreateProcessAsUserA", &Hook{
		Parameters: []string{"hToken", "a:lpApplicationName", "a:lpCommandLine", "lpProcessAttributes", "lpThreadAttributes", "bInheritHandles", "dwCreationFlags", "lpEnvironment", "lpCurrentDirectory", "lpStartupInfo", "lpProcessInformation"},
		Fn:         SkipFunctionStdCall(true, 0x1),
	})
	emu.AddHook("", "CreateProcessAsUserW", &Hook{
		Parameters: []string{"hToken", "w:lpApplicationName", "w:lpCommandLine", "lpProcessAttributes", "lpThreadAttributes", "bInheritHandles", "dwCreationFlags", "lpEnvironment", "lpCurrentDirectory", "lpStartupInfo", "lpProcessInformation"},
		Fn:         SkipFunctionStdCall(true, 0x1),
	})
	emu.AddHook("", "OpenProcess", &Hook{
		Parameters: []string{"dwDesiredAccess", "bInheritHandle", "dwProcessId"},
		Fn: func(emulator *WinEmulator, in *Instruction) bool {
			procIndex := emu.ProcessManager.openProcess(uint32(in.Args[2]))
			if procIndex == -1 {
				return SkipFunctionStdCall(true, 0)(emu, in)
			}
			return SkipFunctionStdCall(true, uint64(procIndex))(emu, in)
		},
	})
	emu.AddHook("", "TerminateProcess", &Hook{
		Parameters: []string{"hProcess", "uExitCode"},
		Fn: func(emulator *WinEmulator, in *Instruction) bool {
			if in.Args[0] == 0xffffffff {
				return false
			}
			success := emu.ProcessManager.terminateProcess(int(in.Args[0]))
			if success {
				return SkipFunctionStdCall(true, 0x1337)(emu, in)
			} else {
				return SkipFunctionStdCall(true, 0)(emu, in)
			}
		},
	})
	emu.AddHook("", "GetPriorityClass", &Hook{
		Parameters: []string{"Handle"},
		Fn:         SkipFunctionStdCall(true, 0x1337),
	})

	emu.AddHook("", "CreateThread", &Hook{
		Parameters: []string{"lpThreadAttributes", "dwStackSize", "lpStartAddress", "lpParameter", "dwCreationFlags", "lpThreadId"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			stackSize := uint64(1 * 1024 * 1024)
			if in.Args[1] != 0x0 {
				stackSize = in.Args[1]
			}
			//stack should start at the top of the newly allocated space on the heap
			stackAddr := emu.Heap.Malloc(stackSize) + stackSize - 0x20
			threadEip := in.Args[2]

			//create new ThreadContext
			threadHandle := emu.Scheduler.NewThread(threadEip, stackAddr, in.Args[3], in.Args[4])

			// write thread ID back to pointer lpThreadId
			util.PutPointer(emu.Uc, emu.PtrSize, in.Args[5], uint64(threadHandle.Thread.ThreadId))

			return SkipFunctionStdCall(true, uint64(threadHandle.Thread.ThreadId))(emu, in)
		},
	})

	emu.AddHook("", "GetCurrentThread", &Hook{
		Parameters: []string{},
		Fn:         SkipFunctionStdCall(true, uint64(emu.Scheduler.CurThreadId())),
	})

	emu.AddHook("", "OpenProcessToken", &Hook{
		Parameters: []string{"ProcessHandle", "DesiredAccess", "TokenHandle"},
		Fn:         SkipFunctionStdCall(true, 0x1),
	})
	emu.AddHook("", "OpenThreadToken", &Hook{
		Parameters: []string{"ThreadHandle", "DesiredAccess", "OpenAsSelf", "TokenHandle"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			util.PutPointer(emu.Uc, emu.PtrSize, in.Args[3], uint64(emu.Scheduler.CurThreadId()))
			return SkipFunctionStdCall(true, 0x1)(emu, in)
		},
	})
	emu.AddHook("", "TerminateThread", &Hook{
		Parameters: []string{"hThread", "dwExitCode"},
		Fn:         SkipFunctionStdCall(true, 0x1),
	})
}
