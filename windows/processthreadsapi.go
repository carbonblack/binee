package windows

import "github.com/carbonblack/binee/util"

type ProcessInformation struct {
	hprocess    uint32
	hThread     uint32
	dwProcessId uint32
	dwThreadId  uint32
}

func createProcess(emu *WinEmulator, in *Instruction) bool {
	stub := make(map[string]interface{})
	wide := in.Hook.Name[len(in.Hook.Name)-1] == 'W'
	var applicationName, commandLine string
	if wide {
		applicationName = util.ReadWideChar(emu.Uc, in.Args[0], 0)
		commandLine = util.ReadWideChar(emu.Uc, in.Args[1], 0)
	} else {
		applicationName = util.ReadASCII(emu.Uc, in.Args[0], 0)
		commandLine = util.ReadASCII(emu.Uc, in.Args[1], 0)
	}
	if (applicationName+commandLine) == "" || in.Args[9] == 0 || in.Args[8] == 0 { // params are not right
		return SkipFunctionStdCall(true, 0)(emu, in)
	}
	stub["szExeFile"] = applicationName + commandLine
	stub["dwFlags"] = uint32(in.Args[5])
	processInfo := &ProcessInformation{}
	emu.ProcessManager.startProcess(stub)
	process := emu.ProcessManager.processMap[uint32(emu.ProcessManager.numberOfProcesses)-1]
	procHandle := &Handle{
		Process: &process,
	}
	handleAddr := emu.Heap.Malloc(4)
	emu.Handles[handleAddr] = procHandle
	processInfo.hprocess = uint32(handleAddr)
	processInfo.dwProcessId = process.the32ProcessID
	processInfo.dwThreadId = 1337
	processInfo.hThread = uint32(emu.Heap.Malloc(4))
	util.StructWrite(emu.Uc, in.Args[9], processInfo)

	return SkipFunctionStdCall(true, 1)(emu, in)
}

func ProcessthreadsapiHooks(emu *WinEmulator) {
	emu.AddHook("", "CreateProcessA", &Hook{
		Parameters: []string{"a:lpApplicationName", "a:lpCommandLine", "lpProcessAttributes", "lpThreadAttributes", "bInheritHandles", "dwCreationFlags", "lpEnvironment", "lpCurrentDirectory", "lpStartupInfo", "lpProcessInformation"},
		Fn:         createProcess,
	})
	emu.AddHook("", "CreateProcessW", &Hook{
		Parameters: []string{"w:lpApplicationName", "w:lpCommandLine", "lpProcessAttributes", "lpThreadAttributes", "bInheritHandles", "dwCreationFlags", "lpEnvironment", "lpCurrentDirectory", "lpStartupInfo", "lpProcessInformation"},
		Fn:         createProcess,
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
			procID := in.Args[2]
			if _, ok := emu.ProcessManager.processMap[uint32(procID)]; !ok {
				return SkipFunctionStdCall(true, 0)(emu, in)
			}
			process := emu.ProcessManager.processMap[uint32(procID)]
			procHandle := &Handle{
				Process: &process,
			}
			handleAddr := emu.Heap.Malloc(4)
			emu.Handles[handleAddr] = procHandle
			return SkipFunctionStdCall(true, handleAddr)(emu, in)
		},
	})
	emu.AddHook("", "TerminateProcess", &Hook{
		Parameters: []string{"hProcess", "uExitCode"},
		Fn: func(emulator *WinEmulator, in *Instruction) bool {
			if in.Args[0] == 0xffffffff {
				return false
			}
			if _, ok := emu.Handles[in.Args[0]]; !ok {
				return SkipFunctionStdCall(true, 0)(emu, in)
			}
			if emu.Handles[in.Args[0]].Process == nil {
				return SkipFunctionStdCall(true, 0)(emu, in)
			}
			process := emu.Handles[in.Args[0]].Process
			success := emu.ProcessManager.terminateProcess(process.the32ProcessID)
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
	emu.AddHook("", "SetPriorityClass", &Hook{
		Parameters: []string{"hProcess", "dwPriorityClass"},
		Fn:         SkipFunctionStdCall(true, 0x1337),
	})
	emu.AddHook("", "SetProcessPriorityBoost", &Hook{
		Parameters: []string{"hProcess", "dwPriorityClass"},
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

	emu.AddHook("", "CreateRemoteThread", &Hook{
		Parameters: []string{"hProcess", "lpThreadAttributes", "dwStackSize", "lpParameter", "lpStartAddress", "dwCreationFlags", "lpThreadId"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			// checking the proc handle exists
			stub := make(map[string]interface{})
			currentProcId := emu.ProcessManager.currentPid
			hproc := &Handle{}
			hproc = emu.Handles[in.Args[0]]
			if hproc == nil {
				return SkipFunctionStdCall(true, 0)(emu, in)
			}
			ownerProcessID := hproc.Process.the32ProcessID
			stackSize := uint64(1 * 1024 * 1024)
			if in.Args[1] != 0x0 {
				stackSize = in.Args[1]
			}
			lpParameter := in.Args[3]
			//stack should start at the top of the newly allocated space on the heap
			stackAddress := emu.Heap.Malloc(stackSize) + stackSize - 0x20
			lpStartAddress := in.Args[4]
			dwCreationFlags := in.Args[5]
			stub["creatorProcessID"] = currentProcId
			stub["lpParameter"] = lpParameter
			stub["stackAddress"] = stackAddress
			stub["stackSize"] = stackSize
			stub["lpStartAddress"] = lpStartAddress
			stub["ownerProcessID"] = ownerProcessID
			stub["dwCreationFlags"] = dwCreationFlags

			//create new ThreadContext
			remotethreadid := emu.ProcessManager.startRemoteThread(stub)
			if remotethreadid < 0xca7 {
				//Todo the dummy process
			}
			remoteThread := emu.ProcessManager.remoteThreadMap[uint32(len(emu.ProcessManager.remoteThreadMap))-1]
			remoteThreadHandle := &Handle{
				Object: &remoteThread,
			}
			handleAddr := emu.Heap.Malloc(4)
			emu.Handles[handleAddr] = remoteThreadHandle
			// write thread ID back to pointer lpThreadId
			util.PutPointer(emu.Uc, emu.PtrSize, in.Args[6], uint64(remoteThread.remoteThreadID))

			return SkipFunctionStdCall(true, handleAddr)(emu, in)
		},
	})

	emu.AddHook("", "ResumeThread", &Hook{
		Parameters: []string{"hThread"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			threadHandle := in.Args[0]
			handle := emu.Handles[threadHandle]
			if handle.Thread != nil {
				threadId := handle.Thread.ThreadId
				status := emu.Scheduler.ResumeThread(threadId)
				if status {
					emu.setLastError(0)
					return SkipFunctionStdCall(true, 0x1337)(emu, in)
				} else {
					emu.setLastError(0xFFFFFFFF)
					return SkipFunctionStdCall(true, 0)(emu, in)
				}
			}
			rthreadHandle := handle.Object.(*RemoteThread)
			if rthreadHandle != nil {
				threadId := rthreadHandle.remoteThreadID
				status := emu.ProcessManager.resumeRemoteThread(threadId)
				if status {
					emu.setLastError(0)
					return SkipFunctionStdCall(true, 1337)(emu, in)
				} else {
					emu.setLastError(0xFFFFFFFF)
					return SkipFunctionStdCall(true, 0)(emu, in)
				}
			}
			emu.setLastError(0xFFFFFFFF)
			return SkipFunctionStdCall(true, 0)(emu, in)
		},
	})
	emu.AddHook("", "SuspendThread", &Hook{
		Parameters: []string{"hThread"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			threadHandle := in.Args[0]
			handle := emu.Handles[threadHandle]
			if handle.Thread != nil {
				threadId := handle.Thread.ThreadId
				status := emu.Scheduler.SuspendThread(threadId)
				if status {
					emu.setLastError(0)
					return SkipFunctionStdCall(true, 0x1337)(emu, in)
				} else {
					emu.setLastError(0xFFFFFFFF)
					return SkipFunctionStdCall(true, 0)(emu, in)
				}
			}
			rthreadHandle := handle.Object.(*RemoteThread)
			if rthreadHandle != nil {
				threadId := rthreadHandle.remoteThreadID
				status := emu.ProcessManager.suspendRemoteThread(threadId)
				if status {
					emu.setLastError(0)
					return SkipFunctionStdCall(true, 0x1337)(emu, in)
				} else {
					emu.setLastError(0xFFFFFFFF)
					return SkipFunctionStdCall(true, 0)(emu, in)
				}
			}
			emu.setLastError(0xFFFFFFFF)
			return SkipFunctionStdCall(true, 0)(emu, in)
		},
	})
	emu.AddHook("", "SetThreadContext", &Hook{
		Parameters: []string{"hThread", "lpContext"},
		Fn:         SkipFunctionStdCall(true, 1),
	})

	emu.AddHook("", "QueueUserAPC", &Hook{
		Parameters: []string{"pfnAPC", "hThread", "dwData"},
		Fn:         SkipFunctionStdCall(true, 1),
	})

	emu.AddHook("", "NtQueueApcThread", &Hook{
		Parameters: []string{"threadHandle", "ApcRoutine", "ApcRoutineContxt", "ApcStatusBlock", "ApcReserved"},
		Fn:         SkipFunctionStdCall(true, 1),
	})
	emu.AddHook("", "ZwQueueApcThread", &Hook{
		Parameters: []string{"threadHandle", "ApcRoutine", "ApcRoutineContxt", "ApcStatusBlock", "ApcReserved"},
		Fn:         SkipFunctionStdCall(true, 1),
	})

	emu.AddHook("", "NtCreateProcessEx", &Hook{
		Parameters: []string{"ProcessHandle", "DesiredAccess", "oa", "ParentProcess", "InheritObjectTable", "SectionHandle", "DebugPort", "ExceptionPort", "arg9"},
		Fn:         SkipFunctionStdCall(true, 0x1337),
	})

	emu.AddHook("", "OpenThread", &Hook{
		Parameters: []string{"dwDesiredAccess", "bInheritHandle", "dwThreadId"},
		Fn:         SkipFunctionStdCall(true, 0x1337),
	})

	emu.AddHook("", "GetProcessIdOfThread", &Hook{
		Parameters: []string{"Thread"},
		Fn:         SkipFunctionStdCall(true, 0x3),
	})

	emu.AddHook("", "GetThreadContext", &Hook{
		Parameters: []string{"hThread", "lpContext"},
		Fn:         SkipFunctionStdCall(true, 0),
	})

	emu.AddHook("", "SetThreadPriority", &Hook{
		Parameters: []string{"hThread", "dwPriorityClass"},
		Fn:         SkipFunctionStdCall(true, 0x1337),
	})

	emu.AddHook("", "FlushInstructionCache", &Hook{
		Parameters: []string{"hProcess", "lpBaseAddress", "dwSize"},
		Fn:         SkipFunctionStdCall(true, 1),
	})

	emu.AddHook("", "ZwSuspendProcess", &Hook{
		Parameters: []string{"hProcess"},
		Fn:         SkipFunctionStdCall(true, 0),
	})
	emu.AddHook("", "ZwResumeProcess", &Hook{
		Parameters: []string{"hProcess"},
		Fn:         SkipFunctionStdCall(true, 0),
	})

	//Threadpool

	emu.AddHook("", "CreateThreadpoolTimer", &Hook{
		Parameters: []string{"pfnti", "pv", "pcbe"},
		Fn:         SkipFunctionStdCall(true, 0x1337),
	})

}
