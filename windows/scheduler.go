package windows

import (
	"encoding/binary"
	"fmt"
	"github.com/unicorn-engine/unicorn/bindings/go/unicorn"

	"github.com/carbonblack/binee/core"
)

type Thread struct {
	ThreadId        int
	registers       interface{}
	Status          int
	WaitingChannels []chan int
}

type ScheduleManager struct {
	curThread     *Thread
	curIndex      int
	threads       []*Thread
	emu           *WinEmulator
	threadsAtomic int
}

func NewScheduleManager(emu *WinEmulator) *ScheduleManager {
	threads := make([]*Thread, 0, 1)
	firstThread := &Thread{1, emu.CPU.PopContext(), 0, nil}

	//Building stack with ROP to exit thread after it ends.
	if emu.PtrSize == 4 {
		exitFunc := emu.libFunctionAddress["ntdll.dll"]["RtlExitUserThread"]
		buf := make([]byte, 4)
		binary.LittleEndian.PutUint32(buf, uint32(exitFunc))
		esp, _ := emu.Uc.RegRead(unicorn.X86_REG_ESP)
		esp -= uint64(4 * emu.NumMainCallDll)
		emu.Uc.MemWrite(esp, buf)
	} else {
		exitFunc := emu.libFunctionAddress["ntdll.dll"]["RtlExitUserThread"]
		buf := make([]byte, 8)
		binary.LittleEndian.PutUint64(buf, exitFunc)
		rsp, _ := emu.Uc.RegRead(unicorn.X86_REG_RSP + (-8 * int(emu.NumMainCallDll*4)))
		rsp -= uint64(8 * emu.NumMainCallDll)
		emu.Uc.MemWrite(rsp, buf)
	}

	threads = append(threads, firstThread)
	handleAddr := emu.Heap.Malloc(emu.PtrSize)
	handle := Handle{}
	handle.Thread = firstThread
	emu.Handles[handleAddr] = &handle
	return &ScheduleManager{
		firstThread,
		0,
		threads,
		emu,
		1,
	}
}

func (self *ScheduleManager) CurThreadId() int {
	return self.curThread.ThreadId
}

func (self *ScheduleManager) findThreadyByID(threadId int) *Thread {
	for _, t := range self.threads {
		if t.ThreadId == threadId {
			return t
		}
	}
	return nil
}

func (self *ScheduleManager) DoSchedule() {
	// if there is only one thread, nothing to do
	if len(self.threads) == 1 {
		return
	}

	//save current context
	curThread := self.curThread
	curThread.registers = self.emu.CPU.PopContext()

	//round robin scheduler
	// find next thread with status running
	var nextThread *Thread
	for i := 1; i < len(self.threads)+1; i++ {
		tid := (self.curIndex + i) % len(self.threads)
		if self.threads[tid].Status == 0 {
			nextThread = self.threads[tid]
			self.curIndex = (self.curIndex + i) % len(self.threads)
			break
		}
	}

	if nextThread == nil {
		fmt.Errorf("No active threads available to run")
		return
	}

	//update cpu
	self.curThread = nextThread
	self.emu.CPU.PushContext(nextThread.registers)
}

func (self *Thread) RemoveReceiverChannel(rc chan int) {
	var waitingChanels []chan int
	for _, wc := range self.WaitingChannels {
		if wc != rc {
			waitingChanels = append(waitingChanels, wc)
		} else {
			close(wc)
		}
	}
	self.WaitingChannels = waitingChanels
}

func (self *ScheduleManager) ThreadEnded(threadId int) uint64 {
	//Tell channels waiting that I am closed.
	t := self.findThreadyByID(threadId)
	for _, c := range t.WaitingChannels {
		c <- threadId
	}

	self.DelThread(threadId)
	if len(self.threads) == 0 {
		return 0
	}
	nextThread := self.threads[0]
	self.curThread = nextThread
	self.emu.CPU.PushContext(nextThread.registers)
	if self.emu.PtrSize == 4 {
		return uint64(nextThread.registers.(*core.Registers32).Eip)
	} else {
		return nextThread.registers.(*core.Registers64).Rip
	}
}

func (self *ScheduleManager) NewThread(eip uint64, stack uint64, parameter uint64, creationFlag uint64) *Handle {
	// get status, can only be either running or suspended
	status := 0
	if creationFlag&CREATE_SUSPENDED == CREATE_SUSPENDED {
		status = CREATE_SUSPENDED
	}

	// init new thread
	// Range 0xca5 to 3 * 0xca7 reserved for RemoteThreads
	if self.threadsAtomic == 0xca5 {
		self.threadsAtomic += 2 * 0xca7
	}
	self.threadsAtomic += 1
	newThread := Thread{self.threadsAtomic, self.emu.CPU.PopContext(), int(status), nil}

	if self.emu.PtrSize == 4 {
		// offset by one due to parameter to thread
		newThread.registers.(*core.Registers32).Esp = uint32(stack - 8)
		newThread.registers.(*core.Registers32).Eip = uint32(eip)
		newThread.registers.(*core.Registers32).Edi = uint32(eip)
		newThread.registers.(*core.Registers32).Esi = uint32(eip)
		newThread.registers.(*core.Registers32).Edi = uint32(eip)
		newThread.registers.(*core.Registers32).Ecx = uint32(eip)
		newThread.registers.(*core.Registers32).Ebp = uint32(eip)

		// write parameter to stack
		buf := make([]byte, 4)
		binary.LittleEndian.PutUint32(buf, uint32(parameter))
		// write the paramter that is passed into the thread function onto the stack
		self.emu.Uc.MemWrite(stack-4, buf)

		//Building stack with ROP to exit thread after it ends.
		exitFunc := self.emu.libFunctionAddress["ntdll.dll"]["RtlExitUserThread"]
		binary.LittleEndian.PutUint32(buf, uint32(exitFunc))
		self.emu.Uc.MemWrite(stack-8, buf)

	} else {
		newThread.registers.(*core.Registers64).Rsp = stack
		newThread.registers.(*core.Registers64).Rip = eip
		newThread.registers.(*core.Registers64).Rdi = eip
		newThread.registers.(*core.Registers64).Rsi = eip
		newThread.registers.(*core.Registers64).Rdi = eip
		newThread.registers.(*core.Registers64).Rcx = eip
		newThread.registers.(*core.Registers64).Rbp = eip
		exitFunc := self.emu.libFunctionAddress["ntdll.dll"]["RtlExitUserThread"]
		buf := make([]byte, 8)
		binary.LittleEndian.PutUint64(buf, exitFunc)
		self.emu.Uc.MemWrite(stack, buf)
	}

	self.threads = append(self.threads, &newThread)
	handle := Handle{}
	handle.Thread = &newThread

	// create new handle for thread, add it to WinEmulator Handles map
	handleAddr := self.emu.Heap.Malloc(self.emu.PtrSize)
	self.emu.Handles[handleAddr] = &handle

	return &handle
}

func (self *ScheduleManager) DelThread(threadId int) {
	newThreads := make([]*Thread, 0, len(self.threads))
	for _, t := range self.threads {
		if t.ThreadId != threadId {
			newThreads = append(newThreads, t)
		}
	}

	self.threads = newThreads
}

//ToDo add SuspendCount
func (self *ScheduleManager) SuspendThread(threadId int) bool {
	thread := self.findThreadyByID(threadId)
	if thread == nil {
		return false
	}
	thread.Status &= CREATE_SUSPENDED
	return true
}

func (self *ScheduleManager) ResumeThread(threadId int) bool {
	thread := self.findThreadyByID(threadId)
	if thread == nil {
		return false
	}
	thread.Status &= 0
	return true
}
