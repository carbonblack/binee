package windows

import "fmt"
import "binee/core"
import "encoding/binary"

type Thread struct {
	ThreadId  int
	registers interface{}
	Status    int
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
	firstThread := &Thread{1, emu.Cpu.PopContext(), 0}
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

func (self *ScheduleManager) DoSchedule() {
	// if there is only one thread, nothing to do
	if len(self.threads) == 1 {
		return
	}

	//save current context
	curThread := self.curThread
	curThread.registers = self.emu.Cpu.PopContext()

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
	self.emu.Cpu.PushContext(nextThread.registers)
}

func (self *ScheduleManager) ThreadEnded(threadId int) uint64 {
	self.DelThread(threadId)
	nextThread := self.threads[0]
	self.curThread = nextThread
	self.emu.Cpu.PushContext(nextThread.registers)
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
	self.threadsAtomic += 1
	newThread := Thread{self.threadsAtomic, self.emu.Cpu.PopContext(), int(status)}

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

	} else {
		newThread.registers.(*core.Registers64).Rsp = stack
		newThread.registers.(*core.Registers64).Rip = eip
		newThread.registers.(*core.Registers64).Rdi = eip
		newThread.registers.(*core.Registers64).Rsi = eip
		newThread.registers.(*core.Registers64).Rdi = eip
		newThread.registers.(*core.Registers64).Rcx = eip
		newThread.registers.(*core.Registers64).Rbp = eip
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
	for i, t := range self.threads {
		if i+1 != threadId {
			newThreads = append(newThreads, t)
		}
	}

	self.threads = newThreads
}
