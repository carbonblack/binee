package core

import (
	"encoding/binary"
	"fmt"

	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
)

type CpuManager struct {
	emu          uc.Unicorn
	mode         int
	ptrSize      int
	stackAddress uint64
	stackSize    uint64
	heapAddress  uint64
	heapSize     uint64
}

func NewCpuManager(emu uc.Unicorn, mode int, stackAddress, stackSize, heapAddress, heapSize uint64) *CpuManager {
	ptrSize := 4
	if mode == uc.MODE_64 {
		ptrSize = 8
	}

	return &CpuManager{
		emu,
		mode,
		ptrSize,
		stackAddress,
		stackSize,
		heapAddress,
		heapSize,
	}
}

func (self *CpuManager) PrintStack(size int) {
	if size <= 0 {
		size = 10
	}

	var rsp uint64
	if self.ptrSize == 4 {
		rsp, _ = self.emu.RegRead(uc.X86_REG_ESP)
	} else {
		rsp, _ = self.emu.RegRead(uc.X86_REG_RSP)
	}

	for i := (-1 * size); i <= size; i++ {

		cur := rsp - uint64(self.ptrSize*i)

		if val, err := self.emu.MemRead(cur, uint64(self.ptrSize)); err != nil {
			break
		} else {

			mark := ""
			if cur == rsp {
				if self.ptrSize == 4 {
					mark = "esp -->"
				} else {
					mark = "rsp -->"
				}
			}

			if self.ptrSize == 4 {
				fmt.Printf("%-8s 0x%x = 0x%x\n", mark, cur, binary.LittleEndian.Uint32(val))
			} else {
				fmt.Printf("%-8s 0x%x = 0x%x\n", mark, cur, binary.LittleEndian.Uint64(val))
			}
		}
	}
}

type Registers32 struct {
	Eip    uint32
	Esp    uint32
	Eax    uint32
	Ebx    uint32
	Ecx    uint32
	Edx    uint32
	Esi    uint32
	Edi    uint32
	Ebp    uint32
	EipVal uint32
	EspVal uint32
	EaxVal uint32
	EbxVal uint32
	EcxVal uint32
	EdxVal uint32
	EsiVal uint32
	EdiVal uint32
	EbpVal uint32
}

func (self *Registers32) String() string {
	ret := fmt.Sprintf("eax -->  0x%08x", self.Eax)
	if self.Eax != self.EaxVal {
		ret += fmt.Sprintf(" = 0x%x\n", self.EaxVal)
	} else {
		ret += "\n"
	}

	ret += fmt.Sprintf("ebx -->  0x%08x", self.Ebx)
	if self.Ebx != self.EbxVal {
		ret += fmt.Sprintf(" = 0x%x\n", self.EbxVal)
	} else {
		ret += "\n"
	}

	ret += fmt.Sprintf("ecx -->  0x%08x", self.Ecx)
	if self.Ecx != self.EcxVal {
		ret += fmt.Sprintf(" = 0x%x\n", self.EcxVal)
	} else {
		ret += "\n"
	}

	ret += fmt.Sprintf("edx -->  0x%08x", self.Edx)
	if self.Edx != self.EdxVal {
		ret += fmt.Sprintf(" = 0x%x\n", self.EdxVal)
	} else {
		ret += "\n"
	}
	ret += fmt.Sprintf("edi -->  0x%08x", self.Edi)
	if self.Edi != self.EdiVal {
		ret += fmt.Sprintf(" = 0x%x\n", self.EdiVal)
	} else {
		ret += "\n"
	}
	ret += fmt.Sprintf("esi -->  0x%08x", self.Esi)
	if self.Esi != self.EsiVal {
		ret += fmt.Sprintf(" = 0x%x\n", self.EsiVal)
	} else {
		ret += "\n"
	}
	ret += fmt.Sprintf("ebp -->  0x%08x", self.Ebp)
	if self.Ebp != self.EbpVal {
		ret += fmt.Sprintf(" = 0x%x\n", self.EbpVal)
	} else {
		ret += "\n"
	}
	ret += fmt.Sprintf("esp -->  0x%08x", self.Esp)
	if self.Esp != self.EspVal {
		ret += fmt.Sprintf(" = 0x%x\n", self.EspVal)
	} else {
		ret += "\n"
	}
	ret += fmt.Sprintf("eip -->  0x%08x", self.Eip)
	return ret
}

type Registers64 struct {
	Rip uint64
	Rsp uint64
	Rax uint64
	Rbx uint64
	Rcx uint64
	Rdx uint64
	Rsi uint64
	Rdi uint64
	Rbp uint64
	R8  uint64
	R9  uint64
	R10 uint64
	R11 uint64
	R12 uint64
	R13 uint64
	R14 uint64
	R15 uint64
}

func (self *Registers64) String() string {
	ret := fmt.Sprintf("rip is 0x%016x", self.Rip)
	ret += fmt.Sprintf("rsp is 0x%016x\n", self.Rsp)
	ret += fmt.Sprintf("rax is 0x%016x", self.Rax)
	ret += fmt.Sprintf("rbx is 0x%016x\n", self.Rbx)
	ret += fmt.Sprintf("rcx is 0x%016x", self.Rcx)
	ret += fmt.Sprintf("rdx is 0x%016x\n", self.Rdx)
	ret += fmt.Sprintf("rsi is 0x%016x", self.Rsi)
	ret += fmt.Sprintf("rdi is 0x%016x\n", self.Rdi)
	ret += fmt.Sprintf("rbp is 0x%016x", self.Rbp)
	ret += fmt.Sprintf("r8 is 0x%016x\n", self.R8)
	ret += fmt.Sprintf("r9 is 0x%016x", self.R9)
	ret += fmt.Sprintf("r10 is 0x%016x\n", self.R10)
	ret += fmt.Sprintf("r11 is 0x%016x", self.R11)
	ret += fmt.Sprintf("r12 is 0x%016x\n", self.R12)
	ret += fmt.Sprintf("r13 is 0x%016x", self.R13)
	ret += fmt.Sprintf("r14 is 0x%016x\n", self.R14)
	ret += fmt.Sprintf("r15 is 0x%016x", self.R15)
	return ret
}

func (self *CpuManager) getAddressValue(addr uint64) uint64 {
	if self.mode == uc.MODE_32 {
		if addr >= self.stackAddress && addr <= self.stackAddress+self.stackSize {
			val, _ := self.emu.MemRead(addr, 4)
			return uint64(binary.LittleEndian.Uint32(val))
		}

		if addr >= self.heapAddress && addr <= self.heapAddress+self.heapSize {
			val, _ := self.emu.MemRead(addr, 4)
			return uint64(binary.LittleEndian.Uint32(val))
		}
	} else {
		if addr >= self.stackAddress && addr <= self.stackAddress+self.stackSize {
			val, _ := self.emu.MemRead(addr, 8)
			return binary.LittleEndian.Uint64(val)
		}
		if addr >= self.heapAddress && addr <= self.heapAddress+self.heapSize {
			val, _ := self.emu.MemRead(addr, 8)
			return binary.LittleEndian.Uint64(val)
		}
	}
	return addr
}

func (self *CpuManager) ReadRegisters() interface{} {
	if self.mode == uc.MODE_32 {
		eip, _ := self.emu.RegRead(uc.X86_REG_EIP)
		esp, _ := self.emu.RegRead(uc.X86_REG_ESP)
		eax, _ := self.emu.RegRead(uc.X86_REG_EAX)
		ebx, _ := self.emu.RegRead(uc.X86_REG_EBX)
		ecx, _ := self.emu.RegRead(uc.X86_REG_ECX)
		edx, _ := self.emu.RegRead(uc.X86_REG_EDX)
		esi, _ := self.emu.RegRead(uc.X86_REG_ESI)
		edi, _ := self.emu.RegRead(uc.X86_REG_EDI)
		ebp, _ := self.emu.RegRead(uc.X86_REG_EBP)

		return &Registers32{
			Eip:    uint32(eip),
			EipVal: uint32(self.getAddressValue(eip)),
			Esp:    uint32(esp),
			EspVal: uint32(self.getAddressValue(esp)),
			Eax:    uint32(eax),
			EaxVal: uint32(self.getAddressValue(eax)),
			Ebx:    uint32(ebx),
			EbxVal: uint32(self.getAddressValue(ebx)),
			Ecx:    uint32(ecx),
			EcxVal: uint32(self.getAddressValue(ecx)),
			Edx:    uint32(edx),
			EdxVal: uint32(self.getAddressValue(edx)),
			Esi:    uint32(esi),
			EsiVal: uint32(self.getAddressValue(esi)),
			Edi:    uint32(edi),
			EdiVal: uint32(self.getAddressValue(edi)),
			Ebp:    uint32(ebp),
			EbpVal: uint32(self.getAddressValue(ebp)),
		}

	} else {
		rip, _ := self.emu.RegRead(uc.X86_REG_RIP)
		rsp, _ := self.emu.RegRead(uc.X86_REG_RSP)
		rax, _ := self.emu.RegRead(uc.X86_REG_RAX)
		rbx, _ := self.emu.RegRead(uc.X86_REG_RBX)
		rcx, _ := self.emu.RegRead(uc.X86_REG_RCX)
		rdx, _ := self.emu.RegRead(uc.X86_REG_RDX)
		rsi, _ := self.emu.RegRead(uc.X86_REG_RSI)
		rdi, _ := self.emu.RegRead(uc.X86_REG_RDI)
		rbp, _ := self.emu.RegRead(uc.X86_REG_RBP)
		r8, _ := self.emu.RegRead(uc.X86_REG_R8)
		r9, _ := self.emu.RegRead(uc.X86_REG_R9)
		r10, _ := self.emu.RegRead(uc.X86_REG_R10)
		r11, _ := self.emu.RegRead(uc.X86_REG_R11)
		r12, _ := self.emu.RegRead(uc.X86_REG_R12)
		r13, _ := self.emu.RegRead(uc.X86_REG_R13)
		r14, _ := self.emu.RegRead(uc.X86_REG_R14)
		r15, _ := self.emu.RegRead(uc.X86_REG_R15)

		return &Registers64{
			Rip: uint64(rip),
			Rsp: uint64(rsp),
			Rax: uint64(rax),
			Rbx: uint64(rbx),
			Rcx: uint64(rcx),
			Rdx: uint64(rdx),
			Rsi: uint64(rsi),
			Rdi: uint64(rdi),
			Rbp: uint64(rbp),
			R8:  uint64(r8),
			R9:  uint64(r9),
			R10: uint64(r10),
			R11: uint64(r11),
			R12: uint64(r12),
			R13: uint64(r13),
			R14: uint64(r14),
			R15: uint64(r15),
		}
	}
}

func (self *CpuManager) PopContext() interface{} {
	return self.ReadRegisters()
}

func (self *CpuManager) PushContext(context interface{}) {
	if self.mode == uc.MODE_32 {
		ctx := context.(*Registers32)
		self.emu.RegWrite(uc.X86_REG_EIP, uint64(ctx.Eip))
		self.emu.RegWrite(uc.X86_REG_ESP, uint64(ctx.Esp))
		self.emu.RegWrite(uc.X86_REG_EAX, uint64(ctx.Eax))
		self.emu.RegWrite(uc.X86_REG_EBX, uint64(ctx.Ebx))
		self.emu.RegWrite(uc.X86_REG_ECX, uint64(ctx.Ecx))
		self.emu.RegWrite(uc.X86_REG_EDX, uint64(ctx.Edx))
		self.emu.RegWrite(uc.X86_REG_ESI, uint64(ctx.Esi))
		self.emu.RegWrite(uc.X86_REG_EDI, uint64(ctx.Edi))
		self.emu.RegWrite(uc.X86_REG_EBP, uint64(ctx.Ebp))
	}
}
