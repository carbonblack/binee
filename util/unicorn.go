// util package provides some helper functions for interacting with unicorn
// emulator that are independent from any of the process emulation happening
package util

import "strings"
import "fmt"
import "encoding/binary"
import "bytes"
import "errors"
import "github.com/carbonblack/binee/pefile"
import uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"

// StructWrite, given a struct and a unicorn memory address. Convert the struct to a byte
// array and write that byte array to the address in the unicorn memory
func StructWrite(u uc.Unicorn, addr uint64, data interface{}) error {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, data)
	return u.MemWrite(addr, buf.Bytes())
}

// PutPointer will take a pointer uint64 and write that pointer as little
// endian bytes into the emulator address specified by the where argument
func PutPointer(u uc.Unicorn, ptrSize uint64, where uint64, ptr uint64) error {
	buf := make([]byte, ptrSize)
	if ptrSize == 4 {
		binary.LittleEndian.PutUint32(buf, uint32(ptr))
		return u.MemWrite(where, buf)
	} else {
		binary.LittleEndian.PutUint64(buf, ptr)
		return u.MemWrite(where, buf)
	}
}

// GetPointer will retrieve a pointer value from unicorn memory from the where
// argument address
func GetPointer(u uc.Unicorn, ptrSize uint64, where uint64) (uint64, error) {
	if buf, err := u.MemRead(where, ptrSize); err != nil {
		return 0, err
	} else {
		var ret uint64
		if ptrSize == 4 {
			ret = uint64(binary.LittleEndian.Uint32(buf))
		} else {
			ret = binary.LittleEndian.Uint64(buf)
		}
		return ret, nil
	}
}

// PushStack will push some value of some Unincorn Mode (uc.MODE_32, uc.MODE_64)
// onto the call stack located at ESP or RSP
func PushStack(u uc.Unicorn, mode int, val uint64) {
	if mode == uc.MODE_32 {
		esp, _ := u.RegRead(uc.X86_REG_ESP)
		esp = esp - 4
		u.RegWrite(uc.X86_REG_ESP, esp)
		buf := make([]byte, 4)
		binary.LittleEndian.PutUint32(buf, uint32(val))
		u.MemWrite(esp, buf)
	} else {
		rsp, _ := u.RegRead(uc.X86_REG_RSP)
		rsp = rsp - 8
		u.RegWrite(uc.X86_REG_RSP, rsp)
		buf := make([]byte, 8)
		binary.LittleEndian.PutUint64(buf, val)
		u.MemWrite(rsp, buf)

	}
}

// ResolveRegisterByName takes a register name like 'eax' or 'rax' and returns
// the unicorn enumeration value coorisponding to that register.
func ResolveRegisterByName(name string) (int, error) {
	switch strings.ToLower(name) {
	case "eax":
		return uc.X86_REG_EAX, nil
	case "ebx":
		return uc.X86_REG_EBX, nil
	case "ecx":
		return uc.X86_REG_ECX, nil
	case "edx":
		return uc.X86_REG_EDX, nil
	case "esi":
		return uc.X86_REG_ESI, nil
	case "edi":
		return uc.X86_REG_EDI, nil
	case "ebp":
		return uc.X86_REG_EBP, nil
	case "esp":
		return uc.X86_REG_ESP, nil
	case "eip":
		return uc.X86_REG_EIP, nil
	case "rax":
		return uc.X86_REG_RAX, nil
	case "rbx":
		return uc.X86_REG_RBX, nil
	case "rcx":
		return uc.X86_REG_RCX, nil
	case "rdx":
		return uc.X86_REG_RDX, nil
	case "rsi":
		return uc.X86_REG_RSI, nil
	case "rdi":
		return uc.X86_REG_RDI, nil
	case "rbp":
		return uc.X86_REG_RBP, nil
	case "rsp":
		return uc.X86_REG_RSP, nil
	case "rip":
		return uc.X86_REG_RIP, nil
	}

	return 0, fmt.Errorf("Invalid register name: %s", name)

}

// ReadAscii will read an ascii string from memory, ending at a null byte. The
// null byte is also included in the return result
func ReadAscii(u uc.Unicorn, addr uint64, size int) string {
	ret := ""

	if size == 0 {
		size = 100000
	}

	for i := 0; i < size; i++ {
		b, err := u.MemRead(addr+uint64(i), 1)

		if err != nil {
			return ret
		}

		switch b[0] {
		case 0x09:
			ret += "\\t"
		case 0x0a:
			ret += "\\n"
		case 0x0b:
			ret += "\\v"
		case 0x0c:
			ret += "\\f"
		case 0x0d:
			ret += "\\r"
		case 0x00:
			return ret
		default:
			ret += string(b)
		}
	}

	return ret
}

// ReadWideChar will read a windows 2 byte wchar from an address, terminating
// at two null bytes. The return value will not include the null bytes.
func ReadWideChar(u uc.Unicorn, addr uint64, size int) string {
	ret := make([]byte, 0, 0)

	if size == 0 {
		size = 100000
	}

	for i := 0; i < size; i += 2 {
		b, err := u.MemRead(addr+uint64(i), 2)

		if err != nil {
			break
		}

		if b[0] == 0x00 && b[1] == 0x00 {
			break
		}

		switch b[0] {
		case 0x09:
			ret = append(ret, 0x5c)
			ret = append(ret, 0x5c)
			ret = append(ret, 0x74)
		case 0x0a:
			ret = append(ret, 0x5c)
			ret = append(ret, 0x5c)
			ret = append(ret, 0x6e)
		case 0x0b:
			ret = append(ret, 0x5c)
			ret = append(ret, 0x5c)
			ret = append(ret, 0x76)
		case 0x0c:
			ret = append(ret, 0x5c)
			ret = append(ret, 0x5c)
			ret = append(ret, 0x66)
		case 0x0d:
			ret = append(ret, 0x5c)
			ret = append(ret, 0x5c)
			ret = append(ret, 0x72)
		default:
			ret = append(ret, b[0])
		}
	}

	return string(ret)
}

// ReadPeFile will attempt to read a PE file from unicorn memory looking for specific headers
func ReadPeFile(u uc.Unicorn, addr uint64) (pefile.PeFile, error) {
	var err error
	var buf []byte
	pe := pefile.PeFile{}

	// read DosHeader
	pe.DosHeader = &pefile.DosHeader{}
	if buf, err = u.MemRead(addr, uint64(binary.Size(pe.DosHeader))); err != nil {
		return pe, errors.New(fmt.Sprintf("error reading DosHeader from unicorn memory"))
	}
	if err = binary.Read(bytes.NewReader(buf), binary.LittleEndian, pe.DosHeader); err != nil {
		return pe, errors.New(fmt.Sprintf("error writing DosHeader bytes to structure"))
	}

	pe.CoffHeader = &pefile.CoffHeader{}
	if buf, err = u.MemRead(uint64(pe.DosHeader.AddressExeHeader)+4, uint64(binary.Size(pe.CoffHeader))); err != nil {
		return pe, errors.New(fmt.Sprintf("error reading CoffHeader from unicorn memory"))
	}
	if err = binary.Read(bytes.NewReader(buf), binary.LittleEndian, pe.CoffHeader); err != nil {
		return pe, errors.New(fmt.Sprintf("error writing CoffHeader bytes to structure"))
	}

	optionalHeaderAddr := addr + uint64(pe.DosHeader.AddressExeHeader) + 4 + uint64(binary.Size(pe.CoffHeader))

	if uint16(binary.Size(pefile.OptionalHeader32{})) == pe.CoffHeader.SizeOfOptionalHeader {
		pe.PeType = pefile.Pe32
		pe.OptionalHeader = &pefile.OptionalHeader32{}
		if buf, err = u.MemRead(optionalHeaderAddr, uint64(binary.Size(pe.OptionalHeader))); err != nil {
			return pe, errors.New(fmt.Sprintf("error reading OptionalHeader32 from unicorn memory"))
		}
		if err = binary.Read(bytes.NewReader(buf), binary.LittleEndian, pe.OptionalHeader); err != nil {
			return pe, errors.New(fmt.Sprintf("error writing OptionalHeader32 bytes to structure"))
		}
	}

	return pe, nil

}

// GetStackValueByIndex gets a single entry (pointer) off the stack at a given depth
func GetStackEntryByIndex(u uc.Unicorn, mode int, n int) uint64 {
	if mode == uc.MODE_32 {
		esp, _ := u.RegRead(uc.X86_REG_ESP)
		// n pointers down
		ptr, _ := u.MemRead(esp+uint64(n)*4, 4)
		addr := uint64(binary.LittleEndian.Uint32(ptr))
		return addr
	} else {
		rsp, _ := u.RegRead(uc.X86_REG_RSP)
		ptr, _ := u.MemRead(rsp+uint64(n)*8, 8)
		addr := uint64(
			binary.LittleEndian.Uint64(ptr))
		return addr
	}
}
