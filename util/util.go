package util

import (
	"fmt"
	"io/ioutil"
	"math/rand"
	"regexp"
	"strings"
)

//SearchFile is the primary function for searching the host/mock system for
//files for use in the emulator
func SearchFile(searchPaths []string, filename string) (string, error) {
	for i := 0; i < len(searchPaths); i++ {
		files, err := ioutil.ReadDir(searchPaths[i])
		if err != nil {
			return "", fmt.Errorf("directory '%s'not found", searchPaths[i])
		}
		for _, file := range files {
			if strings.ToLower(file.Name()) == strings.ToLower(filename) {
				return searchPaths[i] + "/" + file.Name(), nil
			}
		}
	}

	return "", fmt.Errorf("file '%s' not found", filename)
}

// NewGdtEntry initializes a gdt table entry
//https://github.com/unicorn-engine/unicorn/blob/master/samples/sample_x86_32_gdt_and_seg_regs.c
//github.com/lunixbochs/usercorn/blob/981730e3cd6b4a4186eb91d51d6c1a907fe44b6f/go/arch/x86/linux.go#L64
//scoding.de/setting-global-descriptor-table-unicorn
func NewGdtEntry(base, limit, access, flags uint32) uint64 {
	var entry uint64
	access |= 1 << 7
	if limit > 0xfffff {
		limit >>= 12
		flags |= 8
	}
	entry |= uint64(limit) & 0xffff
	entry |= ((uint64(limit) >> 16) & 0xf) << 48
	entry |= (uint64(base) & 0xffffff) << 16
	entry |= (uint64(base>>24) & 0xff) << 56
	entry |= (uint64(access) & 0xff) << 40
	entry |= (uint64(flags) & 0xff) << 52
	return entry
}

func CreateSelector(index, flags uint32) uint64 {
	ret := flags
	ret |= index << 3
	return uint64(ret)
}

// ASCIIToWinWChar will convert an ascii string to a windows sized wchar (2 byte width)
func ASCIIToWinWChar(s string) []byte {
	ret := make([]byte, 0, 0)
	for _, c := range s {
		ret = append(ret, byte(c))
		ret = append(ret, 0x0)
	}
	return ret
}

// RandomName will generate a random string name of l length. This is primarily
// used for saving temporary files to the host file system
func RandomName(l int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	s := ""
	for i := 0; i < l; i++ {
		s += string(letters[rand.Intn(len(letters))])
	}
	return s
}

/*
func WinWCharToAscii(w []byte) string {
	ret := ""
}
*/

// ParseFormatter will take a format string specifier and returns the individual formatters
func ParseFormatter(format string) []string {
	types := "diufFeEgGxXosScCpaAn"

	// pattern = %(%|[^%diufFeEgGxXosScCpaAn]*?[diufFeEgGxXosScCpaAn])
	// percent followed by either
	//   - a percent
	//   - a bunch of characters that are NOT a format specifier, followed by a specifier
	pattern := fmt.Sprintf("%%(%%|[^%%%s]*?[%s])", types, types)

	re := regexp.MustCompile(pattern)

	match_indices := re.FindAllStringIndex(format, -1)
	var fmts []string
	for _, match_index := range match_indices {
		f_str := format[match_index[0]:match_index[1]]
		// last character is the format type
		f_type := string(f_str[len(f_str)-1])
		if f_type == "%" {
			continue
		}
		fmts = append(fmts, f_type)
	}
	return fmts
}

func RoundUp(addr, mask uint64) uint64 {
	return (addr + mask) & ^mask
}
