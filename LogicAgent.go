package main

import "C"
import (
	"github.com/carbonblack/binee/windows"
	"log"
	"os"
	"strings"
)

//export ExtractBehaviour
func ExtractBehaviour(binaryFile *C.char, arguments *C.char, dllsPath *C.char, outputFile *C.char) *C.char {

	binaryInput := C.GoString(binaryFile)
	dllsInput := C.GoString(dllsPath)
	outputInput := C.GoString(outputFile)
	argumentsInput := C.GoString(arguments)
	argsSplit := strings.Split(argumentsInput, " ")
	options := windows.InitWinEmulatorOptions()
	options.VerboseLevel = 0
	options.ConfigPath = ""
	options.RootFolder = dllsInput
	options.ShowDLL = false
	options.RunDLLMain = false
	options.MaxTicks = 0
	emu, err := windows.Load(binaryInput, argsSplit, options)
	if err != nil {
		log.Fatal(err)
	}
	emu.Start()
	f, err := os.Create(outputInput)
	if err == nil {
		defer f.Close()
		for i, _ := range emu.FactFactory.Facts {
			f.WriteString(i + "\n")
		}
	}
	facts := ""
	for i, _ := range emu.FactFactory.Facts {
		facts += i + "\n"
	}
	return C.CString(facts)
}

func main() {
	// We need the main function to make possible
	// CGO compiler to compile the package as C shared library
}
