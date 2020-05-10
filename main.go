// Package main is the main entry point into using Binee. Provides all
// parameterized options passed in via command line
package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/carbonblack/binee/pefile"
	"github.com/carbonblack/binee/util"
	"github.com/carbonblack/binee/windows"
)

func main() {

	isAPISetLookup := flag.String("a", "", "get the real dll name from an apiset name")
	listAllAPISets := flag.Bool("A", false, "list all apisets and their mappings")
	showDLL := flag.Bool("d", false, "show the dll prfix on all function calls")
	configFilePath := flag.String("c", "", "path to configuration file")
	listExports := flag.Bool("e", false, "dump pe file's exports table")
	listImports := flag.Bool("i", false, "dump a pe file's imports table")
	listResources := flag.Bool("res", false, "dump a pe file's resources section")
	outputJSON := flag.Bool("j", false, "output data as json")
	instructionLog := flag.Bool("l", false, "log instructions to a []*Instruction slice, typically this is for programmatic emulation")
	verbose2 := flag.Bool("vv", false, "verbose level 2")
	verbose1 := flag.Bool("v", false, "verbose level 1")
	runDLLMain := flag.Bool("m", false, "call DLLMain while loading DLLs")
	rootFolder := flag.String("r", "os/win10_32/", "root path of mock file system, defaults to ./os/win10_32")
	maxTicks := flag.Int64("t", 0, "maximum number of instructions to emulate before stopping emulation, default is 0 and will run forever or until other stopping event")

	flag.Parse()

	verboseLevel := 0
	if *verbose1 {
		verboseLevel = 1
	}
	if *verbose2 {
		verboseLevel = 2
	}

	// if apiset dump option, load apisetschema.dll and dump all apisets
	if *listAllAPISets {
		if *configFilePath != "" {
			conf, err := util.ReadGenericConfig(*configFilePath)
			if err != nil {
				log.Fatal(err)
			}
			rootFolder = &conf.Root
		}
		path, err := util.SearchFile([]string{"C:\\Windows\\System32", *rootFolder + "windows/system32"}, "apisetschema.dll")
		if err != nil {
			log.Fatal(err)
		}

		apiset, _ := pefile.LoadPeFile(path)

		for k, v := range apiset.Apisets {
			fmt.Println(k, v)
		}

		return
	}

	// if apiset lookup, load apisetschema.dll and look up the apiset name
	if *isAPISetLookup != "" {
		if *configFilePath != "" {
			conf, err := util.ReadGenericConfig(*configFilePath)
			if err != nil {
				log.Fatal(err)
			}
			rootFolder = &conf.Root
		}
		path, err := util.SearchFile([]string{"C:\\Windows\\System32", *rootFolder + "windows/system32"}, "apisetschema.dll")
		if err != nil {
			log.Fatal(err)
		}

		apiset, _ := pefile.LoadPeFile(path)
		lookup := (*isAPISetLookup)[0 : len(*isAPISetLookup)-6]
		if apiset.Apisets[lookup] != nil {
			for i := 0; i < len(apiset.Apisets[lookup]); i++ {
				fmt.Println("  ", apiset.Apisets[lookup][i])
			}
		} else {
			fmt.Println("apiset not found.")
		}

		return
	}

	// quit if no binary is passed in
	if flag.NArg() == 0 {
		flag.PrintDefaults()
		return
	}

	// print the binaries import table
	if *listImports {
		if pe, err := pefile.LoadPeFile(flag.Arg(0)); err == nil {
			for _, importInfo := range pe.Imports {
				fmt.Printf("%s.%s => 0x%x\n", importInfo.DllName, importInfo.FuncName, importInfo.Offset)
			}
		}
		return
	}
	if *listResources {
		if pe, err := pefile.LoadPeFile(flag.Arg(0)); err == nil {
			var resourcesRVA uint32
			if pe.PeType == pefile.Pe32 {
				resourcesRVA = pe.OptionalHeader.(*pefile.OptionalHeader32).DataDirectories[2].VirtualAddress
			} else {
				resourcesRVA = pe.OptionalHeader.(*pefile.OptionalHeader32P).DataDirectories[2].VirtualAddress
			}
			if resourcesRVA != 0 {
				pe.PrintResources()
			} else {
				fmt.Println("This executable has no resources section.")

			}
		} else {
			fmt.Println("Can't parse pefile.")
		}
		return
	}
	// print the binaries export table
	if *listExports {
		if pe, err := pefile.LoadPeFile(flag.Arg(0)); err == nil {
			for _, export := range pe.Exports {
				fmt.Println(export.Name)
			}
		}
		return
	}

	options := windows.InitWinEmulatorOptions()
	options.VerboseLevel = verboseLevel
	options.ConfigPath = *configFilePath
	options.RootFolder = *rootFolder
	options.ShowDLL = *showDLL
	options.RunDLLMain = *runDLLMain
	if *outputJSON {
		options.LogType = windows.LogTypeJSON
	} else if *instructionLog {
		options.LogType = windows.LogTypeSlice
	} else {
		options.LogType = windows.LogTypeStdout
	}
	options.MaxTicks = *maxTicks

	// now start the emulator with the various options
	emu, err := windows.Load(flag.Arg(0), flag.Args()[1:], options)
	if err != nil {
		log.Fatal(err)
	}

	emu.Start()
}
