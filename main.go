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

	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
)

func main() {

	isAPISetLookup := flag.String("a", "", "get the real dll name from an apiset name")
	listAllAPISets := flag.Bool("A", false, "list all apisets and their mappings")
	showDLL := flag.Bool("d", false, "show the dll prfix on all function calls")
	configFilePath := flag.String("c", "", "path to configuration file")
	listExports := flag.Bool("e", false, "dump pe file's exports table")
	listImports := flag.Bool("i", false, "dump a pe file's imports table")
	showHelp := flag.Bool("h", false, "show help menu")
	outputJSON := flag.Bool("j", false, "output data as json")
	verbose2 := flag.Bool("vv", false, "verbose level 2")
	verbose1 := flag.Bool("v", false, "verbose level 1")
	rootFolder := flag.String("r", "os/win10_32", "root path of mock file system, defaults to ./os/win10_32")

	flag.Parse()

	if *showHelp {
		flag.PrintDefaults()
		return
	}

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
	if len(flag.Args()) == 0 {
		flag.PrintDefaults()
		return
	}

	// print the binaries import table
	if *listImports {
		if pe, err := pefile.LoadPeFile(flag.Args()[0]); err == nil {
			for _, importInfo := range pe.Imports {
				fmt.Printf("%s.%s => 0x%x\n", importInfo.DllName, importInfo.FuncName, importInfo.Offset)
			}
		}
		return
	}

	// print the binaries export table
	if *listExports {
		if pe, err := pefile.LoadPeFile(flag.Args()[0]); err == nil {
			for _, export := range pe.Exports {
				fmt.Println(export.Name)
			}
		}
		return
	}

	// now start the emulator with the various options
	emu, err := windows.New(flag.Args()[0], uc.ARCH_X86, uc.MODE_32, flag.Args()[1:], verboseLevel, *configFilePath, *showDLL, false)
	emu.AsJson = *outputJSON
	if err != nil {
		log.Fatal(err)
	}

	emu.Start()
}
