// Package main is the main entry point into using Binee. Provides all
// parameterized options passed in via command line
package main

import "fmt"
import "log"
import "os"
import "binee/pefile"
import "binee/windows"
import "binee/util"
import uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"

type Options struct {
	Binary       string
	Args         []string
	Verbose      int
	ApisetLookup string
	ApisetDump   bool
	Usage        bool
	Exports      bool
	Imports      bool
	ImportsFuncs bool
	SingleStep   bool
	Config       string
	OutputJson   bool
	ShowDll      bool
	CallDllMain  bool
}

// parseArgs parses out command line arguments passed into binee on start
func parseArgs(args []string) Options {
	options := Options{}
	options.Args = make([]string, 0)
	options.ApisetDump = false
	options.CallDllMain = false

	for i := 0; i < len(args); i++ {

		if args[i][0] == '-' {
			switch args[i][1] {
			case 'v':
				options.Verbose += 1
				if len(args[i]) > 2 && args[i][2] == 'v' {
					options.Verbose += 1
				}
			case 'a':
				if len(args[i]) == 2 {
					options.ApisetLookup = args[i+1]
					i += 1
				} else {
					options.ApisetLookup = args[i][2:]
				}
			case 'A':
				options.ApisetDump = true
			case 'c':
				if len(args[i]) == 2 {
					options.Config = args[i+1]
					i += 1
				} else {
					options.Config = args[i][2:]
				}
			case 'd':
				options.ShowDll = true
			case 'e':
				options.Exports = true
			case 'h':
				options.Usage = true
			case 'i':
				options.Imports = true
				if len(args[i]) > 2 && args[i][2] == 'i' {
					options.ImportsFuncs = true
				}
			case 'j':
				options.Verbose = -1
				options.OutputJson = true
			case 'l':
				options.CallDllMain = true
			case 's':
				options.SingleStep = true
			}
		} else {
			if len(options.Args) == 0 {
				options.Binary = args[i]
			}
			options.Args = append(options.Args, args[i])
		}
	}

	return options
}

// usage prints out the command line flags availabe to Binee
func usage() {
	fmt.Println("usage ./binee [-aAhvveis] [FILE] [ARGS]")
	fmt.Println("  -a <apiset dll name>     Returns the real dll name given an apiset dll")
	fmt.Println("  -A                       List all apisets and their mappings")
	fmt.Println("  -c FILE                  Path to a configuration file")
	fmt.Println("  -d                       Show dll names with function in output")
	fmt.Println("  -e FILE                  List file exports")
	fmt.Println("  -h                       Show this usage menu")
	fmt.Println("  -i FILE                  List file imports")
	fmt.Println("  -j                       Output as JSON")
	fmt.Println("  -l                       Run full DllMain of imported functions with debug output")
	fmt.Println("  -s                       Run application through binee debugger")
	fmt.Println("  -v[v]                    Verbosity level, two v's for more verbose")
}

func main() {

	//parse all command line arguments and get executable to emulate
	options := parseArgs(os.Args[1:])

	// if apiset dump option, load apisetschema.dll and dump all apisets
	if options.ApisetDump {
		path, err := util.SearchFile([]string{"C:\\Windows\\System32", "os/win10_32/windows/system32"}, "apisetschema.dll")
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
	if options.ApisetLookup != "" {
		path, err := util.SearchFile([]string{"C:\\Windows\\System32", "os/win10_32/windows/system32"}, "apisetschema.dll")
		if err != nil {
			log.Fatal(err)
		}

		apiset, _ := pefile.LoadPeFile(path)
		lookup := options.ApisetLookup[0 : len(options.ApisetLookup)-6]
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
	if options.Binary == "" {
		usage()
		return
	}

	// print the binaries import table
	if options.Imports {
		if pe, err := pefile.LoadPeFile(options.Binary); err == nil {
			for _, importInfo := range pe.Imports {
				fmt.Printf("%s.%s => 0x%x\n", importInfo.DllName, importInfo.FuncName, importInfo.Offset)
			}
		}
		return
	}

	// print the binaries export table
	if options.Exports {
		if pe, err := pefile.LoadPeFile(options.Binary); err == nil {
			for _, export := range pe.Exports {
				fmt.Println(export.Name)
			}
		}
		return
	}

	// now start the emulator with the various options
	emu, err := windows.New(options.Binary, uc.ARCH_X86, uc.MODE_32, options.Args, options.Verbose, options.Config, options.ShowDll, options.CallDllMain)
	emu.AsJson = options.OutputJson
	if err != nil {
		log.Fatal(err)
	}

	if options.SingleStep == false {
		emu.Start()
	} else {
		emu.StartSingleStep()
	}
}
