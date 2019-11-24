# binee (Binary Emulation Environment)

Binee is a complete binary emulation environment that focuses on introspection
of all IO operations. Primary goals for this project are to provide a flexible
environment for determining a binaries side effects on the system.

The goals Binee tries to solve are the following:

1. Realistic loading of a PE file and its required dependencies. The userland
   memory should look as close to a real execution as possible.
2. Easy to use hooking framework. We want to create a flexible hooking
   framework that allows the analyst to rapidly implement new hooks and capture
   data.
3. Mock out as much of the OS internals as reasonably possible. Currently,
   there are small mocks of the file system, registry, threading and TIB/PEB
   structures for Windows.
4. The OS environment, as much as possible, should be defined in a
   configuration file. This enables rapid movement from environment to
   environment.

**If you choose to use Binee to emulate portions of Microsoft Windows, you are
solely responsible for obtaining any necessary rights and licenses from
Microsoft.**

## Development and Support

Please feel free to submit github issues or if you want to talk with us directly, come join is in slack

[slack workspace](https://join.slack.com/t/cb-binee/shared_invite/enQtODAwMjM5NzU4MDY4LTE3ZjJkY2FiNmIwMjExOTcwZDAxMjllZjdhODExNDZiZGFkOTJkZTU4YzY0YzVmMTc0N2ExMmYzMzg5MjNhOWU)

## DEF CON 27 Materials

[slides](https://github.com/carbonblack/binee/blob/defcon27/Kyle%20Gwinnup%20-%20Next%20Generation%20Process%20Emulation%20with%20Binee.pdf)

[demo video](https://github.com/carbonblack/binee/blob/defcon27/Kyle%20Gwinnup%20-%20Next%20Generation%20Process%20Emulation%20with%20Binee%20Demo.mp4)

[presentation](https://www.youtube.com/watch?v=z4OvVFw5pYI)

# Setup and developing in Docker container

If you are running Binee on Microsoft Windows, you can skip the mock file system step. 

Most malware will require at least some standard DLLs and these DLLs will need
to be accessible from the mock file system. The default "root" mock file system
is located in `os/win10_32/`. In order to allow for the malware to load up DLLs
you will need to copy them into the appropriate location within the mock file
system. Typically, these should be copied into,
`os/win10_32/windows/system32/`. Once you have the required files in that
directory, you can move onto the compiling and running step.

## Compiling and running

Build with the following docker command `docker build -t binee .`

```
docker run -it -v $PWD:/bineedev/go/src/github.com/carbonblack/binee binee bash
```

Download Golang dependencies and build Binee 

```
root@2b0fee41629f:~/go/src/github.com/carbonblack/binee# go build
```
_Note: presence of go.mod file will direct the build utility to collect dependencies upon build, and also allow for the repository to be cloned and developed at any path (regardless of `$GOPATH`) directory_


At this point you should be able to execute binee within the Docker container
and see the usage menu.

```
root@6a6fe8c2b2a7:~/go/src/github.com/carbonblack/binee# ./binee -h
Usage of ./binee:
  -A    list all apisets and their mappings
  -a string
        get the real dll name from an apiset name
  -c string
        path to configuration file
  -d    show the dll prfix on all function calls
  -e    dump pe file's exports table
  -i    dump a pe file's imports table
  -j    output data as json
  -l    call DLLMain while loading DLLs
  -r string
        root path of mock file system, defaults to ./os/win10_32 (default "os/win10_32/")
  -v    verbose level 1
  -vv
        verbose level 2
```

If you are running on Microsoft Windows and/or you have your mock file system
configured properly, you should be able to execute all the PE files within the
`tests/` directory.

```
root@2b0fee41629f:~/go/src/github.com/carbonblack/binee# ./binee tests/ConsoleApplication1_x86.exe
0x20735900: GetSystemTimeAsFileTime(lpSystemTimeAsFileTime = 0xb000ffe0) = 0xb000ffe0
0x2072a310: GetCurrentThreadId() = 0x0
0x20734100: GetCurrentProcessId() = 0x2001
0x207340e0: QueryPerformanceCounter(lpPerformanceCount = 0xb000ffd8) = 0x1
0x20738860: IsProcessorFeaturePresent(ProcessorFeature = 0xa) = 0x1
0x212ae760: _initterm_e(PVFV = 0x4020d8, PVFV = 0x4020e4) = 0x0
0x212a7260: _initterm(PVPV = 0x4020cc, PVPV = 0x4020d4) = 0x0
0x212fd880: __p___argv() = 0x40338c
0x212fd870: __p___argc() = 0x21352104
0x21330940: _get_initial_narrow_environment() = 0x21352108
0x212ad780: __acrt_iob_func() = 0x403380
0x2130f510: __stdio_common_vfprintf(stream = 0x0, format = 'GENERIC_READ = 0x%llx\n') = 0x403380
0x212ad780: __acrt_iob_func() = 0x403380
0x2130f510: __stdio_common_vfprintf(stream = 0x0, format = 'GENERIC_WRITE = 0x%llx\n') = 0x403380
0x212ad780: __acrt_iob_func() = 0x403380
0x2130f510: __stdio_common_vfprintf(stream = 0x0, format = 'INVALID_HANDLE = 0x%llx\n') = 0x403380
0x212ad780: __acrt_iob_func() = 0x403380
0x2130f510: __stdio_common_vfprintf(stream = 0x0, format = 'CREATE_ALWAYS = 0x%x\n') = 0x403380
0x212ad780: __acrt_iob_func() = 0x403380
0x2130f510: __stdio_common_vfprintf(stream = 0x0, format = 'FILE_ATTRIBUTE_NORMAL = 0x%x\n') = 0x403380
0x212ad780: __acrt_iob_func() = 0x403380
0x2130f510: __stdio_common_vfprintf(stream = 0x0, format = 'ERROR_SUCCESS = 0x%x\n') = 0x403380
0x2073e500: CreateFileA(lpFileName = 'malfile.exe', dwDesiredAccess = 0xc0000000, dwShareMode = 0x0, lpSecurityAttributes = 0x0, dwCreationDisposition = 0x2, dwFlagsAndAttributes = 0x80, hTemplateFile = 0x0) = 0xa0001578
0x207920d3: VerSetConditionMask() = 0x403380
0x212ad780: __acrt_iob_func() = 0x403380
0x2130f510: __stdio_common_vfprintf(stream = 0x0, format = 'out = 0x%x\n') = 0x403380
0x207920d3: VerSetConditionMask() = 0x403380
0x212ad780: __acrt_iob_func() = 0x403380
0x2130f510: __stdio_common_vfprintf(stream = 0x0, format = 'out = 0x%x\n') = 0x403380
0x207920d3: VerSetConditionMask() = 0x403380
0x212ad780: __acrt_iob_func() = 0x403380
0x2130f510: __stdio_common_vfprintf(stream = 0x0, format = 'out = 0x%x\n') = 0x403380
0x216b5730: memset(dest = 0xb000ff1c, char = 0x0, count = 0x58) = 0xb000ff1c
0x2073e920: WriteFile(hFile = 0xa0001578, lpBuffer = 0xb000ff10, nNumberOfBytesToWrite = 0xb, lpNumberOfBytesWritten = 0xb000ff0c, lpOverlapped = 0x0) = 0xb
0x20738860: IsProcessorFeaturePresent(ProcessorFeature = 0x17) = 0x1
0x2073ab20: SetUnhandledExceptionFilter(lpTopLevelExceptionFilter = 0x0) = 0x4
0x2075c770: UnhandledExceptionFilter(ExceptionInfo = 0x402100) = 0x1
0x207361b0: GetCurrentProcess() = 0x1
0x2073bd30: TerminateProcess(hProcess = 0xffffffff, uExitCode = 0xc0000409) = 0xffffffff
```


