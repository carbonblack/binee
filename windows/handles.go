package windows

import "fmt"
import "os"
import "strings"
import "path/filepath"

type Handle struct {
	Path   string
	Access int32
	File   *os.File
	Info   os.FileInfo
	RegKey *RegKey
	Thread *Thread
}

func (handle *Handle) Close() {
	if handle.File != nil {
		handle.File.Close()
	}
}

func (handle *Handle) Write(bytes []byte) (int, error) {
	if handle.File != nil {
		return handle.File.Write(bytes)
	}
	return 0, fmt.Errorf("Invalid handle, cannot write to handle")
}

func (handle *Handle) Read(out_bytes []byte) (int, error) {
	if handle.File != nil {
		return handle.File.Read(out_bytes)
	}
	return 0, fmt.Errorf("Invalid handle, cannot read from handle")
}

func (emu *WinEmulator) OpenFile(path string, access int32) (*Handle, error) {
	var err error

	fd := Handle{
		Path:   path,
		Access: access,
		File:   nil,
		Info:   nil,
	}

	temp := strings.Replace(path, "c:", emu.Opts.Root, 1)
	temp = strings.Replace(temp, "C:", emu.Opts.Root, 1)
	temp = strings.Replace(temp, "\\", "/", -1)
	fd.Path = temp

	if strings.HasPrefix(fd.Path, emu.Opts.Root) {
		return nil, fmt.Errorf("Invalid path, file not found")
	}

	//if file is open for writing, do all writes in temp folder
	if access&GENERIC_WRITE == GENERIC_WRITE {
		fd.Path = "temp/" + path
		fd.File, err = os.OpenFile(fd.Path, os.O_RDWR|os.O_CREATE, 0755)
	} else if strings.Contains(path, filepath.Base(emu.Binary)) {
		fd.Path = emu.Binary
		fd.File, err = os.OpenFile(emu.Binary, os.O_RDWR, 0755)
	} else {
		fd.File, err = os.Open(fd.Path)
		if err != nil {
			fd.Path = "temp/" + path
			fd.File, err = os.OpenFile(fd.Path, os.O_RDWR|os.O_CREATE, 0755)
		}
	}

	fd.Info, _ = os.Stat(fd.Path)

	return &fd, err
}
