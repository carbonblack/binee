package windows_test

import "github.com/carbonblack/binee/windows"
import "testing"

func makeRegistry() *windows.Registry {
	temp := make(map[string]string)
	temp["HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Arbiters\\InaccessibleRange\\Psi"] = "PyhsicalAddress"
	temp["HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Arbiters\\InaccessibleRange\\Root"] = "PyhsicalAddress2"
	temp["HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Arbiters\\InaccessibleRange2"] = "PyhsicalAddress3"

	mock, _ := windows.NewRegistry(temp)
	return mock
}

func TestRegistry(t *testing.T) {
	mock := makeRegistry()

	if mock.Size != 8 {
		t.Errorf("Size of Registry should be 2, found '%v'", mock.Size)
	}

	if _, err := mock.Get("HKEY_LOCAL_MACHINE", "SYSTEM\\ControlSet001\\Control\\Arbiters\\InaccessibleRange2"); err != nil {
		t.Errorf("%s", err)
	}

	if err := mock.Update("HKEY_LOCAL_MACHINE", "SYSTEM\\ControlSet001\\Control\\Arbiters\\InaccessibleRange2", "test"); err != nil {
		t.Errorf("%s", err)
	}

	if v, err := mock.Get("HKEY_LOCAL_MACHINE", "SYSTEM\\ControlSet001\\Control\\Arbiters\\InaccessibleRange2"); err == nil {
		if v.Value != "test" {
			t.Errorf("update failed")
		}
	}

}

func TestReg(t *testing.T) {
	reg := windows.NewReg("", "AAAA")

	h, _ := reg.Bytes()

	if h[0] == 0x41 && h[1] == 0x41 && h[2] == 0x41 && h[3] == 0x41 && h[4] == 0x00 {
	} else {
		t.Errorf("error converting string to bytes, expecting 0x41,0x41,0x41,0x41,0x00 got 0x%x, 0x%x, 0x%x, 0x%x, 0x%x", h[0], h[1], h[2], h[3], h[4])
	}
}

func TestRegHex(t *testing.T) {
	reg := windows.NewReg("", "hex(a):41,41,41,41")

	hexStuff, _ := reg.Bytes()
	for i, n := range hexStuff {
		if n != 0x41 {
			t.Errorf("error converting string to bytes")
		}

		if i > 3 {
			t.Errorf("error converting string to bytes, to many")
			break
		}
	}
}

func TestRegDword(t *testing.T) {
	reg := windows.NewReg("", "dword:00000005")

	hexStuff, _ := reg.Bytes()
	if hexStuff[0] != 0x5 {
		t.Errorf("error converting string to bytes")
	}
	if hexStuff[1] != 0x0 {
		t.Errorf("error converting string to bytes")
	}
	if hexStuff[2] != 0x0 {
		t.Errorf("error converting string to bytes")
	}
	if hexStuff[3] != 0x0 {
		t.Errorf("error converting string to bytes")
	}
}
