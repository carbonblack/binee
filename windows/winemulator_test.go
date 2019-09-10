package windows_test

import "github.com/carbonblack/binee/windows"
import "testing"

func TestLookupFunctionByAddress(t *testing.T) {
	emu := windows.WinEmulator{}
	emu.LoadedModules = map[string]uint64{
		"a": 10,
		"b": 8,
		"c": 6,
		"d": 4,
		"e": 2,
	}
	if emu.LookupLibByAddress(3) != "e" {
		t.Errorf("Error in LookupFunction")
	}
	if emu.LookupLibByAddress(11) != "a" {
		t.Errorf("Error in LookupFunction")
	}
	if emu.LookupLibByAddress(1) != "" {
		t.Errorf("Error in LookupFunction")
	}
	if emu.LookupLibByAddress(7) != "c" {
		t.Errorf("Error in LookupFunction")
	}
}
