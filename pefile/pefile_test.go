package pefile

import "testing"

func TestLoadExe(t *testing.T) {
	pe, err := LoadPeFile("../tests/ConsoleApplication1_x86.exe")
	if err != nil {
		t.Errorf("Error loading %s\n", pe.Path)
	}

	if len(pe.ImportedDlls()) != 7 {
		t.Errorf("Wrong number of imported dlls for %s, 7 == %d\n", pe.Path, len(pe.Imports))
	}

	var count int = len(pe.Imports)

	if count != 43 {
		t.Errorf("%s total number of imported functions should be 43 == %d\n", pe.Path, count)
	}

}
