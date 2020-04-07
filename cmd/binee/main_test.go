package main

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

type JsonOutput struct {
	Tid        int           `json:"tid"`
	Addr       int           `json:"addr"`
	Size       int           `json:"size"`
	Opcode     string        `json:"opcode"`
	Lib        string        `json:"lib"`
	Fn         string        `json:"fn"`
	Parameters []string      `json:"parameters"`
	Values     []interface{} `json:"values"`
	Return     int           `json:"return"`
}

type PfPair struct {
	Name  string
	Value int
}

func (self *JsonOutput) CheckFn(fnName string, index int, compare func(b interface{}) bool) error {
	if self.Fn != fnName || len(self.Values) < index-1 {
		return nil
	}

	curValue := self.Values[index]
	if compare(curValue) == false {
		return fmt.Errorf("(%s) invalid: %v", fnName, curValue)
	}

	return nil
}

func (self *JsonOutput) checkPrintf(chks []PfPair) error {
	// if not printf, skip
	if self.Fn != "__stdio_common_vfprintf" {
		return nil
	}

	// if not enough values, skip
	if len(self.Values) < 5 {
		return nil
	}

	// record observed name and value
	s := self.Values[3].(string)
	v := int(self.Values[4].(float64))

	for _, chk := range chks {
		// if the prefix matches, but the value doesn't throw an error
		if strings.HasPrefix(s, chk.Name) && v != chk.Value {
			return fmt.Errorf("(Printf) %s != %d: %d", chk.Name, chk.Value, v)
		}
	}
	return nil
}

func (self *JsonOutput) checkTerminate() error {
	if self.Fn != "TerminateProcess" {
		return nil
	}

	if self.Return > 0 {
		return nil
	}
	return fmt.Errorf("TerminateProcess returned 0")
}

func createJSONLines(fname string) ([]JsonOutput, error) {
	cmd := exec.Command("./binee", "-j", fname)
	jsonLines := []JsonOutput{}

	// if the output errors out then error
	out, err := cmd.Output()
	if err != nil {
		return jsonLines, err
	}

	// split by newline (and closing curly bracket)
	lines := strings.Split(string(out), "}\n")
	for _, line := range lines {
		// if the line is empty, skip it
		if strings.TrimSpace(line) == "" {
			continue
		}
		// otherwise, add back the closing curly bracket
		line += "}"

		// create the struct and unmarshal
		var output JsonOutput
		err := json.Unmarshal([]byte(line), &output)

		// if there was an error unmarshaling, error out and skip
		if err != nil {
			return jsonLines, err
		}

		// otherwise, append it
		jsonLines = append(jsonLines, output)
	}

	return jsonLines, nil
}

func TestConsoleApplication1_x86(t *testing.T) {
	jsonLines, err := createJSONLines("tests/ConsoleApplication1_x86.exe")
	if err != nil {
		t.Error(err)
		return
	}
	// keep track of required names and values
	chks := []PfPair{}
	chks = append(chks, PfPair{"GENERIC_READ", 2147483648})
	chks = append(chks, PfPair{"GENERIC_WRITE", 1073741824})
	chks = append(chks, PfPair{"INVALID_HANDLE", 4294967295})
	chks = append(chks, PfPair{"CREATE_ALWAYS", 2})
	chks = append(chks, PfPair{"FILE_ATTRIBUTE_NORMAL", 128})
	chks = append(chks, PfPair{"ERROR_SUCCESS", 0})

	for i, output := range jsonLines {
		err = output.checkPrintf(chks)
		if err != nil {
			t.Error(err)
		}

		if i+1 == len(jsonLines) {
			err = output.checkTerminate()
			if err != nil {
				t.Error(err)
			}
		}

	}
}

func TestConsoleApplication2_x86(t *testing.T) {
	jsonLines, err := createJSONLines("tests/ConsoleApplication2_x86.exe")
	if err != nil {
		t.Error(err)
		return
	}
	chks := []PfPair{}
	chks = append(chks, PfPair{"argv", 0})

	for _, output := range jsonLines {
		err = output.checkPrintf(chks)
		if err != nil {
			t.Error(err)
		}
	}
}

func TestCalloc_x86(t *testing.T) {
	jsonLines, err := createJSONLines("tests/test_calloc_vs17.exe")
	if err != nil {
		t.Error(err)
		return
	}

	//func (self *JsonOutput) CheckFn(fnName string, index int, compare func(b interface{}) bool) error {
	//if self.Fn != "__stdio_common_vfprintf" {

	for _, output := range jsonLines {
		if err := output.CheckFn("__stdio_common_vfprintf", 4, func(b interface{}) bool {
			if int(b.(float64)) >= 0xa0000000 {
				return true
			}
			return false
		}); err != nil {
			t.Error(err)
		}
	}

}
