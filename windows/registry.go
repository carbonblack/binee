package windows

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

func hkeyMap(n uint64) string {
	m := map[uint64]string{
		0x80000000: "HKEY_CLASSES_ROOT",
		0x80000005: "HKEY_CURRENT_CONFIG",
		0x80000001: "HKEY_CURRENT_USER",
		0x80000007: "HKEY_CURRENT_USER_LOCAL_SETTINGS",
		0x80000002: "HKEY_LOCAL_MACHINE",
		0x80000004: "HKEY_PERFORMANCE_DATA",
		0x80000060: "HKEY_PERFORMANCE_NLSTEXT",
		0x80000050: "HKEY_PERFORMANCE_TEXT",
		0x80000003: "HKEY_USERS",
	}
	return m[n]
}

// Reg is the type of each value in the registry, values can be actual values
// or "folders" within the registry
type Reg struct {
	Name    string
	Value   string
	subkeys map[string]*Reg
}

// RegKey used in handles
type RegKey struct {
	Hkey string
	Name string
}

// NewReg will create a new Reg object given a registry long name and its value
func NewReg(name, value string) *Reg {
	return &Reg{name, value, nil}
}

// Bytes will turn a Reg object into a byte representation ready to be loaded
// into the emulator
func (r *Reg) Bytes() ([]byte, int) {

	strBytes := []byte(r.Value)

	// check if its a byte array
	if matched, _ := regexp.Match(`^hex\(2\)\:`, strBytes); matched {
		s := strings.Split(r.Value, ":")
		hexStr := strings.Replace(s[1], ",", "", -1)
		ret, _ := hex.DecodeString(hexStr)
		return ret, REG_EXPAND_SZ
	}

	if matched, _ := regexp.Match(`^hex\(a\)\:`, strBytes); matched {
		s := strings.Split(r.Value, ":")
		hexStr := strings.Replace(s[1], ",", "", -1)
		ret, _ := hex.DecodeString(hexStr)
		return ret, REG_BINARY
	}

	if matched, _ := regexp.Match(`^hex\:`, strBytes); matched {
		s := strings.Split(r.Value, ":")
		hexStr := strings.Replace(s[1], ",", "", -1)
		ret, _ := hex.DecodeString(hexStr)
		return ret, REG_BINARY
	}

	if matched, _ := regexp.Match(`^dword\:`, strBytes); matched {
		s := strings.Split(r.Value, ":")
		i32, _ := strconv.ParseInt(s[1], 16, 32)
		buf := make([]byte, 4)
		binary.LittleEndian.PutUint32(buf, uint32(i32))
		return buf, REG_DWORD
	}

	if matched, _ := regexp.Match(`^qword\:`, strBytes); matched {
		s := strings.Split(r.Value, ":")
		i64, _ := strconv.ParseInt(s[1], 16, 64)
		buf := make([]byte, 8)
		binary.LittleEndian.PutUint64(buf, uint64(i64))
		return buf, REG_QWORD
	}

	// basic string value
	return append(strBytes, 0x00), REG_SZ
}

// Registry is the primary struct representing the mock registry system
type Registry struct {
	hkeys map[string]*Reg
	Size  int
}

// Insert will insert 'item' into the key and name provided. Name should be a
// full path in the registry separated by backslashes
func (r *Registry) Insert(key string, name string, item *Reg) error {
	if hkey, ok := r.hkeys[key]; ok {
		// found key, split the name into an array to iterate the path
		return r.insert(hkey, strings.Split(name, "\\"), item)
	}

	return fmt.Errorf("Registry key not found '%v'", key)
}

// insert is Registry's private helper function for inserting an item.
// Recursively, iterate each string value in the path slice, looking up each
// item and popping off stack as the function recurses
func (r *Registry) insert(cur *Reg, path []string, item *Reg) error {
	if len(path) == 0 {
		return fmt.Errorf("Insertion failed: invalid path provided. (%v)", item)
	}

	//at the end, do the insert
	if len(path) == 1 {
		item.Name = path[0] //set the name of this key
		// check place here and not in the item itself because not all items are parents
		if _, ok := cur.subkeys[item.Name]; !ok {
			cur.subkeys = make(map[string]*Reg)
		}
		cur.subkeys[item.Name] = item
		r.Size++
		return nil
	}

	// check if key already exists
	if _key, ok := cur.subkeys[path[0]]; ok {
		return r.insert(_key, path[1:], item)
	}

	// this must be a new key, add the new registry item and insert into it
	newkey := &Reg{path[0], "", make(map[string]*Reg)}
	cur.subkeys[newkey.Name] = newkey
	r.Size++
	return r.insert(newkey, path[1:], item)
}

// Enum is used with MSDN's reg enum, will allow for enumerating a registry key
func (r *Registry) Enum(hkey string, name string, index int) (*Reg, error) {
	if reg, err := r.Get(hkey, name); err == nil {
		i := 0
		for _, v := range reg.subkeys {
			if i == index {
				return v, nil
			}
			i++
		}
		return nil, fmt.Errorf("Invalid index for RegEnum '%v/%s' %d", hkey, name, index)
	}

	return nil, fmt.Errorf("Registry key not found '%v/%s'", hkey, name)
}

// Get will retrieve some item from the regisry given a key and path
func (r *Registry) Get(hkey string, name string) (*Reg, error) {
	if _hkey, ok := r.hkeys[hkey]; ok {
		return r.get(_hkey, strings.Split(name, "\\"))
	}
	return nil, fmt.Errorf("Registry key not found '%v/%s'", hkey, name)
}

// get is a private helper function for retrieving a value from the registry
func (r *Registry) get(cur *Reg, path []string) (*Reg, error) {
	if len(path) == 0 {
		return nil, fmt.Errorf("Registry error, empty name")
	}

	if k, ok := cur.subkeys[path[0]]; ok {
		if len(path) == 1 {
			return k, nil
		}
		return r.get(k, path[1:])
	}

	return nil, fmt.Errorf("Registry item not found")
}

// Update will update a value within the registry structure
func (r *Registry) Update(hkey string, name string, value string) error {
	if _hkey, ok := r.hkeys[hkey]; ok {
		return r.update(_hkey, strings.Split(name, "\\"), value)
	}
	return fmt.Errorf("Registry update failed, invalid hkey '%v'", hkey)
}

// update is a private helper function for updating a value within the registry
func (r *Registry) update(cur *Reg, path []string, value string) error {
	if len(path) == 0 {
		return fmt.Errorf("Registry update error")
	}

	if key, ok := cur.subkeys[path[0]]; ok {
		if len(path) == 1 {
			key.Value = value
			return nil
		}
		return r.update(key, path[1:], value)
	}

	return fmt.Errorf("Registry update failed, name not found '%v'", strings.Join(path, "\\"))
}

// NewRegistry creates a new registry hive with soje default values
func NewRegistry(temp map[string]string) (*Registry, error) {

	mock := &Registry{make(map[string]*Reg), 0}
	mock.hkeys["HKEY_CLASSES_ROOT"] = &Reg{"HKEY_CLASSES_ROOT", "", make(map[string]*Reg)}
	mock.hkeys["HKEY_CLASSES_CONFIG"] = &Reg{"HKEY_CLASSES_CONFIG", "", make(map[string]*Reg)}
	mock.hkeys["HKEY_CLASSES_USER"] = &Reg{"HKEY_CLASSES_USER", "", make(map[string]*Reg)}
	mock.hkeys["HKEY_CURRENT_USER"] = &Reg{"HKEY_CURRENT_USER", "", make(map[string]*Reg)}
	mock.hkeys["HKEY_CURRENT_USER_LOCAL_SETTINGS"] = &Reg{"HKEY_CURRENT_USER_LOCAL_SETTINGS", "", make(map[string]*Reg)}
	mock.hkeys["HKEY_LOCAL_MACHINE"] = &Reg{"HKEY_LOCAL_MACHINE", "", make(map[string]*Reg)}
	mock.hkeys["HKEY_PERFORMANCE_DATA"] = &Reg{"HKEY_PERFORMANCE_DATA", "", make(map[string]*Reg)}
	mock.hkeys["HKEY_PERFORMANCE_NLSTEXT"] = &Reg{"HKEY_PERFORMANCE_NLSTEXT", "", make(map[string]*Reg)}
	mock.hkeys["HKEY_PERFORMANCE_TEXT"] = &Reg{"HKEY_PERFORMANCE_TEXT", "", make(map[string]*Reg)}
	mock.hkeys["HKEY_USERS"] = &Reg{"HKEY_USERS", "", make(map[string]*Reg)}

	for k, v := range temp {
		item := &Reg{"", v, nil}
		s := strings.Split(k, "\\")
		if err := mock.Insert(s[0], strings.Join(s[1:], "\\"), item); err != nil {
			return mock, err
		}
	}

	return mock, nil
}
