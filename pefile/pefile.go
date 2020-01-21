package pefile

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

type PeType int

const (
	Pe32 PeType = iota
	Pe32p
)

type DosHeader struct {
	Magic                      uint16
	BytesOnLastPage            uint16
	PagesInFile                uint16
	Relocations                uint16
	SizeOfHeader               uint16
	MinExtra                   uint16
	MaxExtra                   uint16
	InitialSS                  uint16
	InitialSP                  uint16
	Checksum                   uint16
	InitialIP                  uint16
	InitialCS                  uint16
	FileAddressRelocationTable uint16
	Overlay                    uint16
	Reserved                   [4]uint16
	OemId                      uint16
	OemInfo                    uint16
	Reserved2                  [10]uint16
	AddressExeHeader           uint32
}

type CoffHeader struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDataStamp        uint32
	PointerSymbolTable   uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

type DataDirectory struct {
	VirtualAddress uint32
	Size           uint32
}

type OptionalHeader32 struct {
	Magic                   uint16
	MajorLinkerVersion      uint8
	MinorLinkerVersion      uint8
	SizeOfCode              uint32
	SizeOfInitializedData   uint32
	SizeOfUninitializedData uint32
	AddressOfEntryPoint     uint32
	BaseOfCode              uint32
	BaseOfData              uint32
	ImageBase               uint32
	SectionAlignment        uint32
	FileAlignment           uint32
	MajorOSVersion          uint16
	MinorOSVersion          uint16
	MajorImageVersion       uint16
	MinorImageVersion       uint16
	MajorSubsystemVersion   uint16
	MinorSubsystemVersion   uint16
	Win32Version            uint32
	SizeOfImage             uint32
	SizeOfHeaders           uint32
	Checksum                uint32
	Sybsystem               uint16
	DllCharacteristics      uint16
	SizeOfStackReserve      uint32
	SizeOfStackCommit       uint32
	SizeOfHeapReserve       uint32
	SizeOfHeapCommit        uint32
	LoaderFlags             uint32
	NumberOfRvaAndSizes     uint32
	DataDirectories         [16]DataDirectory
}

type OptionalHeader32P struct {
	Magic                   uint16
	MajorLinkerVersion      uint8
	MinorLinkerVersion      uint8
	SizeOfCode              uint32
	SizeOfInitializedData   uint32
	SizeOfUninitializedData uint32
	AddressOfEntryPoint     uint32
	BaseOfCode              uint32
	ImageBase               uint64
	SectionAlignment        uint32
	FileAlignment           uint32
	MajorOSVersion          uint16
	MinorOSVersion          uint16
	MajorImageVersion       uint16
	MinorImageVersion       uint16
	MajorSubsystemVersion   uint16
	MinorSubsystemVersion   uint16
	Win32Version            uint32
	SizeOfImage             uint32
	SizeOfHeaders           uint32
	Checksum                uint32
	Sybsystem               uint16
	DllCharacteristics      uint16
	SizeOfStackReserve      uint64
	SizeOfStackCommit       uint64
	SizeOfHeapReserve       uint64
	SizeOfHeapCommit        uint64
	LoaderFlags             uint32
	NumberOfRvaAndSizes     uint32
	DataDirectories         [16]DataDirectory
}

type SectionHeader struct {
	Name                 [8]byte
	VirtualSize          uint32
	VirtualAddress       uint32
	Size                 uint32
	Offset               uint32
	PointerToRelocations uint32
	PointerToLineNumbers uint32
	NumberOfRelocations  uint16
	NumberOfLineNumbers  uint16
	Characteristics      uint32
}

type Section struct {
	Name                 string
	VirtualSize          uint32
	VirtualAddress       uint32
	Size                 uint32
	Offset               uint32
	PointerToRelocations uint32
	PointerToLineNumbers uint32
	NumberOfRelocations  uint16
	NumberOfLineNumbers  uint16
	Characteristics      uint32
	Raw                  []byte
	Entropy              float64
}

type ImportInfo struct {
	DllName  string
	FuncName string
	Offset   uint32
	Ordinal  uint16
}

type PeFile struct {
	Path             string
	Name             string //import name, apiset or on disk
	RealName         string //on disk short name
	Sha256           string
	DosHeader        *DosHeader
	CoffHeader       *CoffHeader
	OptionalHeader   interface{}
	PeType           PeType
	Sections         []*Section
	sectionHeaders   []*SectionHeader
	Imports          []*ImportInfo
	Exports          []*Export
	ExportNameMap    map[string]*Export
	ExportOrdinalMap map[int]*Export
	Apisets          map[string][]string
	Size             int64
	RawHeaders       []byte
	oldImageBase     uint64
	ImageSize        int64
}

func entropy(bs []byte) float64 {
	histo := make([]int, 256)
	for _, b := range bs {
		histo[int(b)]++
	}

	size := len(bs)
	var ret float64 = 0.0

	for _, count := range histo {
		if count == 0 {
			continue
		}

		p := float64(count) / float64(size)
		ret += p * math.Log2(p)
	}

	return -ret
}

func (pe *PeFile) String() string {
	return fmt.Sprintf("{ Path: %s }", pe.Path)
}

// SetImageBase updates the image base of a PeFile and also updates all
// rolcations of the file
func (pe *PeFile) SetImageBase(imageBase uint64) error {
	if pe.PeType == Pe32 {
		pe.oldImageBase = uint64(pe.OptionalHeader.(*OptionalHeader32).ImageBase)
		pe.OptionalHeader.(*OptionalHeader32).ImageBase = uint32(imageBase)
	} else {
		pe.oldImageBase = pe.OptionalHeader.(*OptionalHeader32P).ImageBase
		pe.OptionalHeader.(*OptionalHeader32P).ImageBase = imageBase
	}

	return pe.updateRelocations()
}

// ImageBase returns the base address of the PE file
func (pe *PeFile) ImageBase() uint64 {
	if pe.PeType == Pe32 {
		return uint64(pe.OptionalHeader.(*OptionalHeader32).ImageBase)
	}

	// PE+ base addr
	return pe.OptionalHeader.(*OptionalHeader32P).ImageBase
}

// EntryPoint returns the entry point of the PE file
func (pe *PeFile) EntryPoint() uint32 {
	if pe.PeType == Pe32 {
		return pe.OptionalHeader.(*OptionalHeader32).AddressOfEntryPoint
	}

	// PE+ entry point
	return pe.OptionalHeader.(*OptionalHeader32P).AddressOfEntryPoint
}

// LoadPeFile will parse a file from disk, given a path. The output will be a
// PeFile object or an error
func LoadPeFile(path string) (*PeFile, error) {

	// create PeFile struct
	pe := &PeFile{Path: path}

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("Error opening %s file: %v", path, err)
	}

	// get size of file, then seek back to start to reset the cursor
	size, err := file.Seek(0, 2)
	if err != nil {
		return nil, fmt.Errorf("Error getting size of file %s: %v", path, err)
	}
	file.Seek(0, 0)

	// read the file into data buffer
	data := make([]byte, size)
	if _, err = file.Read(data); err != nil {
		return nil, fmt.Errorf("Error copying file %s into buffer: %v", path, err)
	}
	pe.Size = size

	if err := analyzePeFile(data, pe); err != nil {
		return nil, err
	}
	return pe, nil
}

// LoadPeBytes will take a PE file in the form of an in memory byte array and parse it
func LoadPeBytes(data []byte, name string) (*PeFile, error) {
	pe := &PeFile{Path: name}
	pe.Size = int64(len(data))
	if err := analyzePeFile(data, pe); err != nil {
		return nil, err
	}
	return pe, nil
}

// Sha256Sum will calcuate the sha256 of the supplied byte slice
func Sha256Sum(b []byte) (hexsum string) {
	sum := sha256.Sum256(b)
	hexsum = fmt.Sprintf("%x", sum)
	return
}

// analyzePeFile is the core parser for PE files
func analyzePeFile(data []byte, pe *PeFile) error {
	var err error

	pe.Sha256 = Sha256Sum(data)

	//create reader at offset 0
	r := bytes.NewReader(data)

	// read in DosHeader
	pe.DosHeader = &DosHeader{}
	if err = binary.Read(r, binary.LittleEndian, pe.DosHeader); err != nil {
		return fmt.Errorf("Error reading dosHeader from file %s: %v", pe.Path, err)
	}

	// move offset to CoffHeader
	if _, err = r.Seek(int64(pe.DosHeader.AddressExeHeader)+4, io.SeekStart); err != nil {
		return fmt.Errorf("Error seeking to coffHeader in file %s: %v", pe.Path, err)
	}

	// read CoffHeader into struct
	pe.CoffHeader = &CoffHeader{}
	if err = binary.Read(r, binary.LittleEndian, pe.CoffHeader); err != nil {
		return fmt.Errorf("Error reading coffHeader in file %s: %v", pe.Path, err)
	}

	// advance reader to start of OptionalHeader(32|32+)
	if _, err = r.Seek(int64(pe.DosHeader.AddressExeHeader)+4+int64(binary.Size(CoffHeader{})), io.SeekStart); err != nil {
		return fmt.Errorf("Error seeking to optionalHeader in file %s: %v", pe.Path, err)
	}

	// check if pe or pe+, read 2 bytes to get Magic then seek backward two bytes
	var _magic uint16
	if err := binary.Read(r, binary.LittleEndian, &_magic); err != nil {
		return fmt.Errorf("Error reading in magic")
	}

	// check magic, must be a PE or PE+
	if _magic == 0x10b {
		pe.PeType = Pe32
	} else if _magic == 0x20b {
		pe.PeType = Pe32p
	} else {
		return fmt.Errorf("invalid magic, must be PE or PE+")
	}

	if _, err = r.Seek(int64(pe.DosHeader.AddressExeHeader)+4+int64(binary.Size(CoffHeader{})), io.SeekStart); err != nil {
		return fmt.Errorf("Error seeking to optionalHeader in file %s: %v", pe.Path, err)
	}

	// copy the optional headers into their respective structs
	if pe.PeType == Pe32 {
		pe.OptionalHeader = &OptionalHeader32{}
		if err = binary.Read(r, binary.LittleEndian, pe.OptionalHeader); err != nil {
			return fmt.Errorf("Error reading optionalHeader32 in file %s: %v", pe.Path, err)
		}
	} else {
		pe.OptionalHeader = &OptionalHeader32P{}
		if err = binary.Read(r, binary.LittleEndian, pe.OptionalHeader); err != nil {
			return fmt.Errorf("Error reading optionalHeader32p in file %s: %v", pe.Path, err)
		}
	}

	//loop through each section and create Section structs
	sectionsStart := int64(0)
	if pe.PeType == Pe32 {
		sectionsStart = int64(pe.DosHeader.AddressExeHeader) + 4 + int64(binary.Size(CoffHeader{})) + int64(binary.Size(OptionalHeader32{}))
	} else {
		sectionsStart = int64(pe.DosHeader.AddressExeHeader) + 4 + int64(binary.Size(CoffHeader{})) + int64(binary.Size(OptionalHeader32P{}))
	}

	// section start will be the end of the data we keep for Raw headers

	// create slice to hold Section pointers
	pe.Sections = make([]*Section, int(pe.CoffHeader.NumberOfSections))
	pe.sectionHeaders = make([]*SectionHeader, int(pe.CoffHeader.NumberOfSections))

	// loop over each section and populate struct
	for i := 0; i < int(pe.CoffHeader.NumberOfSections); i++ {
		if _, err = r.Seek(sectionsStart+int64(binary.Size(SectionHeader{})*i), io.SeekStart); err != nil {
			return fmt.Errorf("Error seeking over sections in file %s: %v", pe.Path, err)
		}

		temp := SectionHeader{}
		if err = binary.Read(r, binary.LittleEndian, &temp); err != nil {
			return fmt.Errorf("Error reading section[%d] in file %s: %v", i, pe.Path, err)
		}
		pe.sectionHeaders[i] = &temp

		pe.Sections[i] = &Section{}
		pe.Sections[i].Name = string(temp.Name[:8])
		pe.Sections[i].VirtualSize = temp.VirtualSize
		pe.Sections[i].VirtualAddress = temp.VirtualAddress
		pe.Sections[i].Size = temp.Size
		pe.Sections[i].Offset = temp.Offset
		pe.Sections[i].PointerToRelocations = temp.PointerToRelocations
		pe.Sections[i].PointerToLineNumbers = temp.PointerToLineNumbers
		pe.Sections[i].NumberOfRelocations = temp.NumberOfRelocations
		pe.Sections[i].NumberOfLineNumbers = temp.NumberOfLineNumbers
		pe.Sections[i].Characteristics = temp.Characteristics

		if _, err = r.Seek(int64(temp.Offset), io.SeekStart); err != nil {
			return fmt.Errorf("Error seeking offset in section[%s] of file %s: %v", pe.Sections[i].Name, pe.Path, err)
		}
		raw := make([]byte, temp.Size)
		if _, err = r.Read(raw); err != nil {
			if err == io.EOF {
				pe.Sections[i].Raw = nil
				continue
			}

			return fmt.Errorf("Error reading bytes at offset[0x%x] in section[%s] of file %s: %v", pe.Sections[i].Offset, pe.Sections[i].Name, pe.Path, err)
		}
		pe.Sections[i].Raw = raw
		pe.Sections[i].Entropy = entropy(raw)
	}

	pe.RawHeaders = data[0:pe.Sections[0].Offset]
	pe.readImports()
	if err = pe.readExports(); err != nil {
		return err
	}
	pe.readApiset()

	return nil
}

func readString(b []byte) string {
	for i := 0; ; i++ {
		if b[i] == 0x0 {
			return string(b[0:i])
		}
	}
}

type ExportDirectory struct {
	ExportFlags          uint32
	TimeDateStamp        uint32
	MajorVersion         uint16
	MinorVersion         uint16
	NameRva              uint32
	OrdinalBase          uint32
	NumberOfFunctions    uint32
	NumberOfNamePointers uint32
	FunctionsRva         uint32
	NamesRva             uint32
	OrdinalsRva          uint32
}

type ExportAddressTable struct {
	ExportRva  uint32
	ForwardRva uint32
}

type Export struct {
	Name    string
	Ordinal uint16
	Rva     uint32
}

func (pe *PeFile) readExports() error {
	var exportsRva uint32
	if pe.PeType == Pe32 {
		exportsRva = pe.OptionalHeader.(*OptionalHeader32).DataDirectories[0].VirtualAddress
	} else {
		exportsRva = pe.OptionalHeader.(*OptionalHeader32P).DataDirectories[0].VirtualAddress
	}

	//get the section with exports data
	section := pe.getSectionByRva(exportsRva)

	if section == nil {
		return nil
	}

	// address in section where table resides
	tableOffset := exportsRva - section.VirtualAddress

	// create raw data reader
	r := bytes.NewReader(section.Raw)

	// seek to table offset
	if _, err := r.Seek(int64(tableOffset), io.SeekStart); err != nil {
		return fmt.Errorf("Error seeking to %s exportDirectory", pe.Path)
	}

	exportDirectory := ExportDirectory{}
	if err := binary.Read(r, binary.LittleEndian, &exportDirectory); err != nil {
		return fmt.Errorf("Error retrieving %s exportDirectory", pe.Path)
	}

	namesTableRVA := exportDirectory.NamesRva - section.VirtualAddress
	ordinalsTableRVA := exportDirectory.OrdinalsRva - section.VirtualAddress
	var ordinal uint16

	pe.ExportNameMap = make(map[string]*Export)
	pe.ExportOrdinalMap = make(map[int]*Export)

	for i := 0; i < int(exportDirectory.NumberOfNamePointers); i++ {
		// seek to index in names table
		if _, err := r.Seek(int64(namesTableRVA+uint32(i*4)), io.SeekStart); err != nil {
			return fmt.Errorf("Error seeking %s for exports names table: %v", pe.Path, err)
		}

		exportAddressTable := ExportAddressTable{}
		if err := binary.Read(r, binary.LittleEndian, &exportAddressTable); err != nil {
			return fmt.Errorf("Error retrieving %s exports address table: %v", pe.Path, err)
		}

		name := readString(section.Raw[exportAddressTable.ExportRva-section.VirtualAddress:])

		// get first Name in array
		ordinal = binary.LittleEndian.Uint16(section.Raw[ordinalsTableRVA+uint32(i*2) : ordinalsTableRVA+uint32(i*2)+2])

		// seek to ordinals table
		if _, err := r.Seek(int64(uint32(ordinal)*4+exportDirectory.FunctionsRva-section.VirtualAddress), io.SeekStart); err != nil {
			return fmt.Errorf("Error seeking %s ordinals table: %v", pe.Path, err)
		}

		// get ordinal address table
		exportOrdinalTable := ExportAddressTable{}
		if err := binary.Read(r, binary.LittleEndian, &exportOrdinalTable); err != nil {
			return fmt.Errorf("Error retrieving %s ordinals table: %v", pe.Path, err)
		}

		rva := exportOrdinalTable.ExportRva

		export := &Export{name, ordinal, rva}
		pe.Exports = append(pe.Exports, export)
		pe.ExportNameMap[name] = export
		pe.ExportOrdinalMap[int(ordinal)] = export

	}

	return nil
}

type ImportDirectory struct {
	ImportLookupTableRva  uint32
	TimeDataStamp         uint32
	ForwarderChain        uint32
	NameRva               uint32
	ImportAddressTableRva uint32
}

func (pe *PeFile) SetImportAddress(importInfo *ImportInfo, realAddr uint64) error {

	section := pe.getSectionByRva(importInfo.Offset)
	if section == nil {
		return fmt.Errorf("error setting address for %s.%s to %x, section not found", importInfo.DllName, importInfo.FuncName, importInfo.Offset)
	}

	// update the Raw bytes with the new address
	if pe.PeType == Pe32 {
		buf := make([]byte, 4)
		binary.LittleEndian.PutUint32(buf, uint32(realAddr))
		thunkAddress := importInfo.Offset - section.VirtualAddress
		for i := 0; i < 4; i++ {
			section.Raw[int(thunkAddress)+i] = buf[i]
		}
	} else {
		buf := make([]byte, 8)
		binary.LittleEndian.PutUint64(buf, realAddr)
		thunkAddress := uint16(importInfo.Offset) & 0xfff
		for i := 0; i < 8; i++ {
			section.Raw[int(thunkAddress)+i] = buf[i]
		}
	}

	return nil
}

func (pe *PeFile) ImportedDlls() []string {
	var dllNames []string
	present := make(map[string]bool)
	for _, importInfo := range pe.Imports {
		if present[importInfo.DllName] {
			continue
		}
		present[importInfo.DllName] = true
		dllNames = append(dllNames, importInfo.DllName)
	}
	return dllNames
}

func (pe *PeFile) getSectionByRva(rva uint32) *Section {
	var section *Section
	for i := 0; i < int(pe.CoffHeader.NumberOfSections); i++ {
		if rva >= pe.Sections[i].VirtualAddress && rva < pe.Sections[i].VirtualAddress+pe.Sections[i].Size {
			section = pe.Sections[i]
		}
	}
	return section
}

func (pe *PeFile) readImports() {

	var importsRva uint32
	if pe.PeType == Pe32 {
		importsRva = pe.OptionalHeader.(*OptionalHeader32).DataDirectories[1].VirtualAddress
	} else {
		importsRva = pe.OptionalHeader.(*OptionalHeader32P).DataDirectories[1].VirtualAddress
	}

	//get the section with imports data
	section := pe.getSectionByRva(importsRva)

	if section == nil {
		return
	}

	// address in section where table resides
	tableOffset := importsRva - section.VirtualAddress

	// create raw data reader
	r := bytes.NewReader(section.Raw)

	pe.Imports = make([]*ImportInfo, 0, 100)

	//loop over each dll import
	for i := tableOffset; ; i += uint32(binary.Size(ImportDirectory{})) {
		section = pe.getSectionByRva(importsRva)
		if _, err := r.Seek(int64(i), io.SeekStart); err != nil {
			log.Fatal(err)
		}

		importDirectory := ImportDirectory{}
		if err := binary.Read(r, binary.LittleEndian, &importDirectory); err != nil {
			log.Fatal(err)
		}
		// end of "array" is an empty struct, import lookup table is the first
		// element in the struct so it will be a quick check for 0
		if importDirectory.NameRva == 0 {
			break
		}

		requiredSection := pe.getSectionByRva(importDirectory.NameRva)
		name := strings.ToLower(readString(requiredSection.Raw[importDirectory.NameRva-requiredSection.VirtualAddress:]))

		if pe.PeType == Pe32 {
			var thunk1 uint32
			section = pe.getSectionByRva(importDirectory.ImportAddressTableRva)
			thunk2 := importDirectory.ImportAddressTableRva
			importThunk := 0

			// ImportLookupTableRva and ImportAddressTableRva are identical until the binary is actually loaded
			// there are cases where the tableRva is 0 however, and the address table should be used
			if importDirectory.ImportLookupTableRva > section.VirtualAddress {
				importThunk = int(importDirectory.ImportLookupTableRva - section.VirtualAddress)
			} else {
				importThunk = int(importDirectory.ImportAddressTableRva - section.VirtualAddress)
			}
			for ; ; importThunk += 4 {

				if importThunk+4 > len(section.Raw) {
					break
				}

				// get first thunk
				if thunk1 = binary.LittleEndian.Uint32(section.Raw[importThunk : importThunk+4]); thunk1 == 0 {
					break
				}
				//This would get the ordinal bit to check how to import
				doOrdinal := thunk1&0x80000000 > 0
				if doOrdinal {
					// parse by ordinal
					funcName := ""
					ord := uint16(thunk1 & 0xffff)
					pe.Imports = append(pe.Imports, &ImportInfo{name, funcName, thunk2, ord})
					thunk2 += 4
				} else {
					// might be in a different section
					if sec := pe.getSectionByRva(thunk1 + 2); sec != nil {
						v := thunk1 + 2 - sec.VirtualAddress
						funcName := readString(sec.Raw[v:])
						pe.Imports = append(pe.Imports, &ImportInfo{name, funcName, thunk2, 0})
						thunk2 += 4
					}
				}

			}

		} else {
			var thunk1 uint64
			var thunk2 uint64 = uint64(importDirectory.ImportAddressTableRva - section.VirtualAddress)

			importThunk := 0
			if importDirectory.ImportLookupTableRva > section.VirtualAddress {
				importThunk = int(importDirectory.ImportLookupTableRva - section.VirtualAddress)
			} else {
				importThunk = int(importDirectory.ImportAddressTableRva - section.VirtualAddress)
			}

			for ; ; importThunk += 4 {
				// get first thunk
				if thunk1 = binary.LittleEndian.Uint64(section.Raw[uint32(importThunk) : uint32(importThunk)+8]); thunk1 == 0 {
					break
				}
				if thunk1&0x8000000000000000 > 0 {
					// parse by ordinal
					funcName := ""
					ord := uint16(thunk1 & 0xffff)
					pe.Imports = append(pe.Imports, &ImportInfo{name, funcName, uint32(thunk2), ord})
					thunk2 += 8

				} else {
					// might be in a different section
					if sec := pe.getSectionByRva(uint32(thunk1) + 2); sec != nil {
						v := uint32(thunk1) + 2 - sec.VirtualAddress
						funcName := readString(sec.Raw[v:])
						pe.Imports = append(pe.Imports, &ImportInfo{name, funcName, uint32(thunk2), 0})
						thunk2 += 8
					}
				}
			}
		}
	}
}

type ApisetHeader63 struct {
	Version         uint32
	Size            uint32
	Sealed          uint32
	NumberOfApisets uint32
	NamesOffset     uint32
	TableOffset     uint32
	Multiplier      uint32
}

type ApisetHeader6 struct {
	Version int32
	Count   int32
}

type ApisetNameEntry struct {
	Sealed        uint32
	Offset        uint32
	Ignored       uint32
	Size          uint32
	HostOffset    uint32
	NumberOfHosts uint32
}

type ApisetNameEntry2 struct {
	NameOffset int32
	NameLength int32
	DataOffset int32
}

type ValuesArray2 struct {
	Count uint32
}

type ValuesEntry2 struct {
	NameOffset  int32
	NameLength  int32
	ValueOffset int32
	ValueLength int32
}

type ApisetValueEntry struct {
	Ignored     uint32
	NameOffset  uint32
	NameLength  uint32
	ValueOffset uint32
	ValueLength uint32
}

func utf16ToString(b []byte) string {
	utf := make([]uint16, (len(b)+(2-1))/2)
	for i := 0; i+(2-1) < len(b); i += 2 {
		utf[i/2] = binary.LittleEndian.Uint16(b[i:])
	}
	if len(b)/2 < len(utf) {
		utf[len(utf)-1] = utf8.RuneError
	}
	return string(utf16.Decode(utf))
}

func (pe *PeFile) readApiset() {

	var section Section
	sectionFound := false
	for i := 0; i < int(pe.CoffHeader.NumberOfSections); i++ {
		if pe.Sections[i].Name == ".apiset\u0000" {
			section = *pe.Sections[i]
			sectionFound = true
			break
		}
	}

	if sectionFound == false {
		return
	}

	// create raw data reader
	r := bytes.NewReader(section.Raw)

	version := binary.LittleEndian.Uint32(section.Raw[0:4])

	pe.Apisets = make(map[string][]string)

	if version >= 0x3 {
		header := ApisetHeader63{}
		if err := binary.Read(r, binary.LittleEndian, &header); err != nil {
			log.Fatal(err)
		}
		for i := 0; i < int(header.NumberOfApisets); i++ {
			if _, err := r.Seek(int64(int(header.NamesOffset)+binary.Size(ApisetNameEntry{})*i), io.SeekStart); err != nil {
				log.Fatal(err)
			}

			entry := ApisetNameEntry{}
			if err := binary.Read(r, binary.LittleEndian, &entry); err != nil {
				log.Fatal(err)
			}

			name := utf16ToString(section.Raw[entry.Offset : entry.Offset+entry.Size])
			//name += "-0.dll"

			pe.Apisets[name] = make([]string, 0, 2)
			for i := 0; i < int(entry.NumberOfHosts); i++ {

				if _, err := r.Seek(int64(entry.HostOffset+uint32(binary.Size(ApisetValueEntry{})*i)), io.SeekStart); err != nil {
					log.Fatal(err)
				}

				valueEntry := ApisetValueEntry{}
				if err := binary.Read(r, binary.LittleEndian, &valueEntry); err != nil {
					log.Fatal(err)
				}

				value := utf16ToString(section.Raw[valueEntry.ValueOffset : valueEntry.ValueOffset+valueEntry.ValueLength])
				pe.Apisets[name] = append(pe.Apisets[name], value)
			}
		}
	} else {
		header := ApisetHeader6{}
		if err := binary.Read(r, binary.LittleEndian, &header); err != nil {
			log.Fatal(err)
		}

		loc := binary.Size(ApisetHeader6{})
		// loop over the array of name entries
		for i := 0; i < int(header.Count); i++ {
			//capture each element in the array
			entry := ApisetNameEntry2{}
			if err := binary.Read(r, binary.LittleEndian, &entry); err != nil {
				log.Fatal(err)
			}

			// update loc cursor, we'll need to seek back to this after getting the value
			loc += binary.Size(ApisetNameEntry2{})

			// get api set name and values array pointer
			name := strings.ToLower(utf16ToString(section.Raw[entry.NameOffset : entry.NameOffset+int32(entry.NameLength)]))
			name = name[0 : len(name)-2]
			valuesCount := binary.LittleEndian.Uint32(section.Raw[entry.DataOffset : entry.DataOffset+4])

			if valuesCount == 0 {
				continue
			}

			// seek to values head
			if _, err := r.Seek(int64(entry.DataOffset)+4, io.SeekStart); err != nil {
				log.Fatal(err)
			}

			pe.Apisets[name] = make([]string, 0, 2)
			for j := 0; j < int(valuesCount); j++ {
				valueEntry := ValuesEntry2{}
				if err := binary.Read(r, binary.LittleEndian, &valueEntry); err != nil {
					log.Fatal(err)
				}
				dllname := utf16ToString(section.Raw[valueEntry.ValueOffset : valueEntry.ValueOffset+int32(valueEntry.ValueLength)])
				pe.Apisets[name] = append(pe.Apisets[name], dllname)
			}

			//return back to loc
			if _, err := r.Seek(int64(loc), io.SeekStart); err != nil {
				log.Fatal(err)
			}
		}
	}
}

type RelocationBlock struct {
	PageRva uint32
	Size    uint32
}

func min(a, b int) int {
	if a < b {
		return a
	} else {
		return b
	}
}

func (pe *PeFile) section(index int) *Section {
	var rva uint32

	if pe.PeType == Pe32 {
		if index < min(16, int(pe.OptionalHeader.(*OptionalHeader32).NumberOfRvaAndSizes)) {
			rva = pe.OptionalHeader.(*OptionalHeader32).DataDirectories[index].VirtualAddress
		} else {
			return nil
		}
	} else {
		if index < min(16, int(pe.OptionalHeader.(*OptionalHeader32P).NumberOfRvaAndSizes)) {
			rva = pe.OptionalHeader.(*OptionalHeader32P).DataDirectories[index].VirtualAddress
		} else {
			return nil
		}
	}

	for i := 0; i < int(pe.CoffHeader.NumberOfSections); i++ {
		if rva >= pe.Sections[i].VirtualAddress && rva < pe.Sections[i].VirtualAddress+pe.Sections[i].Size {
			return pe.Sections[i]
		}
	}

	return nil
}

func (pe *PeFile) sectionByRva(rva uint32) *Section {
	for i := 0; i < int(pe.CoffHeader.NumberOfSections); i++ {
		if rva >= pe.Sections[i].VirtualAddress && rva < pe.Sections[i].VirtualAddress+pe.Sections[i].Size {
			return pe.Sections[i]
		}
	}
	return nil
}

func (pe *PeFile) updateRelocations() error {

	section := pe.section(5)
	if section == nil {
		return fmt.Errorf("section not found, index 5")
	}
	// create raw data reader
	r := bytes.NewReader(section.Raw)

	delta := pe.oldImageBase - pe.ImageBase()

	for {
		block := RelocationBlock{}
		if err := binary.Read(r, binary.LittleEndian, &block); err != nil {
			log.Fatal(err)
		}

		// check if at the end of the reloc blocks
		if block.PageRva == 0 {
			break
		}

		for i := 0; i < int(block.Size-8); i += 2 {
			var temp uint16
			if err := binary.Read(r, binary.LittleEndian, &temp); err != nil {
				log.Fatal(err)
			}

			temp &= 0x0fff
			curSection := pe.sectionByRva(block.PageRva)
			relocRva := block.PageRva + uint32(temp) - curSection.VirtualAddress

			// get bytes at location
			// then subtract delta
			// then update bytes in section with result
			if pe.PeType == Pe32 {
				updated := binary.LittleEndian.Uint32(curSection.Raw[relocRva:relocRva+4]) - uint32(delta)
				buf := make([]byte, 4)
				binary.LittleEndian.PutUint32(buf, uint32(updated))
				for i := 0; i < 4; i++ {
					curSection.Raw[int(relocRva)+i] = buf[i]
				}
			} else {
				updated := binary.LittleEndian.Uint64(curSection.Raw[relocRva:relocRva+8]) - delta
				buf := make([]byte, 8)
				binary.LittleEndian.PutUint32(buf, uint32(updated))
				for i := 0; i < 8; i++ {
					curSection.Raw[int(relocRva)+i] = buf[i]
				}
			}
		}
	}

	return nil
}

func (pe *PeFile) ApiSetLookup(name string) string {
	realDll := name

	if strings.Compare(name[:4], "api-") == 0 {
		apisetLen := len(pe.Apisets[name[0:len(name)-6]]) - 1
		if apisetLen >= 0 {
			realDll = pe.Apisets[name[0:len(name)-6]][apisetLen]
		}
	}

	return realDll
}
