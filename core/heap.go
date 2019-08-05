package core

import "fmt"
import "binee/util"

type HeapEntry struct {
	Address uint64
	Size    uint64
}

type HeapManager struct {
	base uint64
	heap []*HeapEntry
}

func NewHeap(base uint64) *HeapManager {
	return &HeapManager{
		base,
		make([]*HeapEntry, 0, 100),
	}
}

// Size returns the size of a particular heap entry, returns 0 of heap entry is not found
func (self *HeapManager) Size(addr uint64) uint64 {
	size := uint64(0)
	for i := 0; i < len(self.heap); i++ {
		if self.heap[i].Address == addr {
			size = self.heap[i].Size
			break
		}
	}
	return size
}

//Scans for a particular heap allocated with Malloc. Returns the index where
//this heap exists in the heap data structure
func (self *HeapManager) scan(size uint64) int {
	heaplen := len(self.heap)

	if heaplen == 0 {
		return -1
	}

	for i, entry := range self.heap[:heaplen-1] {
		nextEntry := self.heap[i+1]
		gap := nextEntry.Address - (entry.Address + entry.Size)
		if gap >= size+0x20 {
			return i + 1
		}
	}
	return -1
}

func (self *HeapManager) nextAddress() uint64 {
    heaplen := len(self.heap)
    return self.heap[heaplen-1].Address + self.heap[heaplen-1].Size + 0x10
}

func (self *HeapManager) naiveMalloc(size uint64) uint64 {
	heaplen := len(self.heap)

	if heaplen == 0 {
		self.heap = append(self.heap, &HeapEntry{self.base, size})
		return self.base
	} else {
        nxt := self.nextAddress()
		self.heap = append(self.heap, &HeapEntry{nxt, size})
		return nxt
	}
}

// insert without looking
func (self *HeapManager) insertHeap(index int, addr, size uint64) {
    insertEntry := &HeapEntry{addr, size}
    self.heap = append(self.heap, &HeapEntry{0, 0})
    copy(self.heap[index+1:], self.heap[index:])
    self.heap[index] = insertEntry
}

func (self *HeapManager) Malloc(size uint64) uint64 {
	index := self.scan(size)
	if index == -1 {
		return self.naiveMalloc(size)
	}
    nxt := self.heap[index-1].Address + self.heap[index-1].Size + 0x10
    self.insertHeap(index, nxt, size)
	return nxt
}

// preferEndMalloc: malloc at the end, rounded up to the
// nearest multiple of align
func (self *HeapManager) preferEndMalloc(align, size uint64) uint64 {
    nxt := self.nextAddress()

    // if align is a power of 2, then we could use util.RoundUp(nxt, align-1)
    // since this function is more generic, we can't do that
    nxt += (align - (nxt%align)) % align
    self.heap = append(self.heap, &HeapEntry{nxt, size})
    return nxt
}

// preferMalloc: try to malloc at the given address, rounded up to the
// nearest multiple of align
// if it doesn't fit, keep adding align until it does
func (self *HeapManager) preferMalloc(addr, align, size uint64) uint64 {
    // if the address is 0, then put it at the end
    if addr == 0 {
        return self.preferEndMalloc(align, size)
    }

    // round up the address (if align is a power of 2, then we could use util.RoundUp)
    addr += (align - (addr % align)) % align

    heaplen := len(self.heap)

    // look through the heaps
    for i, heap := range self.heap[:heaplen-1] {
        heapNext := self.heap[i+1]
        for {
            // if the preferred address (+size) is bigger than the next heap
            if addr+size >= heapNext.Address {
                // then break (i.e., try to fit it after the next heap)
                break
            }

            // otherwise, keep adding align value
            if heap.Address + heap.Size < addr && addr + size < heapNext.Address {
                self.insertHeap(i+1, addr, size)
                return addr
            }
            addr += align
        }
    }

    // if we get to the end, then just put it at the end
    return self.preferEndMalloc(align, size)
}

// returns a given heap block given some address
func (self *HeapManager) getHeapBlock(addr uint64) (*HeapEntry, error) {
	for i := 0; i < len(self.heap); i++ {
		if self.heap[i].Address == addr {
			return self.heap[i], nil
		}
	}
	return nil, fmt.Errorf("allocated region not found: 0x%x", addr)
}

// given a previously allocated memory block, copy contents to new block and increase size
func (self *HeapManager) ReAlloc(addr uint64, newsize uint64) (uint64, uint64) {
	heap, err := self.getHeapBlock(addr)
	if err != nil {
		return addr, 0
	}

	if newsize <= heap.Size {
		return addr, 0
	}

	// create new heap space
	newheapaddr := self.Malloc(newsize)

	//return new address
	return newheapaddr, heap.Size
}

func (self *HeapManager) Free(addr uint64) uint64 {
	for index, element := range self.heap {
		if element.Address == addr {
			self.heap = append(self.heap[:index], self.heap[index+1:]...)
			return 1
		}
	}
	return 0
}

// Map (length) bytes preferably at (start)
// this will map memory aligned to 4k boundaries,
// and round up size to 4k multiples
func (self *HeapManager) MMap(start, size uint64) (uint64, uint64) {
    // useful to declare this as it's used several times
    // page boundary at 0x1000
    pageMask := uint64(0xfff)

    // size can't be 0
    if size == 0 {
        return uint64(0), uint64(0)
    }

    // Round size
    size = util.RoundUp(size, pageMask)

    // Round start
    start = util.RoundUp(start, pageMask)

    // malloc
    allocAddr := self.preferMalloc(start, pageMask+1, size)

    return allocAddr, size
}


