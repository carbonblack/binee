package core_test

import (
	"testing"

	"github.com/carbonblack/binee/core"
)

func TestHeapFree(t *testing.T) {
	// copied from windows/loader.go
	heapAddress := uint64(0xffe792a000)
	heap := core.NewHeap(heapAddress)

	// Malloc
	ptr1 := heap.Malloc(100)
	ptr2 := heap.Malloc(1000)
	ptr3 := heap.Malloc(100)

	// Free
	heap.Free(ptr2)

	// Re-malloc
	ptr4 := heap.Malloc(100)

	// Tests
	if ptr2 < ptr1 {
		t.Errorf("Hard fail.  Malloc isn't working correctly: 0x%x should be LESS than 0x%x\n", ptr1, ptr2)
	}

	if ptr3 < ptr4 {
		t.Errorf("Didn't malloc/free correctly: 0x%x should be LESS than 0x%x\n", ptr4, ptr3)
	}

	if ptr4 != ptr2 {
		t.Errorf("Soft fail.  Ideally, these pointers should be the same: 0x%x and 0x%x", ptr2, ptr4)
	}

}
