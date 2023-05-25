package heap

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/windows"
)

// TODO: needs to callz	procHeapFree = modkernel32.NewProc("HeapFree")

const (
	errnoERROR_IO_PENDING = 997
)

var (
	errERROR_IO_PENDING error = syscall.Errno(errnoERROR_IO_PENDING)
)

var (
	modkernel32 = windows.NewLazySystemDLL("kernel32.dll")
)

func GetProcessHeap() (procHeap windows.Handle, err error) {
	var procGetProcessHeap = modkernel32.NewProc("GetProcessHeap")
	r0, _, e1 := syscall.Syscall(procGetProcessHeap.Addr(), 0, 0, 0, 0)
	procHeap = windows.Handle(r0)
	if procHeap == 0 {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func HeapAlloc(hHeap windows.Handle, dwFlags uint32, dwBytes uintptr) (lpMem uintptr, err error) {
	var procHeapAlloc = modkernel32.NewProc("HeapAlloc")
	r0, _, e1 := syscall.Syscall(procHeapAlloc.Addr(), 3, uintptr(hHeap), uintptr(dwFlags), uintptr(dwBytes))
	lpMem = r0
	if lpMem == 0 {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func CopyMemory(dest uintptr, src uintptr, length uint32) {
	var procCopyMemory = modkernel32.NewProc("RtlMoveMemory")
	r1, r2, le := procCopyMemory.Call(dest, src, uintptr(length))
	syslast := syscall.GetLastError()
	if 1 == 2 {
		fmt.Println("---------- CopyMemmory ----------")
		fmt.Println("r1:", r1)
		fmt.Println("r2:", r2)
		fmt.Println("le:", le)
		fmt.Println("lastError:", syslast)
		// fmt.Println(lsa.LsaNtStatusToWinError(r1))
	}
}

func HeapFree(hHeap windows.Handle, dwFlags uint32, lpMem uintptr) (err error) {
	var procHeapFree = modkernel32.NewProc("HeapFree")
	r1, _, e1 := syscall.Syscall(procHeapFree.Addr(), 3, uintptr(hHeap), uintptr(dwFlags), uintptr(lpMem))
	if r1 == 0 {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func errnoErr(e syscall.Errno) error {
	switch e {
	case 0:
		return nil
	case errnoERROR_IO_PENDING:
		return errERROR_IO_PENDING
	}
	// TODO: add more here, after collecting data on the common
	// error values see on Windows. (perhaps when running
	// all.bat?)
	return e
}
