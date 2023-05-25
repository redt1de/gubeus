package process

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows API functions
var (
	modKernel32                  = syscall.NewLazyDLL("kernel32.dll")
	procCloseHandle              = modKernel32.NewProc("CloseHandle")
	procCreateToolhelp32Snapshot = modKernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32First           = modKernel32.NewProc("Process32FirstW")
	procProcess32Next            = modKernel32.NewProc("Process32NextW")
)

// Some constants from the Windows API
const (
	ERROR_NO_MORE_FILES               = 0x12
	MAX_PATH                          = 260
	PROCESS_ALL_ACCESS                = 0x1F0FFF
	PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
	PROCESS_DUP_HANDLE                = 0x0040
	PROCESS_QUERY_INFORMATION         = 0x0400
)

// PROCESSENTRY32 is the Windows API structure that contains a process's
// information.
type PROCESSENTRY32 struct {
	Size              uint32
	CntUsage          uint32
	ProcessID         uint32
	DefaultHeapID     uintptr
	ModuleID          uint32
	CntThreads        uint32
	ParentProcessID   uint32
	PriorityClassBase int32
	Flags             uint32
	ExeFile           [MAX_PATH]uint16
}

// WindowsProcess is an implementation of Process for Windows.
type WindowsProcess struct {
	pid  int
	ppid int
	exe  string
}

func GetProcessByNameWin(nme string) (*windows.Handle, error) {
	// uintNme,_ := syscall.UTF16FromString(nme)
	handle, _, _ := procCreateToolhelp32Snapshot.Call(
		0x00000002,
		0)
	if handle < 0 {
		return nil, syscall.GetLastError()
	}
	defer procCloseHandle.Call(handle)

	var entry PROCESSENTRY32

	entry.Size = uint32(unsafe.Sizeof(entry))
	ret, _, _ := procProcess32First.Call(handle, uintptr(unsafe.Pointer(&entry)))
	if ret == 0 {
		return nil, fmt.Errorf("Error retrieving process info.")
	}

	for {
		exe := syscall.UTF16ToString(entry.ExeFile[:])
		if strings.Contains(exe, nme) {
			handle, err := windows.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, true, entry.ProcessID) // use minimum required privs to get the handle, PROCESS_ALL_ACCESS is excessive and will result in access denied most of the time
			// handle, err := windows.OpenProcess(PROCESS_ALL_ACCESS, true, entry.ProcessID)
			if err != nil {
				return nil, err
			}
			return &handle, nil
		}

		ret, _, _ := procProcess32Next.Call(handle, uintptr(unsafe.Pointer(&entry)))
		if ret == 0 {
			break
		}
	}

	return nil, nil
}

func GetProcessByNameSys(nme string) (*syscall.Handle, error) {
	// uintNme,_ := syscall.UTF16FromString(nme)
	handle, _, _ := procCreateToolhelp32Snapshot.Call(
		0x00000002,
		0)
	if handle < 0 {
		return nil, syscall.GetLastError()
	}
	defer procCloseHandle.Call(handle)

	var entry PROCESSENTRY32

	entry.Size = uint32(unsafe.Sizeof(entry))
	ret, _, _ := procProcess32First.Call(handle, uintptr(unsafe.Pointer(&entry)))
	if ret == 0 {
		return nil, fmt.Errorf("Error retrieving process info.")
	}

	for {
		exe := syscall.UTF16ToString(entry.ExeFile[:])
		if strings.Contains(exe, nme) {
			handle, err := syscall.OpenProcess(PROCESS_ALL_ACCESS, true, entry.ProcessID)
			// handle, err := windows.OpenProcess(PROCESS_ALL_ACCESS, true, entry.ProcessID)
			if err != nil {
				return nil, err
			}
			return &handle, nil
		}

		ret, _, _ := procProcess32Next.Call(handle, uintptr(unsafe.Pointer(&entry)))
		if ret == 0 {
			break
		}
	}

	return nil, nil
}
