package lsa

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	DebugLSA bool
	secur32  = windows.NewLazySystemDLL("Secur32.dll")
	advapi32 = windows.NewLazySystemDLL("Advapi32.dll")
)

// NTSTATUS LsaRegisterLogonProcess(
// [in] PLSA_STRING LogonProcessName,
// [out] PHANDLE LsaHandle,
// [out] PLSA_OPERATIONAL_MODE SecurityMode
// );
func LsaRegisterLogonProcess(LogonProcessName *LSA_STRING_IN, LsaHandle *syscall.Handle, SecurityMode *uint64) error {
	var procLsaRegisterLogonProcess = secur32.NewProc("LsaRegisterLogonProcess")
	r1, r2, le := procLsaRegisterLogonProcess.Call(uintptr(unsafe.Pointer(LogonProcessName)), uintptr(unsafe.Pointer(LsaHandle)), uintptr(unsafe.Pointer(SecurityMode)))
	syslast := syscall.GetLastError()
	if DebugLSA {
		fmt.Println("---------- LsaRegisterLogonProcess ----------")
		fmt.Println("r1:", r1)
		fmt.Println("r2:", r2)
		fmt.Println("le:", le)
		fmt.Println("lastError:", syslast)
	}
	return syslast
}

// NTSTATUS LsaEnumerateLogonSessions(
// [out] PULONG LogonSessionCount,
// [out] PLUID  *LogonSessionList
// );

func LsaEnumerateLogonSessions(sessionCount *uint32, sessions *uintptr) error {
	var procLsaEnumerateLogonSessions = secur32.NewProc("LsaEnumerateLogonSessions")
	r1, r2, le := procLsaEnumerateLogonSessions.Call(uintptr(unsafe.Pointer(sessionCount)), uintptr(unsafe.Pointer(sessions)), 0)
	syslast := syscall.GetLastError()
	if DebugLSA {
		fmt.Println("---------- LsaEnumerateLogonSessions ----------")
		fmt.Println("r1:", r1)
		fmt.Println("r2:", r2)
		fmt.Println("le:", le)
		fmt.Println("lastError:", syslast)
	}
	return syslast
}

// NTSTATUS LsaGetLogonSessionData(
// [in]  PLUID LogonId,
// [out] PSECURITY_LOGON_SESSION_DATA *ppLogonSessionData
// );

func LsaGetLogonSessionData(luid *LUID, sessionData **SECURITY_LOGON_SESSION_DATA) error {
	var procLsaGetLogonSessionData = secur32.NewProc("LsaGetLogonSessionData")
	r1, r2, le := procLsaGetLogonSessionData.Call(uintptr(unsafe.Pointer(luid)), uintptr(unsafe.Pointer(sessionData)), 0)
	syslast := syscall.GetLastError()
	if DebugLSA && 1 == 2 {
		fmt.Println("---------- LsaGetLogonSessionData ----------")
		fmt.Println("r1:", r1)
		fmt.Println("r2:", r2)
		fmt.Println("le:", le)
		fmt.Println("lastError:", syslast)
	}
	return syslast
}

// NTSTATUS LsaFreeReturnBuffer([in] PVOID Buffer);

func LsaFreeReturnBuffer(buffer uintptr) error {
	var procLsaFreeReturnBuffer = secur32.NewProc("LsaFreeReturnBuffer")
	r1, r2, le := procLsaFreeReturnBuffer.Call(buffer, 0, 0)
	syslast := syscall.GetLastError()
	if DebugLSA {
		fmt.Println("---------- LsaFreeReturnBuffer ----------")
		fmt.Println("r1:", r1)
		fmt.Println("r2:", r2)
		fmt.Println("le:", le)
		fmt.Println("lastError:", syslast)
	}
	return syslast
}

// NTSTATUS LsaLookupAuthenticationPackage(
// [in] HANDLE LsaHandle,
// [in] PLSA_STRING PackageName,
// [out] PULONG AuthenticationPackage
// );

func LsaLookupAuthenticationPackage(LsaHandle syscall.Handle, PackageName *LSA_STRING_IN, AuthenticationPackage *int) error {
	var procLsaLookupAuthenticationPackage = secur32.NewProc("LsaLookupAuthenticationPackage")
	r1, r2, le := procLsaLookupAuthenticationPackage.Call(uintptr(LsaHandle), uintptr(unsafe.Pointer(PackageName)), uintptr(unsafe.Pointer(AuthenticationPackage)))
	syslast := syscall.GetLastError()
	if DebugLSA {
		fmt.Println("---------- LsaLookupAuthenticationPackage ----------")
		fmt.Println("r1:", r1)
		fmt.Println("r2:", r2)
		fmt.Println("le:", le)
		fmt.Println("lastError:", syslast)
		fmt.Println(LsaNtStatusToWinError(r1))
	}
	return syslast
}

// NTSTATUS LsaCallAuthenticationPackage(
// [in]  HANDLE    LsaHandle,
// [in]  ULONG     AuthenticationPackage,
// [in]  PVOID     ProtocolSubmitBuffer,
// [in]  ULONG     SubmitBufferLength,
// [out] PVOID     *ProtocolReturnBuffer,
// [out] PULONG    ReturnBufferLength,
// [out] PNTSTATUS ProtocolStatus
// );
// func LsaCallAuthenticationPackageStruct(LsaHandle syscall.Handle, AuthenticationPackage int, reqBuff *KERB_QUERY_TKT_CACHE_REQUEST, reqlen int, retbuf **KERB_QUERY_TKT_CACHE_RESPONSE, retbuflen *int, status *int) error {
// 	var procLsaCallAuthenticationPackage = secur32.NewProc("LsaCallAuthenticationPackage")
// 	r1, r2, le := procLsaCallAuthenticationPackage.Call(uintptr(LsaHandle), uintptr(AuthenticationPackage), uintptr(unsafe.Pointer(reqBuff)), uintptr(reqlen), uintptr(unsafe.Pointer(&retbuf)), uintptr(unsafe.Pointer(retbuflen)), uintptr(unsafe.Pointer(status)))
// 	syslast := syscall.GetLastError()
// 	if DebugLSA || 1 == 2 {
// 		fmt.Println("---------- LsaCallAuthenticationPackage ----------")
// 		fmt.Println("r1:", r1)
// 		fmt.Println("r2:", r2)
// 		fmt.Println("le:", le)
// 		fmt.Println("lastError:", syslast)
// 		fmt.Println(LsaNtStatusToWinError(r2))
// 	}
// 	return syslast
// }

// func LsaCallAuthenticationPackage(LsaHandle syscall.Handle, AuthenticationPackage int, reqBuff *KERB_QUERY_TKT_CACHE_REQUEST, reqlen int, retbuf uintptr, retbuflen *int, status *int) error {
// 	var procLsaCallAuthenticationPackage = secur32.NewProc("LsaCallAuthenticationPackage")
// 	// r1, r2, le := procLsaCallAuthenticationPackage.Call(uintptr(LsaHandle), uintptr(AuthenticationPackage), uintptr(unsafe.Pointer(reqBuff)), uintptr(reqlen), uintptr(unsafe.Pointer(&retbuf)), uintptr(unsafe.Pointer(retbuflen)), uintptr(unsafe.Pointer(status)))
// 	r1, r2, le := procLsaCallAuthenticationPackage.Call(uintptr(LsaHandle), uintptr(AuthenticationPackage), uintptr(unsafe.Pointer(&reqBuff)), uintptr(int(unsafe.Sizeof(reqBuff))), retbuf, uintptr(unsafe.Pointer(&retBufSize)), uintptr(unsafe.Pointer(&status)))

// 	syslast := syscall.GetLastError()
// 	if DebugLSA || 1 == 2 {
// 		fmt.Println("---------- LsaCallAuthenticationPackage ----------")
// 		fmt.Println("r1:", r1)
// 		fmt.Println("r2:", r2)
// 		fmt.Println("le:", le)
// 		fmt.Println("lastError:", syslast)
// 		fmt.Println(LsaNtStatusToWinError(r2))
// 	}
// 	return syslast
// }

// ULONG LsaNtStatusToWinError([in] NTSTATUS Status);

func LsaNtStatusToWinError(ntstatus uintptr) error {
	var procLsaNtStatusToWinError = advapi32.NewProc("LsaNtStatusToWinError")

	r0, _, errno := syscall.Syscall(procLsaNtStatusToWinError.Addr(), 1, ntstatus, 0, 0)

	switch errno {
	case windows.ERROR_SUCCESS:
		if r0 == 0 {
			return nil
		}
	case windows.ERROR_MR_MID_NOT_FOUND:
		return fmt.Errorf("Unknown LSA NTSTATUS code %x", ntstatus)
	}
	return syscall.Errno(r0)
}
