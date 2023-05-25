package lsa

import (
	"time"

	"golang.org/x/sys/windows"
)

const (
	// Not explicitly defined in LSA, but according to
	// https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-logonsession,
	// LogonType=0 is "Used only by the System account."
	LogonTypeSystem LogonType = iota
	_                         // LogonType=1 is not used
	LogonTypeInteractive
	LogonTypeNetwork
	LogonTypeBatch
	LogonTypeService
	LogonTypeProxy
	LogonTypeUnlock
	LogonTypeNetworkCleartext
	LogonTypeNewCredentials
	LogonTypeRemoteInteractive
	LogonTypeCachedInteractive
	LogonTypeCachedRemoteInteractive
	LogonTypeCachedUnlock
)

type LogonType uint32

type LogonSessionData struct {
	UserName                                   string
	LogonDomain                                string
	AuthenticationPackage                      string
	LogonType                                  LogonType
	Session                                    uint32
	Sid                                        *windows.SID
	LogonTime                                  time.Time
	LogonServer                                string
	DnsDomainName                              string
	Upn                                        string
	UserFlags                                  uint32
	LastSuccessfulLogon                        time.Time
	LastFailedLogon                            time.Time
	FailedAttemptCountSinceLastSuccessfulLogon uint32
	LogonScript                                string
	ProfilePath                                string
	HomeDirectory                              string
	HomeDirectoryDrive                         string
	LogoffTime                                 time.Time
	KickOffTime                                time.Time
	PasswordLastSet                            time.Time
	PasswordCanChange                          time.Time
	PasswordMustChange                         time.Time
}

type LSA_UNICODE_STRING struct {
	Length        uint16
	MaximumLength uint16
	Buffer        uintptr
}

type LSA_STRING_OUT struct {
	Length        uint16
	MaximumLength uint16
	Buffer        string
}

type LSA_STRING_IN struct {
	Length        uint16
	MaximumLength uint16
	Buffer        string
}

type LSA_LAST_INTER_LOGON_INFO struct {
	LastSuccessfulLogon                        uint64
	LastFailedLogon                            uint64
	FailedAttemptCountSinceLastSuccessfulLogon uint32
}

type SECURITY_LOGON_SESSION_DATA struct {
	Size                  uint32
	LogonId               LUID
	UserName              LSA_UNICODE_STRING
	LogonDomain           LSA_UNICODE_STRING
	AuthenticationPackage LSA_UNICODE_STRING
	LogonType             uint32
	Session               uint32
	Sid                   *windows.SID
	LogonTime             uint64
	LogonServer           LSA_UNICODE_STRING
	DnsDomainName         LSA_UNICODE_STRING
	Upn                   LSA_UNICODE_STRING
	UserFlags             uint32
	LastLogonInfo         LSA_LAST_INTER_LOGON_INFO
	LogonScript           LSA_UNICODE_STRING
	ProfilePath           LSA_UNICODE_STRING
	HomeDirectory         LSA_UNICODE_STRING
	HomeDirectoryDrive    LSA_UNICODE_STRING
	LogoffTime            uint64
	KickOffTime           uint64
	PasswordLastSet       uint64
	PasswordCanChange     uint64
	PasswordMustChange    uint64
}
