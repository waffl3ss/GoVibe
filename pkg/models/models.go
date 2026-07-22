package models

import "time"

type User struct {
	Username        string    `json:"username"`
	SID             string    `json:"sid"`
	Description     string    `json:"description"`
	HomeDirectory   string    `json:"homeDirectory"`
	ProfilePath     string    `json:"profilePath"`
	PasswordLastSet time.Time `json:"passwordLastSet"`
	LastLogon       time.Time `json:"lastLogon"`
	AccountSettings []string  `json:"accountSettings"`
	PrimaryGroup    string    `json:"primaryGroup"`
	MemberOf        []string  `json:"memberOf"`
	DN              string    `json:"dn"`
	Enabled         bool      `json:"enabled"`
	AdminCount      bool      `json:"adminCount"`
	SPNs            []string  `json:"servicePrincipalNames,omitempty"`
	UAC             int       `json:"-"`
	PrimaryGroupID  int       `json:"-"`
	DisplayName     string    `json:"-"`
	Email           string    `json:"-"`
	Title           string    `json:"-"`
	WhenCreated     time.Time `json:"-"`
	SIDHistory      []string  `json:"-"`
	AllowedToDelegate []string `json:"-"`
	RawSD           []byte    `json:"-"`
}

type Group struct {
	Name        string   `json:"name"`
	SID         string   `json:"sid"`
	Description string   `json:"description"`
	MemberOf    []string `json:"memberOf"`
	Members     []string `json:"members"`
	DN          string   `json:"dn"`
	AdminCount  bool     `json:"adminCount"`
	MemberDNs   []string `json:"-"`
	WhenCreated time.Time `json:"-"`
	RawSD       []byte    `json:"-"`
}

type Computer struct {
	Name              string    `json:"name"`
	SID               string    `json:"sid"`
	Description       string    `json:"description"`
	OperatingSystem   string    `json:"operatingSystem"`
	OSVersion         string    `json:"osVersion"`
	MemberOf          []string  `json:"memberOf"`
	DN                string    `json:"dn"`
	DNSHostName       string    `json:"dnsHostName"`
	IPv4Address       string    `json:"ipv4Address"`
	LastLogonTimestamp time.Time `json:"lastLogonTimestamp"`
	Enabled           bool      `json:"enabled"`
	SPNs              []string  `json:"servicePrincipalNames,omitempty"`
	UAC               int       `json:"-"`
	PrimaryGroupID    int       `json:"-"`
	WhenCreated       time.Time `json:"-"`
	PwdLastSet        time.Time `json:"-"`
	LAPSPassword      string    `json:"-"`
	AllowedToDelegate []string  `json:"-"`
	AllowedToActRaw   []byte    `json:"-"`
	RawSD             []byte    `json:"-"`
}

type SPN struct {
	ServicePrincipalName string    `json:"spn"`
	Username             string    `json:"username"`
	Description          string    `json:"description"`
	PasswordLastSet      time.Time `json:"passwordLastSet"`
	MemberOf             []string  `json:"memberOf"`
}

type PasswordPolicy struct {
	MinPasswordLength   int      `json:"minPasswordLength"`
	LockoutThreshold    int      `json:"lockoutThreshold"`
	LockoutDuration     int      `json:"lockoutDuration"`
	PasswordsRemembered int      `json:"passwordsRemembered"`
	PasswordProperties  []string `json:"passwordProperties"`
	MaxPasswordAge      int      `json:"maxPasswordAge"`
	MinPasswordAge      int      `json:"minPasswordAge"`
}

type FineGrainedPasswordPolicy struct {
	Name                string   `json:"name"`
	MinPasswordLength   int      `json:"minPasswordLength"`
	LockoutThreshold    int      `json:"lockoutThreshold"`
	LockoutDuration     int      `json:"lockoutDuration"`
	PasswordsRemembered int      `json:"passwordsRemembered"`
	PasswordComplexity  bool     `json:"passwordComplexity"`
	AppliesTo           []string `json:"appliesTo"`
}

type DomainInfo struct {
	Name                  string `json:"name"`
	NetBIOSName           string `json:"netbiosName"`
	DomainSID             string `json:"domainSid"`
	FunctionalLevel       string `json:"functionalLevel"`
	ForestFunctionalLevel string `json:"forestFunctionalLevel"`
	DomainControllers     []string `json:"domainControllers"`
	RawSD                 []byte `json:"-"`
}

type Trust struct {
	TargetDomain       string `json:"targetDomain"`
	TrustType          string `json:"trustType"`
	TrustDirection     string `json:"trustDirection"`
	TrustAttributes    string `json:"trustAttributes"`
	TrustTypeRaw       int    `json:"-"`
	TrustDirectionRaw  int    `json:"-"`
	TrustAttributesRaw int    `json:"-"`
	TargetDomainSID    string `json:"-"`
}

type OU struct {
	Name        string    `json:"name"`
	DN          string    `json:"dn"`
	SID         string    `json:"sid"`
	GPLink      string    `json:"-"`
	WhenCreated time.Time `json:"-"`
	RawSD       []byte    `json:"-"`
}

type GPO struct {
	DisplayName    string    `json:"displayName"`
	Name           string    `json:"name"`
	DN             string    `json:"dn"`
	GpcFileSysPath string    `json:"-"`
	WhenCreated    time.Time `json:"-"`
	RawSD          []byte    `json:"-"`
}

type Container struct {
	Name        string    `json:"name"`
	DN          string    `json:"dn"`
	SID         string    `json:"sid"`
	WhenCreated time.Time `json:"-"`
	RawSD       []byte    `json:"-"`
}

type DomainData struct {
	Domain         DomainInfo                  `json:"domain"`
	Users          []User                      `json:"users"`
	Groups         []Group                     `json:"groups"`
	Computers      []Computer                  `json:"computers"`
	SPNs           []SPN                       `json:"spns"`
	PasswordPolicy PasswordPolicy              `json:"passwordPolicy"`
	FGPolicies     []FineGrainedPasswordPolicy `json:"fineGrainedPolicies"`
	Trusts         []Trust                     `json:"trusts"`
	OUs            []OU                        `json:"ous,omitempty"`
	GPOs           []GPO                       `json:"gpos,omitempty"`
	Containers     []Container                 `json:"containers,omitempty"`
}

type Credentials struct {
	Username    string
	Password    string
	NTHash      string
	Domain      string
	UseKerberos bool
	CCachePath  string
	NoPass      bool
	DCHost      string
}

type Config struct {
	DC               string
	Port             int
	UseLDAPS         bool
	BaseDN           string
	Credentials      Credentials
	OutputDir        string
	ProxyAddr        string
	BloodHound       bool
	BloodHoundLegacy bool
	DCOnly           bool
	Offline          bool
	RemoveDB         bool
	Timeout          time.Duration
}

var UACFlags = map[string]int{
	"ACCOUNT_DISABLED":                 0x00000002,
	"ACCOUNT_LOCKED":                   0x00000010,
	"PASSWD_NOTREQD":                   0x00000020,
	"PASSWD_CANT_CHANGE":               0x00000040,
	"NORMAL_ACCOUNT":                   0x00000200,
	"WORKSTATION_ACCOUNT":              0x00001000,
	"SERVER_TRUST_ACCOUNT":             0x00002000,
	"DONT_EXPIRE_PASSWD":               0x00010000,
	"SMARTCARD_REQUIRED":               0x00040000,
	"TRUSTED_FOR_DELEGATION":           0x00080000,
	"NOT_DELEGATED":                    0x00100000,
	"USE_DES_KEY_ONLY":                 0x00200000,
	"DONT_REQ_PREAUTH":                0x00400000,
	"PASSWORD_EXPIRED":                 0x00800000,
	"TRUSTED_TO_AUTH_FOR_DELEGATION":   0x01000000,
}

var PasswordPropertyFlags = map[string]int{
	"DOMAIN_PASSWORD_COMPLEX":         1,
	"DOMAIN_PASSWORD_NO_ANON_CHANGE":  2,
	"DOMAIN_PASSWORD_NO_CLEAR_CHANGE": 4,
	"DOMAIN_LOCKOUT_ADMINS":           8,
	"DOMAIN_PASSWORD_STORE_CLEARTEXT": 16,
	"DOMAIN_REFUSE_PASSWORD_CHANGE":   32,
}
