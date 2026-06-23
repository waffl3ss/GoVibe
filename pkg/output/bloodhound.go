package output

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"govibe/pkg/models"
)

type bhMeta struct {
	Methods int    `json:"methods"`
	Type    string `json:"type"`
	Count   int    `json:"count"`
	Version int    `json:"version"`
}

type bhFile struct {
	Meta bhMeta      `json:"meta"`
	Data interface{} `json:"data"`
}

type bhMemberRef struct {
	ObjectIdentifier string `json:"ObjectIdentifier"`
	ObjectType       string `json:"ObjectType"`
}

type bhSessionData struct {
	Results   []interface{} `json:"Results"`
	Collected bool          `json:"Collected"`
}

type bhUser struct {
	ObjectIdentifier  string        `json:"ObjectIdentifier"`
	PrimaryGroupSID   string        `json:"PrimaryGroupSID"`
	MemberOf          interface{}   `json:"MemberOf"`
	SPNTargets        []interface{} `json:"SPNTargets"`
	HasSIDHistory     []interface{} `json:"HasSIDHistory"`
	AllowedToDelegate []string      `json:"AllowedToDelegate"`
	IsDeleted         bool          `json:"IsDeleted"`
	IsACLProtected    bool          `json:"IsACLProtected"`
	Aces              []interface{} `json:"Aces"`
	Properties        bhUserProps   `json:"Properties"`
}

type bhUserProps struct {
	Domain                  string   `json:"domain"`
	Name                    string   `json:"name"`
	DistinguishedName       string   `json:"distinguishedname"`
	DomainSID               string   `json:"domainsid"`
	HighValue               bool     `json:"highvalue"`
	Description             *string  `json:"description"`
	WhenCreated             int64    `json:"whencreated"`
	Sensitive               bool     `json:"sensitive"`
	DontReqPreauth          bool     `json:"dontreqpreauth"`
	PasswordNotReqd         bool     `json:"passwordnotreqd"`
	UnconstrainedDelegation bool     `json:"unconstraineddelegation"`
	PwdNeverExpires         bool     `json:"pwdneverexpires"`
	Enabled                 bool     `json:"enabled"`
	TrustedToAuth           bool     `json:"trustedtoauth"`
	LastLogon               int64    `json:"lastlogon"`
	LastLogonTimestamp       int64    `json:"lastlogontimestamp"`
	PwdLastSet              int64    `json:"pwdlastset"`
	ServicePrincipalNames   []string `json:"serviceprincipalnames"`
	HasSPN                  bool     `json:"hasspn"`
	DisplayName             string   `json:"displayname"`
	Email                   string   `json:"email"`
	Title                   string   `json:"title"`
	HomeDirectory           string   `json:"homedirectory"`
	AdminCount              bool     `json:"admincount"`
	SIDHistory              []string `json:"sidhistory"`
}

type bhGroup struct {
	ObjectIdentifier string        `json:"ObjectIdentifier"`
	IsDeleted        bool          `json:"IsDeleted"`
	IsACLProtected   bool          `json:"IsACLProtected"`
	Aces             []interface{} `json:"Aces"`
	Members          []bhMemberRef `json:"Members"`
	Properties       bhGroupProps  `json:"Properties"`
}

type bhGroupProps struct {
	Domain            string  `json:"domain"`
	Name              string  `json:"name"`
	DistinguishedName string  `json:"distinguishedname"`
	DomainSID         string  `json:"domainsid"`
	HighValue         bool    `json:"highvalue"`
	Description       *string `json:"description"`
	WhenCreated       int64   `json:"whencreated"`
	AdminCount        bool    `json:"admincount"`
}

type bhComputer struct {
	ObjectIdentifier   string         `json:"ObjectIdentifier"`
	PrimaryGroupSID    string         `json:"PrimaryGroupSID"`
	MemberOf           interface{}    `json:"MemberOf"`
	AllowedToDelegate  []string       `json:"AllowedToDelegate"`
	AllowedToAct       []interface{}  `json:"AllowedToAct"`
	HasSIDHistory      []interface{}  `json:"HasSIDHistory"`
	Sessions           bhSessionData  `json:"Sessions"`
	PrivilegedSessions bhSessionData  `json:"PrivilegedSessions"`
	RegistrySessions   bhSessionData  `json:"RegistrySessions"`
	LocalAdmins        bhSessionData  `json:"LocalAdmins"`
	RemoteDesktopUsers bhSessionData  `json:"RemoteDesktopUsers"`
	DcomUsers          bhSessionData  `json:"DcomUsers"`
	PSRemoteUsers      bhSessionData  `json:"PSRemoteUsers"`
	Status             *string        `json:"Status"`
	IsDeleted          bool           `json:"IsDeleted"`
	IsACLProtected     bool           `json:"IsACLProtected"`
	IsDC               bool           `json:"IsDC"`
	Aces               []interface{}  `json:"Aces"`
	Properties         bhComputerProps `json:"Properties"`
}

type bhComputerProps struct {
	Domain                  string   `json:"domain"`
	Name                    string   `json:"name"`
	DistinguishedName       string   `json:"distinguishedname"`
	DomainSID               string   `json:"domainsid"`
	HighValue               bool     `json:"highvalue"`
	Description             *string  `json:"description"`
	WhenCreated             int64    `json:"whencreated"`
	OperatingSystem         string   `json:"operatingsystem"`
	Enabled                 bool     `json:"enabled"`
	UnconstrainedDelegation bool     `json:"unconstraineddelegation"`
	TrustedToAuth           bool     `json:"trustedtoauth"`
	LastLogon               int64    `json:"lastlogon"`
	LastLogonTimestamp       int64    `json:"lastlogontimestamp"`
	PwdLastSet              int64    `json:"pwdlastset"`
	ServicePrincipalNames   []string `json:"serviceprincipalnames"`
	HasSPN                  bool     `json:"hasspn"`
}

type bhDomain struct {
	ObjectIdentifier string        `json:"ObjectIdentifier"`
	ChildObjects     []interface{} `json:"ChildObjects"`
	Trusts           []bhTrust     `json:"Trusts"`
	Links            []interface{} `json:"Links"`
	IsDeleted        bool          `json:"IsDeleted"`
	IsACLProtected   bool          `json:"IsACLProtected"`
	Aces             []interface{} `json:"Aces"`
	Properties       bhDomainProps `json:"Properties"`
}

type bhDomainProps struct {
	Domain            string  `json:"domain"`
	Name              string  `json:"name"`
	DistinguishedName string  `json:"distinguishedname"`
	DomainSID         string  `json:"domainsid"`
	HighValue         bool    `json:"highvalue"`
	Description       *string `json:"description"`
	WhenCreated       int64   `json:"whencreated"`
	FunctionalLevel   string  `json:"functionallevel"`
}

type bhTrust struct {
	TargetDomainSid     string `json:"TargetDomainSid"`
	TargetDomainName    string `json:"TargetDomainName"`
	IsTransitive        bool   `json:"IsTransitive"`
	TrustDirection      string `json:"TrustDirection"`
	TrustType           string `json:"TrustType"`
	SidFilteringEnabled bool   `json:"SidFilteringEnabled"`
}

type BloodHoundWriter struct {
	outputDir string
	domain    string
	domainSID string
}

func NewBloodHoundWriter(outputDir, domain string) *BloodHoundWriter {
	return &BloodHoundWriter{
		outputDir: outputDir,
		domain:    domain,
	}
}

func (w *BloodHoundWriter) WriteAll(data *models.DomainData) (string, error) {
	if err := os.MkdirAll(w.outputDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create output directory: %w", err)
	}

	w.domainSID = data.Domain.DomainSID
	upperDomain := strings.ToUpper(w.domain)

	dnMap := w.buildDNMap(data)

	users := w.convertUsers(data.Users, upperDomain)
	groups := w.convertGroups(data.Groups, upperDomain, dnMap)
	computers := w.convertComputers(data.Computers, upperDomain)
	domains := w.convertDomains(data, upperDomain)

	timestamp := time.Now().Format("20060102150405")
	zipName := fmt.Sprintf("%s_GoVibe_BloodHound.zip", timestamp)
	zipPath := filepath.Join(w.outputDir, zipName)

	zipFile, err := os.Create(zipPath)
	if err != nil {
		return "", fmt.Errorf("failed to create zip file: %w", err)
	}
	defer zipFile.Close()

	zw := zip.NewWriter(zipFile)

	if err := w.writeToZip(zw, timestamp+"_users.json", "users", users); err != nil {
		zw.Close()
		return "", err
	}
	if err := w.writeToZip(zw, timestamp+"_groups.json", "groups", groups); err != nil {
		zw.Close()
		return "", err
	}
	if err := w.writeToZip(zw, timestamp+"_computers.json", "computers", computers); err != nil {
		zw.Close()
		return "", err
	}
	if err := w.writeToZip(zw, timestamp+"_domains.json", "domains", domains); err != nil {
		zw.Close()
		return "", err
	}

	if err := zw.Close(); err != nil {
		return "", fmt.Errorf("failed to close zip: %w", err)
	}

	return zipPath, nil
}

func (w *BloodHoundWriter) writeToZip(zw *zip.Writer, filename, dataType string, data interface{}) error {
	var count int
	switch d := data.(type) {
	case []bhUser:
		count = len(d)
	case []bhGroup:
		count = len(d)
	case []bhComputer:
		count = len(d)
	case []bhDomain:
		count = len(d)
	}

	file := bhFile{
		Meta: bhMeta{
			Methods: 0,
			Type:    dataType,
			Count:   count,
			Version: 5,
		},
		Data: data,
	}

	entry, err := zw.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create zip entry %s: %w", filename, err)
	}

	encoder := json.NewEncoder(entry)
	return encoder.Encode(file)
}

func (w *BloodHoundWriter) buildDNMap(data *models.DomainData) map[string]bhMemberRef {
	m := make(map[string]bhMemberRef)
	for _, u := range data.Users {
		if u.DN != "" && u.SID != "" {
			m[strings.ToLower(u.DN)] = bhMemberRef{ObjectIdentifier: u.SID, ObjectType: "User"}
		}
	}
	for _, c := range data.Computers {
		if c.DN != "" && c.SID != "" {
			m[strings.ToLower(c.DN)] = bhMemberRef{ObjectIdentifier: c.SID, ObjectType: "Computer"}
		}
	}
	for _, g := range data.Groups {
		if g.DN != "" && g.SID != "" {
			m[strings.ToLower(g.DN)] = bhMemberRef{ObjectIdentifier: g.SID, ObjectType: "Group"}
		}
	}
	return m
}

func (w *BloodHoundWriter) convertUsers(users []models.User, upperDomain string) []bhUser {
	result := make([]bhUser, 0, len(users))
	for _, u := range users {
		primaryGroupSID := ""
		if u.PrimaryGroupID > 0 && w.domainSID != "" {
			primaryGroupSID = fmt.Sprintf("%s-%d", w.domainSID, u.PrimaryGroupID)
		}

		spns := u.SPNs
		if spns == nil {
			spns = []string{}
		}

		result = append(result, bhUser{
			ObjectIdentifier:  u.SID,
			PrimaryGroupSID:   primaryGroupSID,
			MemberOf:          nil,
			SPNTargets:        []interface{}{},
			HasSIDHistory:     []interface{}{},
			AllowedToDelegate: []string{},
			IsDeleted:         false,
			IsACLProtected:    false,
			Aces:              []interface{}{},
			Properties: bhUserProps{
				Domain:                  upperDomain,
				Name:                    fmt.Sprintf("%s@%s", strings.ToUpper(u.Username), upperDomain),
				DistinguishedName:       u.DN,
				DomainSID:               w.domainSID,
				HighValue:               bhIsHighValueUser(u.SID, u.Username),
				Description:             bhStringPtr(u.Description),
				WhenCreated:             0,
				Sensitive:               false,
				DontReqPreauth:          bhHasUACFlag(u.UAC, models.UACFlags["DONT_REQ_PREAUTH"]),
				PasswordNotReqd:         bhHasUACFlag(u.UAC, models.UACFlags["PASSWD_NOTREQD"]),
				UnconstrainedDelegation: bhHasUACFlag(u.UAC, models.UACFlags["TRUSTED_FOR_DELEGATION"]),
				PwdNeverExpires:         bhHasUACFlag(u.UAC, models.UACFlags["DONT_EXPIRE_PASSWD"]),
				Enabled:                 u.Enabled,
				TrustedToAuth:           bhHasUACFlag(u.UAC, models.UACFlags["TRUSTED_TO_AUTH_FOR_DELEGATION"]),
				LastLogon:               bhToEpoch(u.LastLogon),
				LastLogonTimestamp:       0,
				PwdLastSet:              bhToEpoch(u.PasswordLastSet),
				ServicePrincipalNames:   spns,
				HasSPN:                  len(u.SPNs) > 0,
				HomeDirectory:           u.HomeDirectory,
				AdminCount:              u.AdminCount,
				SIDHistory:              []string{},
			},
		})
	}
	return result
}

func (w *BloodHoundWriter) convertGroups(groups []models.Group, upperDomain string, dnMap map[string]bhMemberRef) []bhGroup {
	result := make([]bhGroup, 0, len(groups))
	for _, g := range groups {
		members := make([]bhMemberRef, 0)
		for _, memberDN := range g.MemberDNs {
			if ref, ok := dnMap[strings.ToLower(memberDN)]; ok {
				members = append(members, ref)
			}
		}

		result = append(result, bhGroup{
			ObjectIdentifier: g.SID,
			IsDeleted:        false,
			IsACLProtected:   false,
			Aces:             []interface{}{},
			Members:          members,
			Properties: bhGroupProps{
				Domain:            upperDomain,
				Name:              fmt.Sprintf("%s@%s", strings.ToUpper(g.Name), upperDomain),
				DistinguishedName: g.DN,
				DomainSID:         w.domainSID,
				HighValue:         bhIsHighValueGroup(g.SID),
				Description:       bhStringPtr(g.Description),
				WhenCreated:       0,
				AdminCount:        g.AdminCount,
			},
		})
	}
	return result
}

func (w *BloodHoundWriter) convertComputers(computers []models.Computer, upperDomain string) []bhComputer {
	emptySession := bhSessionData{Results: []interface{}{}, Collected: false}

	result := make([]bhComputer, 0, len(computers))
	for _, c := range computers {
		primaryGroupSID := ""
		if c.PrimaryGroupID > 0 && w.domainSID != "" {
			primaryGroupSID = fmt.Sprintf("%s-%d", w.domainSID, c.PrimaryGroupID)
		} else if w.domainSID != "" {
			primaryGroupSID = fmt.Sprintf("%s-515", w.domainSID)
		}

		spns := c.SPNs
		if spns == nil {
			spns = []string{}
		}

		name := strings.ToUpper(c.DNSHostName)
		if name == "" {
			name = fmt.Sprintf("%s.%s", strings.ToUpper(c.Name), upperDomain)
		}

		isDC := bhHasUACFlag(c.UAC, models.UACFlags["SERVER_TRUST_ACCOUNT"])

		result = append(result, bhComputer{
			ObjectIdentifier:   c.SID,
			PrimaryGroupSID:    primaryGroupSID,
			MemberOf:           nil,
			AllowedToDelegate:  []string{},
			AllowedToAct:       []interface{}{},
			HasSIDHistory:      []interface{}{},
			Sessions:           emptySession,
			PrivilegedSessions: emptySession,
			RegistrySessions:   emptySession,
			LocalAdmins:        emptySession,
			RemoteDesktopUsers: emptySession,
			DcomUsers:          emptySession,
			PSRemoteUsers:      emptySession,
			Status:             nil,
			IsDeleted:          false,
			IsACLProtected:     false,
			IsDC:               isDC,
			Aces:               []interface{}{},
			Properties: bhComputerProps{
				Domain:                  upperDomain,
				Name:                    name,
				DistinguishedName:       c.DN,
				DomainSID:               w.domainSID,
				HighValue:               isDC,
				Description:             bhStringPtr(c.Description),
				WhenCreated:             0,
				OperatingSystem:         c.OperatingSystem,
				Enabled:                 c.Enabled,
				UnconstrainedDelegation: bhHasUACFlag(c.UAC, models.UACFlags["TRUSTED_FOR_DELEGATION"]),
				TrustedToAuth:           bhHasUACFlag(c.UAC, models.UACFlags["TRUSTED_TO_AUTH_FOR_DELEGATION"]),
				LastLogon:               0,
				LastLogonTimestamp:       bhToEpoch(c.LastLogonTimestamp),
				PwdLastSet:              0,
				ServicePrincipalNames:   spns,
				HasSPN:                  len(c.SPNs) > 0,
			},
		})
	}
	return result
}

func (w *BloodHoundWriter) convertDomains(data *models.DomainData, upperDomain string) []bhDomain {
	trusts := make([]bhTrust, 0, len(data.Trusts))
	for _, t := range data.Trusts {
		isTransitive := t.TrustTypeRaw == 2 && (t.TrustAttributesRaw&0x1 == 0)
		sidFiltering := t.TrustAttributesRaw&0x20 == 0

		trusts = append(trusts, bhTrust{
			TargetDomainSid:     "",
			TargetDomainName:    strings.ToUpper(t.TargetDomain),
			IsTransitive:        isTransitive,
			TrustDirection:      bhTrustDirectionStr(t.TrustDirectionRaw),
			TrustType:           bhTrustTypeStr(t.TrustTypeRaw, t.TrustAttributesRaw),
			SidFilteringEnabled: sidFiltering,
		})
	}

	return []bhDomain{{
		ObjectIdentifier: data.Domain.DomainSID,
		ChildObjects:     []interface{}{},
		Trusts:           trusts,
		Links:            []interface{}{},
		IsDeleted:        false,
		IsACLProtected:   false,
		Aces:             []interface{}{},
		Properties: bhDomainProps{
			Domain:            upperDomain,
			Name:              upperDomain,
			DistinguishedName: bhDomainToDN(w.domain),
			DomainSID:         data.Domain.DomainSID,
			HighValue:         true,
			Description:       nil,
			WhenCreated:       0,
			FunctionalLevel:   data.Domain.FunctionalLevel,
		},
	}}
}

func bhTrustDirectionStr(dir int) string {
	switch dir {
	case 0:
		return "Disabled"
	case 1:
		return "Inbound"
	case 2:
		return "Outbound"
	case 3:
		return "Bidirectional"
	default:
		return "Unknown"
	}
}

func bhTrustTypeStr(trustType int, trustAttrs int) string {
	if trustAttrs&0x8 != 0 {
		return "Forest"
	}
	if trustAttrs&0x20 != 0 {
		return "ParentChild"
	}
	return "External"
}

func bhHasUACFlag(uac int, flag int) bool {
	return uac&flag != 0
}

func bhToEpoch(t time.Time) int64 {
	if t.IsZero() || t.Year() < 1970 {
		return 0
	}
	return t.Unix()
}

func bhStringPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func bhIsHighValueUser(sid, username string) bool {
	if strings.EqualFold(username, "krbtgt") {
		return true
	}
	if strings.HasSuffix(sid, "-500") {
		return true
	}
	return false
}

func bhIsHighValueGroup(sid string) bool {
	highValueRIDs := []string{"-512", "-516", "-518", "-519", "-520"}
	for _, rid := range highValueRIDs {
		if strings.HasSuffix(sid, rid) {
			return true
		}
	}
	highValueSIDs := []string{
		"S-1-5-32-544",
		"S-1-5-32-548",
		"S-1-5-32-549",
		"S-1-5-32-550",
		"S-1-5-32-551",
	}
	for _, hvSID := range highValueSIDs {
		if sid == hvSID {
			return true
		}
	}
	return false
}

func bhDomainToDN(domain string) string {
	parts := strings.Split(domain, ".")
	dnParts := make([]string, len(parts))
	for i, p := range parts {
		dnParts[i] = "DC=" + p
	}
	return strings.Join(dnParts, ",")
}
