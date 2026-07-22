package output

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"govibe/pkg/ldap"
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

type bhACE struct {
	PrincipalSID  string `json:"PrincipalSID"`
	PrincipalType string `json:"PrincipalType"`
	RightName     string `json:"RightName"`
	IsInherited   bool   `json:"IsInherited"`
}

type bhUser struct {
	ObjectIdentifier  string        `json:"ObjectIdentifier"`
	PrimaryGroupSID   string        `json:"PrimaryGroupSID"`
	MemberOf          interface{}   `json:"MemberOf"`
	SPNTargets        []interface{} `json:"SPNTargets"`
	HasSIDHistory     []bhMemberRef `json:"HasSIDHistory"`
	AllowedToDelegate []bhMemberRef `json:"AllowedToDelegate"`
	IsDeleted         bool          `json:"IsDeleted"`
	IsACLProtected    bool          `json:"IsACLProtected"`
	Aces              []bhACE       `json:"Aces"`
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
	ObjectIdentifier string      `json:"ObjectIdentifier"`
	IsDeleted        bool        `json:"IsDeleted"`
	IsACLProtected   bool        `json:"IsACLProtected"`
	Aces             []bhACE     `json:"Aces"`
	Members          []bhMemberRef `json:"Members"`
	Properties       bhGroupProps `json:"Properties"`
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
	ObjectIdentifier   string          `json:"ObjectIdentifier"`
	PrimaryGroupSID    string          `json:"PrimaryGroupSID"`
	MemberOf           interface{}     `json:"MemberOf"`
	AllowedToDelegate  []bhMemberRef   `json:"AllowedToDelegate"`
	AllowedToAct       []bhMemberRef   `json:"AllowedToAct"`
	HasSIDHistory      []interface{}   `json:"HasSIDHistory"`
	Sessions           bhSessionData   `json:"Sessions"`
	PrivilegedSessions bhSessionData   `json:"PrivilegedSessions"`
	RegistrySessions   bhSessionData   `json:"RegistrySessions"`
	LocalAdmins        bhSessionData   `json:"LocalAdmins"`
	RemoteDesktopUsers bhSessionData   `json:"RemoteDesktopUsers"`
	DcomUsers          bhSessionData   `json:"DcomUsers"`
	PSRemoteUsers      bhSessionData   `json:"PSRemoteUsers"`
	Status             *string         `json:"Status"`
	IsDeleted          bool            `json:"IsDeleted"`
	IsACLProtected     bool            `json:"IsACLProtected"`
	IsDC               bool            `json:"IsDC"`
	Aces               []bhACE         `json:"Aces"`
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
	HasLAPS                 bool     `json:"haslaps"`
}

type bhDomain struct {
	ObjectIdentifier string        `json:"ObjectIdentifier"`
	ChildObjects     []interface{} `json:"ChildObjects"`
	Trusts           []bhTrust     `json:"Trusts"`
	Links            []bhGPLink    `json:"Links"`
	IsDeleted        bool          `json:"IsDeleted"`
	IsACLProtected   bool          `json:"IsACLProtected"`
	Aces             []bhACE       `json:"Aces"`
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

type bhOU struct {
	ObjectIdentifier string        `json:"ObjectIdentifier"`
	IsDeleted        bool          `json:"IsDeleted"`
	IsACLProtected   bool          `json:"IsACLProtected"`
	Aces             []bhACE       `json:"Aces"`
	Links            []bhGPLink    `json:"Links"`
	ChildObjects     []interface{} `json:"ChildObjects"`
	Properties       bhOUProps     `json:"Properties"`
}

type bhOUProps struct {
	Domain            string  `json:"domain"`
	Name              string  `json:"name"`
	DistinguishedName string  `json:"distinguishedname"`
	DomainSID         string  `json:"domainsid"`
	HighValue         bool    `json:"highvalue"`
	Description       *string `json:"description"`
	WhenCreated       int64   `json:"whencreated"`
}

type bhGPO struct {
	ObjectIdentifier string    `json:"ObjectIdentifier"`
	IsDeleted        bool      `json:"IsDeleted"`
	IsACLProtected   bool      `json:"IsACLProtected"`
	Aces             []bhACE   `json:"Aces"`
	Properties       bhGPOProps `json:"Properties"`
}

type bhGPOProps struct {
	Domain            string  `json:"domain"`
	Name              string  `json:"name"`
	DistinguishedName string  `json:"distinguishedname"`
	DomainSID         string  `json:"domainsid"`
	HighValue         bool    `json:"highvalue"`
	Description       *string `json:"description"`
	WhenCreated       int64   `json:"whencreated"`
	GpcPath           string  `json:"gpcpath"`
}

type bhContainer struct {
	ObjectIdentifier string          `json:"ObjectIdentifier"`
	IsDeleted        bool            `json:"IsDeleted"`
	IsACLProtected   bool            `json:"IsACLProtected"`
	Aces             []bhACE         `json:"Aces"`
	ChildObjects     []interface{}   `json:"ChildObjects"`
	Properties       bhContainerProps `json:"Properties"`
}

type bhContainerProps struct {
	Domain            string  `json:"domain"`
	Name              string  `json:"name"`
	DistinguishedName string  `json:"distinguishedname"`
	DomainSID         string  `json:"domainsid"`
	HighValue         bool    `json:"highvalue"`
	Description       *string `json:"description"`
	WhenCreated       int64   `json:"whencreated"`
}

type bhGPLink struct {
	GUID       string `json:"GUID"`
	IsEnforced bool   `json:"IsEnforced"`
}

type BloodHoundWriter struct {
	outputDir  string
	domain     string
	domainSID  string
	hostSIDMap map[string]string
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
	sidTypeMap := w.buildSIDTypeMap(data)
	w.hostSIDMap = buildHostSIDMap(data.Computers)

	users := w.convertUsers(data.Users, upperDomain, sidTypeMap)
	groups := w.convertGroups(data.Groups, upperDomain, dnMap, sidTypeMap)
	computers := w.convertComputers(data.Computers, upperDomain, sidTypeMap)
	domains := w.convertDomains(data, upperDomain, sidTypeMap)

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

	if len(data.OUs) > 0 {
		ous := w.convertOUs(data.OUs, upperDomain, sidTypeMap)
		if err := w.writeToZip(zw, timestamp+"_ous.json", "ous", ous); err != nil {
			zw.Close()
			return "", err
		}
	}
	if len(data.GPOs) > 0 {
		gpos := w.convertGPOs(data.GPOs, upperDomain, sidTypeMap)
		if err := w.writeToZip(zw, timestamp+"_gpos.json", "gpos", gpos); err != nil {
			zw.Close()
			return "", err
		}
	}
	if len(data.Containers) > 0 {
		containers := w.convertContainers(data.Containers, upperDomain, sidTypeMap)
		if err := w.writeToZip(zw, timestamp+"_containers.json", "containers", containers); err != nil {
			zw.Close()
			return "", err
		}
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
	case []bhOU:
		count = len(d)
	case []bhGPO:
		count = len(d)
	case []bhContainer:
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
	for _, ou := range data.OUs {
		if ou.DN != "" && ou.SID != "" {
			m[strings.ToLower(ou.DN)] = bhMemberRef{ObjectIdentifier: ou.SID, ObjectType: "OU"}
		}
	}
	for _, cont := range data.Containers {
		if cont.DN != "" && cont.SID != "" {
			m[strings.ToLower(cont.DN)] = bhMemberRef{ObjectIdentifier: cont.SID, ObjectType: "Container"}
		}
	}
	return m
}

func (w *BloodHoundWriter) buildSIDTypeMap(data *models.DomainData) map[string]string {
	m := make(map[string]string)
	for _, u := range data.Users {
		if u.SID != "" {
			m[u.SID] = "User"
		}
	}
	for _, g := range data.Groups {
		if g.SID != "" {
			m[g.SID] = "Group"
		}
	}
	for _, c := range data.Computers {
		if c.SID != "" {
			m[c.SID] = "Computer"
		}
	}
	if data.Domain.DomainSID != "" {
		m[data.Domain.DomainSID] = "Domain"
	}
	for _, ou := range data.OUs {
		if ou.SID != "" {
			m[ou.SID] = "OU"
		}
	}
	for _, cont := range data.Containers {
		if cont.SID != "" {
			m[cont.SID] = "Container"
		}
	}
	return m
}

func (w *BloodHoundWriter) resolveACEs(rawSD []byte, objectSID string, sidTypeMap map[string]string) ([]bhACE, bool) {
	if len(rawSD) == 0 {
		return []bhACE{}, false
	}

	sd, err := ldap.ParseSecurityDescriptor(rawSD)
	if err != nil {
		return []bhACE{}, false
	}

	edges := ldap.ACEsToBloodHoundEdges(sd, objectSID, sidTypeMap)
	aces := make([]bhACE, 0, len(edges))
	for _, e := range edges {
		aces = append(aces, bhACE{
			PrincipalSID:  e.PrincipalSID,
			PrincipalType: e.PrincipalType,
			RightName:     e.RightName,
			IsInherited:   e.IsInherited,
		})
	}

	return aces, sd.IsACLProtected
}

func (w *BloodHoundWriter) convertUsers(users []models.User, upperDomain string, sidTypeMap map[string]string) []bhUser {
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

		aces, aclProtected := w.resolveACEs(u.RawSD, u.SID, sidTypeMap)

		allowedToDelegate := resolveSPNTargets(u.AllowedToDelegate, w.hostSIDMap)

		var sidHistory []string
		var hasSIDHistory []bhMemberRef
		if len(u.SIDHistory) > 0 {
			sidHistory = u.SIDHistory
			for _, sh := range u.SIDHistory {
				hasSIDHistory = append(hasSIDHistory, bhMemberRef{
					ObjectIdentifier: sh,
					ObjectType:       lookupTypeForSID(sh, sidTypeMap),
				})
			}
		} else {
			sidHistory = []string{}
			hasSIDHistory = []bhMemberRef{}
		}

		result = append(result, bhUser{
			ObjectIdentifier:  u.SID,
			PrimaryGroupSID:   primaryGroupSID,
			MemberOf:          nil,
			SPNTargets:        []interface{}{},
			HasSIDHistory:     hasSIDHistory,
			AllowedToDelegate: allowedToDelegate,
			IsDeleted:         false,
			IsACLProtected:    aclProtected,
			Aces:              aces,
			Properties: bhUserProps{
				Domain:                  upperDomain,
				Name:                    fmt.Sprintf("%s@%s", strings.ToUpper(u.Username), upperDomain),
				DistinguishedName:       u.DN,
				DomainSID:               w.domainSID,
				HighValue:               bhIsHighValueUser(u.SID, u.Username),
				Description:             bhStringPtr(u.Description),
				WhenCreated:             bhToEpoch(u.WhenCreated),
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
				DisplayName:             u.DisplayName,
				Email:                   u.Email,
				Title:                   u.Title,
				HomeDirectory:           u.HomeDirectory,
				AdminCount:              u.AdminCount,
				SIDHistory:              sidHistory,
			},
		})
	}
	return result
}

func (w *BloodHoundWriter) convertGroups(groups []models.Group, upperDomain string, dnMap map[string]bhMemberRef, sidTypeMap map[string]string) []bhGroup {
	result := make([]bhGroup, 0, len(groups))
	for _, g := range groups {
		members := make([]bhMemberRef, 0)
		for _, memberDN := range g.MemberDNs {
			if ref, ok := dnMap[strings.ToLower(memberDN)]; ok {
				members = append(members, ref)
			}
		}

		aces, aclProtected := w.resolveACEs(g.RawSD, g.SID, sidTypeMap)

		result = append(result, bhGroup{
			ObjectIdentifier: g.SID,
			IsDeleted:        false,
			IsACLProtected:   aclProtected,
			Aces:             aces,
			Members:          members,
			Properties: bhGroupProps{
				Domain:            upperDomain,
				Name:              fmt.Sprintf("%s@%s", strings.ToUpper(g.Name), upperDomain),
				DistinguishedName: g.DN,
				DomainSID:         w.domainSID,
				HighValue:         bhIsHighValueGroup(g.SID),
				Description:       bhStringPtr(g.Description),
				WhenCreated:       bhToEpoch(g.WhenCreated),
				AdminCount:        g.AdminCount,
			},
		})
	}
	return result
}

func (w *BloodHoundWriter) convertComputers(computers []models.Computer, upperDomain string, sidTypeMap map[string]string) []bhComputer {
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
		aces, aclProtected := w.resolveACEs(c.RawSD, c.SID, sidTypeMap)

		allowedToDelegate := resolveSPNTargets(c.AllowedToDelegate, w.hostSIDMap)

		var allowedToAct []bhMemberRef
		if len(c.AllowedToActRaw) > 0 {
			actSIDs := ldap.ParseRBCDAllowedToAct(c.AllowedToActRaw)
			for _, sid := range actSIDs {
				allowedToAct = append(allowedToAct, bhMemberRef{
					ObjectIdentifier: sid,
					ObjectType:       lookupTypeForSID(sid, sidTypeMap),
				})
			}
		}
		if allowedToAct == nil {
			allowedToAct = []bhMemberRef{}
		}

		result = append(result, bhComputer{
			ObjectIdentifier:   c.SID,
			PrimaryGroupSID:    primaryGroupSID,
			MemberOf:           nil,
			AllowedToDelegate:  allowedToDelegate,
			AllowedToAct:       allowedToAct,
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
			IsACLProtected:     aclProtected,
			IsDC:               isDC,
			Aces:               aces,
			Properties: bhComputerProps{
				Domain:                  upperDomain,
				Name:                    name,
				DistinguishedName:       c.DN,
				DomainSID:               w.domainSID,
				HighValue:               isDC,
				Description:             bhStringPtr(c.Description),
				WhenCreated:             bhToEpoch(c.WhenCreated),
				OperatingSystem:         c.OperatingSystem,
				Enabled:                 c.Enabled,
				UnconstrainedDelegation: bhHasUACFlag(c.UAC, models.UACFlags["TRUSTED_FOR_DELEGATION"]),
				TrustedToAuth:           bhHasUACFlag(c.UAC, models.UACFlags["TRUSTED_TO_AUTH_FOR_DELEGATION"]),
				LastLogon:               0,
				LastLogonTimestamp:       bhToEpoch(c.LastLogonTimestamp),
				PwdLastSet:              bhToEpoch(c.PwdLastSet),
				ServicePrincipalNames:   spns,
				HasSPN:                  len(c.SPNs) > 0,
				HasLAPS:                 c.LAPSPassword != "",
			},
		})
	}
	return result
}

func (w *BloodHoundWriter) convertDomains(data *models.DomainData, upperDomain string, sidTypeMap map[string]string) []bhDomain {
	trusts := make([]bhTrust, 0, len(data.Trusts))
	for _, t := range data.Trusts {
		isTransitive := t.TrustTypeRaw == 2 && (t.TrustAttributesRaw&0x1 == 0)
		sidFiltering := t.TrustAttributesRaw&0x20 == 0

		trusts = append(trusts, bhTrust{
			TargetDomainSid:     t.TargetDomainSID,
			TargetDomainName:    strings.ToUpper(t.TargetDomain),
			IsTransitive:        isTransitive,
			TrustDirection:      bhTrustDirectionStr(t.TrustDirectionRaw),
			TrustType:           bhTrustTypeStr(t.TrustTypeRaw, t.TrustAttributesRaw),
			SidFilteringEnabled: sidFiltering,
		})
	}

	aces, aclProtected := w.resolveACEs(data.Domain.RawSD, data.Domain.DomainSID, sidTypeMap)

	return []bhDomain{{
		ObjectIdentifier: data.Domain.DomainSID,
		ChildObjects:     []interface{}{},
		Trusts:           trusts,
		Links:            []bhGPLink{},
		IsDeleted:        false,
		IsACLProtected:   aclProtected,
		Aces:             aces,
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

func (w *BloodHoundWriter) convertOUs(ous []models.OU, upperDomain string, sidTypeMap map[string]string) []bhOU {
	result := make([]bhOU, 0, len(ous))
	for _, ou := range ous {
		oid := ou.SID
		if oid == "" {
			oid = ou.DN
		}
		aces, aclProtected := w.resolveACEs(ou.RawSD, oid, sidTypeMap)
		links := parseGPLinks(ou.GPLink)

		result = append(result, bhOU{
			ObjectIdentifier: oid,
			IsDeleted:        false,
			IsACLProtected:   aclProtected,
			Aces:             aces,
			Links:            links,
			ChildObjects:     []interface{}{},
			Properties: bhOUProps{
				Domain:            upperDomain,
				Name:              fmt.Sprintf("%s@%s", strings.ToUpper(ou.Name), upperDomain),
				DistinguishedName: ou.DN,
				DomainSID:         w.domainSID,
				HighValue:         false,
				Description:       nil,
				WhenCreated:       bhToEpoch(ou.WhenCreated),
			},
		})
	}
	return result
}

func (w *BloodHoundWriter) convertGPOs(gpos []models.GPO, upperDomain string, sidTypeMap map[string]string) []bhGPO {
	result := make([]bhGPO, 0, len(gpos))
	for _, gpo := range gpos {
		oid := gpo.DN
		aces, aclProtected := w.resolveACEs(gpo.RawSD, oid, sidTypeMap)

		name := gpo.DisplayName
		if name == "" {
			name = gpo.Name
		}

		result = append(result, bhGPO{
			ObjectIdentifier: oid,
			IsDeleted:        false,
			IsACLProtected:   aclProtected,
			Aces:             aces,
			Properties: bhGPOProps{
				Domain:            upperDomain,
				Name:              fmt.Sprintf("%s@%s", strings.ToUpper(name), upperDomain),
				DistinguishedName: gpo.DN,
				DomainSID:         w.domainSID,
				HighValue:         false,
				Description:       nil,
				WhenCreated:       bhToEpoch(gpo.WhenCreated),
				GpcPath:           gpo.GpcFileSysPath,
			},
		})
	}
	return result
}

func (w *BloodHoundWriter) convertContainers(containers []models.Container, upperDomain string, sidTypeMap map[string]string) []bhContainer {
	result := make([]bhContainer, 0, len(containers))
	for _, cont := range containers {
		oid := cont.SID
		if oid == "" {
			oid = cont.DN
		}
		aces, aclProtected := w.resolveACEs(cont.RawSD, oid, sidTypeMap)

		result = append(result, bhContainer{
			ObjectIdentifier: oid,
			IsDeleted:        false,
			IsACLProtected:   aclProtected,
			Aces:             aces,
			ChildObjects:     []interface{}{},
			Properties: bhContainerProps{
				Domain:            upperDomain,
				Name:              fmt.Sprintf("%s@%s", strings.ToUpper(cont.Name), upperDomain),
				DistinguishedName: cont.DN,
				DomainSID:         w.domainSID,
				HighValue:         false,
				Description:       nil,
				WhenCreated:       bhToEpoch(cont.WhenCreated),
			},
		})
	}
	return result
}

// parseGPLinks parses the gplink attribute into BH GPLink structs
// Format: [LDAP://cn={GUID},cn=policies,cn=system,DC=...;0][LDAP://...;2]
func parseGPLinks(gplink string) []bhGPLink {
	if gplink == "" {
		return []bhGPLink{}
	}
	var links []bhGPLink
	parts := strings.Split(gplink, "[")
	for _, part := range parts {
		part = strings.TrimSuffix(part, "]")
		if part == "" {
			continue
		}
		semicolonIdx := strings.LastIndex(part, ";")
		if semicolonIdx < 0 {
			continue
		}
		dn := strings.TrimPrefix(part[:semicolonIdx], "LDAP://")
		dn = strings.TrimPrefix(dn, "ldap://")
		enforced := part[semicolonIdx+1:]

		// Extract the GUID from the CN
		guid := ""
		dnLower := strings.ToLower(dn)
		if idx := strings.Index(dnLower, "cn={"); idx >= 0 {
			endIdx := strings.Index(dn[idx+4:], "}")
			if endIdx >= 0 {
				guid = strings.ToUpper(dn[idx+4 : idx+4+endIdx])
			}
		}
		if guid == "" {
			guid = dn
		}

		links = append(links, bhGPLink{
			GUID:       guid,
			IsEnforced: enforced == "2",
		})
	}
	if links == nil {
		return []bhGPLink{}
	}
	return links
}

func buildHostSIDMap(computers []models.Computer) map[string]string {
	m := make(map[string]string)
	for _, c := range computers {
		if c.SID == "" {
			continue
		}
		if c.DNSHostName != "" {
			m[strings.ToLower(c.DNSHostName)] = c.SID
		}
		name := strings.ToLower(strings.TrimSuffix(c.Name, "$"))
		if name != "" {
			m[name] = c.SID
		}
	}
	return m
}

func resolveSPNTargets(spns []string, hostSIDMap map[string]string) []bhMemberRef {
	if len(spns) == 0 {
		return []bhMemberRef{}
	}
	result := make([]bhMemberRef, 0, len(spns))
	seen := make(map[string]bool)
	for _, spn := range spns {
		parts := strings.SplitN(spn, "/", 2)
		if len(parts) < 2 {
			continue
		}
		host := parts[1]
		if colonIdx := strings.Index(host, ":"); colonIdx >= 0 {
			host = host[:colonIdx]
		}
		host = strings.ToLower(host)
		if seen[host] {
			continue
		}
		seen[host] = true
		sid, ok := hostSIDMap[host]
		if !ok {
			sid = strings.ToUpper(host)
		}
		result = append(result, bhMemberRef{
			ObjectIdentifier: sid,
			ObjectType:       "Computer",
		})
	}
	if len(result) == 0 {
		return []bhMemberRef{}
	}
	return result
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

func lookupTypeForSID(sid string, sidTypeMap map[string]string) string {
	if t, ok := sidTypeMap[sid]; ok {
		return t
	}
	if strings.HasPrefix(sid, "S-1-5-32-") {
		return "Group"
	}
	return "Base"
}
