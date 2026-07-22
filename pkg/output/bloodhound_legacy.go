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

type bhLegacyMeta struct {
	Methods int    `json:"methods"`
	Type    string `json:"type"`
	Count   int    `json:"count"`
	Version int    `json:"version"`
}

type bhLegacyFile struct {
	Data interface{}  `json:"data"`
	Meta bhLegacyMeta `json:"meta"`
}

type bhLegacyACE struct {
	PrincipalSID  string `json:"PrincipalSID"`
	PrincipalType string `json:"PrincipalType"`
	RightName     string `json:"RightName"`
	IsInherited   bool   `json:"IsInherited"`
}

type bhLegacyUser struct {
	Properties        map[string]interface{} `json:"Properties"`
	PrimaryGroupSID   string                 `json:"PrimaryGroupSid"`
	AllowedToDelegate []bhMemberRef          `json:"AllowedToDelegate"`
	SPNTargets        []interface{}           `json:"SPNTargets"`
	HasSIDHistory     []interface{}           `json:"HasSIDHistory"`
	Aces              []bhLegacyACE           `json:"Aces"`
	ObjectIdentifier  string                 `json:"ObjectIdentifier"`
	IsDeleted         bool                   `json:"IsDeleted"`
	IsACLProtected    bool                   `json:"IsACLProtected"`
}

type bhLegacyGroup struct {
	Properties       map[string]interface{} `json:"Properties"`
	Members          []bhMemberRef          `json:"Members"`
	Aces             []bhLegacyACE          `json:"Aces"`
	ObjectIdentifier string                 `json:"ObjectIdentifier"`
	IsDeleted        bool                   `json:"IsDeleted"`
	IsACLProtected   bool                   `json:"IsACLProtected"`
}

type bhLegacyComputer struct {
	Properties         map[string]interface{} `json:"Properties"`
	PrimaryGroupSID    string                 `json:"PrimaryGroupSid"`
	AllowedToDelegate  []bhMemberRef          `json:"AllowedToDelegate"`
	AllowedToAct       []bhMemberRef          `json:"AllowedToAct"`
	HasSIDHistory      []interface{}           `json:"HasSIDHistory"`
	Sessions           bhSessionData           `json:"Sessions"`
	PrivilegedSessions bhSessionData           `json:"PrivilegedSessions"`
	RegistrySessions   bhSessionData           `json:"RegistrySessions"`
	LocalAdmins        bhSessionData           `json:"LocalAdmins"`
	RemoteDesktopUsers bhSessionData           `json:"RemoteDesktopUsers"`
	DcomUsers          bhSessionData           `json:"DcomUsers"`
	PSRemoteUsers      bhSessionData           `json:"PSRemoteUsers"`
	Aces               []bhLegacyACE           `json:"Aces"`
	ObjectIdentifier   string                 `json:"ObjectIdentifier"`
	IsDeleted          bool                   `json:"IsDeleted"`
	IsACLProtected     bool                   `json:"IsACLProtected"`
	IsDC               bool                   `json:"IsDC"`
	Status             *string                `json:"Status"`
}

type bhLegacyDomain struct {
	Properties       map[string]interface{} `json:"Properties"`
	ChildObjects     []interface{}           `json:"ChildObjects"`
	Trusts           []bhTrust              `json:"Trusts"`
	Links            []interface{}           `json:"Links"`
	Aces             []bhLegacyACE          `json:"Aces"`
	ObjectIdentifier string                 `json:"ObjectIdentifier"`
	IsDeleted        bool                   `json:"IsDeleted"`
	IsACLProtected   bool                   `json:"IsACLProtected"`
}

type BloodHoundLegacyWriter struct {
	outputDir  string
	domain     string
	domainSID  string
	hostSIDMap map[string]string
}

func NewBloodHoundLegacyWriter(outputDir, domain string) *BloodHoundLegacyWriter {
	return &BloodHoundLegacyWriter{
		outputDir: outputDir,
		domain:    domain,
	}
}

func (w *BloodHoundLegacyWriter) WriteAll(data *models.DomainData) (string, error) {
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
	zipName := fmt.Sprintf("%s_GoVibe_BloodHound_Legacy.zip", timestamp)
	zipPath := filepath.Join(w.outputDir, zipName)

	zipFile, err := os.Create(zipPath)
	if err != nil {
		return "", fmt.Errorf("failed to create zip file: %w", err)
	}
	defer zipFile.Close()

	zw := zip.NewWriter(zipFile)

	if err := w.writeToZip(zw, timestamp+"_users.json", "users", users, len(users)); err != nil {
		zw.Close()
		return "", err
	}
	if err := w.writeToZip(zw, timestamp+"_groups.json", "groups", groups, len(groups)); err != nil {
		zw.Close()
		return "", err
	}
	if err := w.writeToZip(zw, timestamp+"_computers.json", "computers", computers, len(computers)); err != nil {
		zw.Close()
		return "", err
	}
	if err := w.writeToZip(zw, timestamp+"_domains.json", "domains", domains, len(domains)); err != nil {
		zw.Close()
		return "", err
	}

	if err := zw.Close(); err != nil {
		return "", fmt.Errorf("failed to close zip: %w", err)
	}

	return zipPath, nil
}

func (w *BloodHoundLegacyWriter) writeToZip(zw *zip.Writer, filename, dataType string, data interface{}, count int) error {
	file := bhLegacyFile{
		Meta: bhLegacyMeta{
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

func (w *BloodHoundLegacyWriter) buildDNMap(data *models.DomainData) map[string]bhMemberRef {
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

func (w *BloodHoundLegacyWriter) buildSIDTypeMap(data *models.DomainData) map[string]string {
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
	return m
}

func (w *BloodHoundLegacyWriter) resolveACEs(rawSD []byte, objectSID string, sidTypeMap map[string]string) ([]bhLegacyACE, bool) {
	if len(rawSD) == 0 {
		return []bhLegacyACE{}, false
	}

	sd, err := ldap.ParseSecurityDescriptor(rawSD)
	if err != nil {
		return []bhLegacyACE{}, false
	}

	edges := ldap.ACEsToBloodHoundEdges(sd, objectSID, sidTypeMap)
	aces := make([]bhLegacyACE, 0, len(edges))
	for _, e := range edges {
		aces = append(aces, bhLegacyACE{
			PrincipalSID:  e.PrincipalSID,
			PrincipalType: e.PrincipalType,
			RightName:     e.RightName,
			IsInherited:   e.IsInherited,
		})
	}

	return aces, sd.IsACLProtected
}

func (w *BloodHoundLegacyWriter) convertUsers(users []models.User, upperDomain string, sidTypeMap map[string]string) []bhLegacyUser {
	result := make([]bhLegacyUser, 0, len(users))
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

		props := map[string]interface{}{
			"domain":                  upperDomain,
			"name":                    fmt.Sprintf("%s@%s", strings.ToUpper(u.Username), upperDomain),
			"distinguishedname":       u.DN,
			"domainsid":              w.domainSID,
			"highvalue":              bhIsHighValueUser(u.SID, u.Username),
			"unconstraineddelegation": bhHasUACFlag(u.UAC, models.UACFlags["TRUSTED_FOR_DELEGATION"]),
			"pwdneverexpires":        bhHasUACFlag(u.UAC, models.UACFlags["DONT_EXPIRE_PASSWD"]),
			"enabled":                u.Enabled,
			"trustedtoauth":          bhHasUACFlag(u.UAC, models.UACFlags["TRUSTED_TO_AUTH_FOR_DELEGATION"]),
			"lastlogon":              bhToEpoch(u.LastLogon),
			"pwdlastset":             bhToEpoch(u.PasswordLastSet),
			"serviceprincipalnames":  spns,
			"hasspn":                 len(u.SPNs) > 0,
			"displayname":            u.DisplayName,
			"email":                  u.Email,
			"title":                  u.Title,
			"homedirectory":          u.HomeDirectory,
			"description":            u.Description,
			"admincount":             u.AdminCount,
			"dontreqpreauth":         bhHasUACFlag(u.UAC, models.UACFlags["DONT_REQ_PREAUTH"]),
			"passwordnotreqd":        bhHasUACFlag(u.UAC, models.UACFlags["PASSWD_NOTREQD"]),
			"sensitive":              false,
			"sidhistory":             emptyIfNilStr(u.SIDHistory),
		}

		result = append(result, bhLegacyUser{
			Properties:        props,
			PrimaryGroupSID:   primaryGroupSID,
			AllowedToDelegate: allowedToDelegate,
			SPNTargets:        []interface{}{},
			HasSIDHistory:     []interface{}{},
			Aces:              aces,
			ObjectIdentifier:  u.SID,
			IsDeleted:         false,
			IsACLProtected:    aclProtected,
		})
	}
	return result
}

func (w *BloodHoundLegacyWriter) convertGroups(groups []models.Group, upperDomain string, dnMap map[string]bhMemberRef, sidTypeMap map[string]string) []bhLegacyGroup {
	result := make([]bhLegacyGroup, 0, len(groups))
	for _, g := range groups {
		members := make([]bhMemberRef, 0)
		for _, memberDN := range g.MemberDNs {
			if ref, ok := dnMap[strings.ToLower(memberDN)]; ok {
				members = append(members, ref)
			}
		}

		aces, aclProtected := w.resolveACEs(g.RawSD, g.SID, sidTypeMap)

		props := map[string]interface{}{
			"domain":            upperDomain,
			"name":              fmt.Sprintf("%s@%s", strings.ToUpper(g.Name), upperDomain),
			"distinguishedname": g.DN,
			"domainsid":         w.domainSID,
			"highvalue":         bhIsHighValueGroup(g.SID),
			"description":       g.Description,
			"admincount":        g.AdminCount,
		}

		result = append(result, bhLegacyGroup{
			Properties:       props,
			Members:          members,
			Aces:             aces,
			ObjectIdentifier: g.SID,
			IsDeleted:        false,
			IsACLProtected:   aclProtected,
		})
	}
	return result
}

func (w *BloodHoundLegacyWriter) convertComputers(computers []models.Computer, upperDomain string, sidTypeMap map[string]string) []bhLegacyComputer {
	emptySession := bhSessionData{Results: []interface{}{}, Collected: false}

	result := make([]bhLegacyComputer, 0, len(computers))
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

		props := map[string]interface{}{
			"domain":                  upperDomain,
			"name":                    name,
			"distinguishedname":       c.DN,
			"domainsid":              w.domainSID,
			"highvalue":              isDC,
			"description":            c.Description,
			"operatingsystem":        c.OperatingSystem,
			"enabled":                c.Enabled,
			"unconstraineddelegation": bhHasUACFlag(c.UAC, models.UACFlags["TRUSTED_FOR_DELEGATION"]),
			"trustedtoauth":          bhHasUACFlag(c.UAC, models.UACFlags["TRUSTED_TO_AUTH_FOR_DELEGATION"]),
			"lastlogontimestamp":     bhToEpoch(c.LastLogonTimestamp),
			"pwdlastset":             bhToEpoch(c.PwdLastSet),
			"serviceprincipalnames":  spns,
			"hasspn":                 len(c.SPNs) > 0,
			"haslaps":                c.LAPSPassword != "",
		}

		result = append(result, bhLegacyComputer{
			Properties:         props,
			PrimaryGroupSID:    primaryGroupSID,
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
			Aces:               aces,
			ObjectIdentifier:   c.SID,
			IsDeleted:          false,
			IsACLProtected:     aclProtected,
			IsDC:               isDC,
			Status:             nil,
		})
	}
	return result
}

func emptyIfNilStr(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func (w *BloodHoundLegacyWriter) convertDomains(data *models.DomainData, upperDomain string, sidTypeMap map[string]string) []bhLegacyDomain {
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

	props := map[string]interface{}{
		"domain":            upperDomain,
		"name":              upperDomain,
		"distinguishedname": bhDomainToDN(w.domain),
		"domainsid":         data.Domain.DomainSID,
		"highvalue":         true,
		"functionallevel":   data.Domain.FunctionalLevel,
	}

	return []bhLegacyDomain{{
		Properties:       props,
		ChildObjects:     []interface{}{},
		Trusts:           trusts,
		Links:            []interface{}{},
		Aces:             aces,
		ObjectIdentifier: data.Domain.DomainSID,
		IsDeleted:        false,
		IsACLProtected:   aclProtected,
	}}
}
