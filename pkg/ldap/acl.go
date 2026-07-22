package ldap

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// SecurityDescriptor represents a parsed Windows NT Security Descriptor
type SecurityDescriptor struct {
	OwnerSID        string
	Control         uint16
	DACLEntries     []ACE
	IsACLProtected  bool
}

// ACE represents a parsed Access Control Entry
type ACE struct {
	Type          byte
	Flags         byte
	AccessMask    uint32
	PrincipalSID  string
	ObjectTypeGUID string
	InheritedGUID  string
	IsInherited   bool
}

// BloodHoundEdge represents a BH-compatible ACE edge
type BloodHoundEdge struct {
	PrincipalSID  string `json:"PrincipalSID"`
	PrincipalType string `json:"PrincipalType"`
	RightName     string `json:"RightName"`
	IsInherited   bool   `json:"IsInherited"`
}

const (
	seDACLProtected uint16 = 0x1000

	aceTypeAccessAllowed       byte = 0x00
	aceTypeAccessAllowedObject byte = 0x05

	aceFlagInheritedACE byte = 0x10

	// Access mask rights
	maskGenericAll     uint32 = 0x10000000
	maskGenericWrite   uint32 = 0x40000000
	maskWriteOwner     uint32 = 0x00080000
	maskWriteDACL      uint32 = 0x00040000
	maskWriteProperty  uint32 = 0x00000020
	maskExtendedRight  uint32 = 0x00000100
	maskCreateChild    uint32 = 0x00000001
)

// Well-known object type GUIDs (lowercase, hyphenated)
var (
	guidUserForceChangePassword = "00299570-246d-11d0-a768-00aa006e0529"
	guidGroupMember             = "bf9679c0-0de6-11d0-a285-00aa003049e2"
	guidAllExtendedRights       = "00000000-0000-0000-0000-000000000000"
	guidUserAccountRestrictions = "4c164200-20c0-11d0-a768-00aa006e0529"
	guidLAPSPassword            = "e6a77cf4-3e7e-4f0c-80cf-c2d2e8f1c5a4"
	guidMSLAPSPassword          = "b01ba5c4-d8de-43a6-b8d5-4e2a0622a8a8"
	guidKeyCredentialLink       = "5b47d60f-6090-40b2-9f37-2a4de88f3063"
	guidWriteSPN                = "f3a64788-5306-11d1-a9c5-0000f80367c1"
)

// Noise SIDs to filter out of ACE results
var noiseSIDs = map[string]bool{
	"S-1-5-18":      true, // SYSTEM
	"S-1-3-0":       true, // CREATOR OWNER
	"S-1-5-10":      true, // SELF
	"S-1-5-32-544":  true, // BUILTIN\Administrators
}

// ParseSecurityDescriptor parses a binary Windows Security Descriptor
func ParseSecurityDescriptor(data []byte) (*SecurityDescriptor, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("security descriptor too short: %d bytes", len(data))
	}

	sd := &SecurityDescriptor{}
	sd.Control = binary.LittleEndian.Uint16(data[2:4])
	sd.IsACLProtected = sd.Control&seDACLProtected != 0

	ownerOffset := binary.LittleEndian.Uint32(data[4:8])
	if ownerOffset > 0 && int(ownerOffset) < len(data) {
		sd.OwnerSID = decodeSID(data[ownerOffset:])
	}

	daclOffset := binary.LittleEndian.Uint32(data[16:20])
	if daclOffset > 0 && int(daclOffset) < len(data) {
		aces, err := parseACL(data[daclOffset:])
		if err == nil {
			sd.DACLEntries = aces
		}
	}

	return sd, nil
}

func parseACL(data []byte) ([]ACE, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("ACL too short")
	}

	aceCount := int(binary.LittleEndian.Uint16(data[4:6]))
	var aces []ACE
	offset := 8

	for i := 0; i < aceCount && offset < len(data); i++ {
		ace, size, err := parseACE(data[offset:])
		if err != nil {
			offset += size
			continue
		}
		aces = append(aces, ace)
		offset += size
	}

	return aces, nil
}

func parseACE(data []byte) (ACE, int, error) {
	if len(data) < 4 {
		return ACE{}, 0, fmt.Errorf("ACE too short")
	}

	aceType := data[0]
	aceFlags := data[1]
	aceSize := int(binary.LittleEndian.Uint16(data[2:4]))

	if aceSize < 4 || aceSize > len(data) {
		return ACE{}, aceSize, fmt.Errorf("invalid ACE size")
	}

	ace := ACE{
		Type:        aceType,
		Flags:       aceFlags,
		IsInherited: aceFlags&aceFlagInheritedACE != 0,
	}

	switch aceType {
	case aceTypeAccessAllowed:
		if aceSize < 8 {
			return ace, aceSize, fmt.Errorf("ACCESS_ALLOWED_ACE too short")
		}
		ace.AccessMask = binary.LittleEndian.Uint32(data[4:8])
		if len(data) >= 8+8 {
			ace.PrincipalSID = decodeSID(data[8:])
		}

	case aceTypeAccessAllowedObject:
		if aceSize < 12 {
			return ace, aceSize, fmt.Errorf("ACCESS_ALLOWED_OBJECT_ACE too short")
		}
		ace.AccessMask = binary.LittleEndian.Uint32(data[4:8])
		objectFlags := binary.LittleEndian.Uint32(data[8:12])

		sidOffset := 12
		if objectFlags&0x01 != 0 {
			if len(data) >= sidOffset+16 {
				ace.ObjectTypeGUID = decodeGUID(data[sidOffset : sidOffset+16])
				sidOffset += 16
			}
		}
		if objectFlags&0x02 != 0 {
			if len(data) >= sidOffset+16 {
				ace.InheritedGUID = decodeGUID(data[sidOffset : sidOffset+16])
				sidOffset += 16
			}
		}
		if len(data) >= sidOffset+8 {
			ace.PrincipalSID = decodeSID(data[sidOffset:])
		}

	default:
		return ace, aceSize, fmt.Errorf("unhandled ACE type: %d", aceType)
	}

	return ace, aceSize, nil
}

// decodeGUID decodes a Windows GUID from binary (mixed-endian)
func decodeGUID(data []byte) string {
	if len(data) < 16 {
		return ""
	}
	// First 3 groups: little-endian. Last 2: big-endian.
	d1 := binary.LittleEndian.Uint32(data[0:4])
	d2 := binary.LittleEndian.Uint16(data[4:6])
	d3 := binary.LittleEndian.Uint16(data[6:8])

	return fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		d1, d2, d3,
		data[8], data[9],
		data[10], data[11], data[12], data[13], data[14], data[15])
}

// ACEsToBloodHoundEdges converts a parsed security descriptor into BloodHound-compatible ACE edges
func ACEsToBloodHoundEdges(sd *SecurityDescriptor, objectSID string, sidTypeMap map[string]string) []BloodHoundEdge {
	var edges []BloodHoundEdge

	// Owner -> Owns
	if sd.OwnerSID != "" && !noiseSIDs[sd.OwnerSID] {
		edges = append(edges, BloodHoundEdge{
			PrincipalSID:  sd.OwnerSID,
			PrincipalType: lookupType(sd.OwnerSID, sidTypeMap),
			RightName:     "Owns",
			IsInherited:   false,
		})
	}

	for _, ace := range sd.DACLEntries {
		if ace.PrincipalSID == "" || noiseSIDs[ace.PrincipalSID] {
			continue
		}
		if ace.PrincipalSID == objectSID {
			continue
		}

		principalType := lookupType(ace.PrincipalSID, sidTypeMap)

		if ace.AccessMask&maskGenericAll != 0 {
			edges = append(edges, BloodHoundEdge{
				PrincipalSID:  ace.PrincipalSID,
				PrincipalType: principalType,
				RightName:     "GenericAll",
				IsInherited:   ace.IsInherited,
			})
			continue
		}

		if ace.AccessMask&maskGenericWrite != 0 {
			edges = append(edges, BloodHoundEdge{
				PrincipalSID:  ace.PrincipalSID,
				PrincipalType: principalType,
				RightName:     "GenericWrite",
				IsInherited:   ace.IsInherited,
			})
		}
		if ace.AccessMask&maskWriteOwner != 0 {
			edges = append(edges, BloodHoundEdge{
				PrincipalSID:  ace.PrincipalSID,
				PrincipalType: principalType,
				RightName:     "WriteOwner",
				IsInherited:   ace.IsInherited,
			})
		}
		if ace.AccessMask&maskWriteDACL != 0 {
			edges = append(edges, BloodHoundEdge{
				PrincipalSID:  ace.PrincipalSID,
				PrincipalType: principalType,
				RightName:     "WriteDacl",
				IsInherited:   ace.IsInherited,
			})
		}

		guid := strings.ToLower(ace.ObjectTypeGUID)

		if ace.AccessMask&maskExtendedRight != 0 {
			switch guid {
			case guidUserForceChangePassword:
				edges = append(edges, BloodHoundEdge{
					PrincipalSID:  ace.PrincipalSID,
					PrincipalType: principalType,
					RightName:     "ForceChangePassword",
					IsInherited:   ace.IsInherited,
				})
			case guidAllExtendedRights, "":
				edges = append(edges, BloodHoundEdge{
					PrincipalSID:  ace.PrincipalSID,
					PrincipalType: principalType,
					RightName:     "AllExtendedRights",
					IsInherited:   ace.IsInherited,
				})
			}
		}

		if ace.AccessMask&maskWriteProperty != 0 {
			switch guid {
			case guidGroupMember:
				edges = append(edges, BloodHoundEdge{
					PrincipalSID:  ace.PrincipalSID,
					PrincipalType: principalType,
					RightName:     "AddMember",
					IsInherited:   ace.IsInherited,
				})
			case guidKeyCredentialLink:
				edges = append(edges, BloodHoundEdge{
					PrincipalSID:  ace.PrincipalSID,
					PrincipalType: principalType,
					RightName:     "AddKeyCredentialLink",
					IsInherited:   ace.IsInherited,
				})
			case guidWriteSPN:
				edges = append(edges, BloodHoundEdge{
					PrincipalSID:  ace.PrincipalSID,
					PrincipalType: principalType,
					RightName:     "WriteSPN",
					IsInherited:   ace.IsInherited,
				})
			case guidAllExtendedRights, "":
				edges = append(edges, BloodHoundEdge{
					PrincipalSID:  ace.PrincipalSID,
					PrincipalType: principalType,
					RightName:     "GenericWrite",
					IsInherited:   ace.IsInherited,
				})
			}
		}

		if ace.AccessMask&maskExtendedRight != 0 {
			if guid == guidLAPSPassword || guid == guidMSLAPSPassword {
				edges = append(edges, BloodHoundEdge{
					PrincipalSID:  ace.PrincipalSID,
					PrincipalType: principalType,
					RightName:     "ReadLAPSPassword",
					IsInherited:   ace.IsInherited,
				})
			}
		}
	}

	return edges
}

// ParseRBCDAllowedToAct parses the msDS-AllowedToActOnBehalfOfOtherIdentity SD
// and returns the SIDs of principals allowed to perform RBCD.
// The SD is an authorization list — any principal in an ALLOW ACE is permitted.
func ParseRBCDAllowedToAct(data []byte) []string {
	if len(data) == 0 {
		return nil
	}

	sd, err := ParseSecurityDescriptor(data)
	if err != nil {
		return nil
	}

	var sids []string
	for _, ace := range sd.DACLEntries {
		if ace.PrincipalSID != "" && (ace.Type == aceTypeAccessAllowed || ace.Type == aceTypeAccessAllowedObject) {
			sids = append(sids, ace.PrincipalSID)
		}
	}
	return sids
}

func lookupType(sid string, sidTypeMap map[string]string) string {
	if t, ok := sidTypeMap[sid]; ok {
		return t
	}
	// Well-known SID prefixes
	if strings.HasPrefix(sid, "S-1-5-32-") {
		return "Group"
	}
	return "Base"
}
