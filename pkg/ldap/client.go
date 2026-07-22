package ldap

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/asn1tools"
	"github.com/jcmturner/gokrb5/v8/client"
	krb5config "github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"golang.org/x/net/proxy"
	"govibe/pkg/models"
)

type Client struct {
	conn    *ldap.Conn
	rawConn net.Conn
	config  *models.Config
	baseDN  string
}

func NewClient(config *models.Config) *Client {
	return &Client{
		config: config,
	}
}

func (c *Client) bloodHoundEnabled() bool {
	return c.config.BloodHound || c.config.BloodHoundLegacy
}

func (c *Client) Connect() error {
	var err error
	var address string
	var tcpConn net.Conn

	if c.config.Port == 0 {
		if c.config.UseLDAPS {
			c.config.Port = 636
		} else {
			c.config.Port = 389
		}
	}

	address = fmt.Sprintf("%s:%d", c.config.DC, c.config.Port)
	timeout := c.config.Timeout

	if c.config.ProxyAddr != "" {
		fmt.Printf("[*] Using SOCKS5 proxy: %s\n", c.config.ProxyAddr)
		dialer, err := proxy.SOCKS5("tcp", c.config.ProxyAddr, nil, proxy.Direct)
		if err != nil {
			return fmt.Errorf("failed to create SOCKS5 dialer: %w", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		fmt.Printf("[*] Dialing %s via proxy...\n", address)
		if contextDialer, ok := dialer.(proxy.ContextDialer); ok {
			tcpConn, err = contextDialer.DialContext(ctx, "tcp", address)
		} else {
			tcpConn, err = dialer.Dial("tcp", address)
		}
	} else {
		fmt.Printf("[*] Dialing %s...\n", address)
		tcpConn, err = net.DialTimeout("tcp", address, timeout)
	}

	if err != nil {
		return fmt.Errorf("TCP connection failed: %w", err)
	}
	fmt.Printf("[+] TCP connection established\n")

	if c.config.UseLDAPS {
		fmt.Printf("[*] Starting TLS handshake...\n")
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         c.config.DC,
			MinVersion:         tls.VersionTLS10,
		}
		tlsConn := tls.Client(tcpConn, tlsConfig)
		if err := tlsConn.Handshake(); err != nil {
			tcpConn.Close()
			return fmt.Errorf("TLS handshake failed: %w", err)
		}
		fmt.Printf("[+] TLS handshake complete\n")
		c.rawConn = tlsConn
	} else {
		c.rawConn = tcpConn
	}

	if c.config.Credentials.UseKerberos {
		return nil
	}

	c.conn = ldap.NewConn(c.rawConn, c.config.UseLDAPS)
	c.conn.Start()
	c.conn.SetTimeout(timeout)

	return nil
}

func (c *Client) Bind() error {
	creds := c.config.Credentials

	if creds.UseKerberos {
		return c.bindWithKerberos()
	}

	if creds.NTHash != "" {
		return c.bindWithNTLM()
	}

	bindDN := fmt.Sprintf("%s@%s", creds.Username, creds.Domain)
	err := c.conn.Bind(bindDN, creds.Password)
	if err != nil {
		return fmt.Errorf("LDAP bind failed: %w", err)
	}

	return nil
}

func (c *Client) bindWithKerberos() error {
	creds := c.config.Credentials
	realm := strings.ToUpper(creds.Domain)

	ccachePath := creds.CCachePath
	if ccachePath == "" {
		ccachePath = os.Getenv("KRB5CCNAME")
	}
	if ccachePath == "" {
		return fmt.Errorf("no ccache path provided and KRB5CCNAME not set")
	}
	ccachePath = strings.TrimPrefix(ccachePath, "FILE:")
	ccachePath = strings.TrimPrefix(ccachePath, "file:")

	kdcAddr := fmt.Sprintf("%s:88", c.config.DC)

	if c.config.ProxyAddr != "" {
		localKDC, err := startKDCProxy(c.config.ProxyAddr, kdcAddr)
		if err != nil {
			return fmt.Errorf("failed to start KDC proxy: %w", err)
		}
		kdcAddr = localKDC
		fmt.Printf("[*] KDC proxy: %s -> %s:88 via SOCKS5\n", localKDC, c.config.DC)
	}

	cfg := krb5config.New()
	cfg.LibDefaults.DefaultRealm = realm
	cfg.LibDefaults.DNSLookupKDC = false
	cfg.LibDefaults.DNSLookupRealm = false
	cfg.LibDefaults.UDPPreferenceLimit = 1
	cfg.LibDefaults.PermittedEnctypeIDs = []int32{18, 17, 23}
	cfg.LibDefaults.DefaultTGSEnctypeIDs = []int32{18, 17, 23}
	cfg.LibDefaults.DefaultTktEnctypeIDs = []int32{18, 17, 23}
	cfg.Realms = []krb5config.Realm{{
		Realm:         realm,
		KDC:           []string{kdcAddr},
		DefaultDomain: realm,
	}}

	ccache, err := credentials.LoadCCache(ccachePath)
	if err != nil {
		return fmt.Errorf("failed to load ccache: %w", err)
	}

	cl, err := client.NewFromCCache(ccache, cfg, client.DisablePAFXFAST(true))
	if err != nil {
		return fmt.Errorf("failed to create Kerberos client: %w", err)
	}

	if err := cl.Login(); err != nil {
		return fmt.Errorf("Kerberos login failed: %w", err)
	}

	host := creds.DCHost
	if host == "" {
		host = c.config.DC
	}
	spn := fmt.Sprintf("ldap/%s", host)

	tkt, sessionKey, err := cl.GetServiceTicket(spn)
	if err != nil {
		return fmt.Errorf("failed to get service ticket for %s: %w", spn, err)
	}

	krb5Token, err := spnego.NewKRB5TokenAPREQ(cl, tkt, sessionKey, []int{}, []int{})
	if err != nil {
		return fmt.Errorf("failed to create KRB5 AP-REQ token: %w", err)
	}
	mechTokenBytes, err := krb5Token.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal KRB5 token: %w", err)
	}

	negInit := spnego.NegTokenInit{
		MechTypes:      []asn1.ObjectIdentifier{gssapi.OIDKRB5.OID()},
		MechTokenBytes: mechTokenBytes,
	}
	tokenBytes, err := negInit.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal NegTokenInit: %w", err)
	}

	oidBytes, _ := asn1.Marshal(gssapi.OIDSPNEGO.OID())
	tokenBytes = asn1tools.AddASNAppTag(append(oidBytes, tokenBytes...), 0)

	if err := c.sendSPNEGOBind(tokenBytes); err != nil {
		return err
	}

	c.conn = ldap.NewConn(c.rawConn, c.config.UseLDAPS)
	c.conn.Start()
	c.conn.SetTimeout(c.config.Timeout)

	return nil
}

func (c *Client) sendSPNEGOBind(token []byte) error {
	resultCode, _, err := c.sendSASLBind(1, "GSS-SPNEGO", token)
	if err != nil {
		return fmt.Errorf("SPNEGO bind leg 1 failed: %w", err)
	}
	if resultCode == 0 {
		return nil
	}
	if resultCode != 14 {
		return fmt.Errorf("LDAP SPNEGO bind error (code %d)", resultCode)
	}

	resultCode, _, err = c.sendSASLBind(2, "GSS-SPNEGO", nil)
	if err != nil {
		return fmt.Errorf("SPNEGO bind leg 2 failed: %w", err)
	}
	if resultCode != 0 {
		return fmt.Errorf("LDAP SPNEGO bind error on leg 2 (code %d)", resultCode)
	}

	return nil
}

func (c *Client) sendSASLBind(msgID int64, mechanism string, creds []byte) (int64, []byte, error) {
	envelope := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	envelope.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, msgID, "MessageID"))

	bindReq := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 0, nil, "Bind Request")
	bindReq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "Version"))
	bindReq.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Name"))

	auth := ber.Encode(ber.ClassContext, ber.TypeConstructed, 3, nil, "authentication")
	auth.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, mechanism, "SASL Mech"))
	if creds != nil {
		credPacket := ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "Credentials")
		credPacket.Value = creds
		credPacket.Data.Write(creds)
		auth.AppendChild(credPacket)
	}

	bindReq.AppendChild(auth)
	envelope.AppendChild(bindReq)

	if _, err := c.rawConn.Write(envelope.Bytes()); err != nil {
		return 0, nil, fmt.Errorf("failed to write: %w", err)
	}

	packet, err := c.readLDAPPacket()
	if err != nil {
		return 0, nil, fmt.Errorf("failed to read response: %w", err)
	}

	if len(packet.Children) < 2 {
		return 0, nil, fmt.Errorf("malformed response")
	}

	bindResp := packet.Children[1]
	if len(bindResp.Children) < 3 {
		return 0, nil, fmt.Errorf("malformed bind response")
	}

	resultCode := bindResp.Children[0].Value.(int64)
	diagnosticMsg := ""
	if bindResp.Children[2].Value != nil {
		diagnosticMsg = bindResp.Children[2].Value.(string)
	}

	var serverCreds []byte
	if len(bindResp.Children) > 3 {
		cred := bindResp.Children[3]
		if len(cred.ByteValue) > 0 {
			serverCreds = cred.ByteValue
		} else if cred.Data.Len() > 0 {
			serverCreds = cred.Data.Bytes()
		}
	}

	if resultCode != 0 && resultCode != 14 {
		return resultCode, nil, fmt.Errorf("LDAP bind error (code %d): %s", resultCode, diagnosticMsg)
	}

	return resultCode, serverCreds, nil
}

func (c *Client) readLDAPPacket() (*ber.Packet, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(c.rawConn, header); err != nil {
		return nil, fmt.Errorf("failed to read packet header: %w", err)
	}

	var length int
	if header[1] < 0x80 {
		length = int(header[1])
	} else {
		numBytes := int(header[1] & 0x7F)
		if numBytes > 4 {
			return nil, fmt.Errorf("length too large: %d bytes", numBytes)
		}
		lenBytes := make([]byte, numBytes)
		if _, err := io.ReadFull(c.rawConn, lenBytes); err != nil {
			return nil, fmt.Errorf("failed to read length bytes: %w", err)
		}
		for _, b := range lenBytes {
			length = (length << 8) | int(b)
		}
		header = append(header, lenBytes...)
	}

	body := make([]byte, length)
	if _, err := io.ReadFull(c.rawConn, body); err != nil {
		return nil, fmt.Errorf("failed to read packet body: %w", err)
	}

	fullPacket := append(header, body...)
	packet, err := ber.DecodePacketErr(fullPacket)
	if err != nil {
		return nil, fmt.Errorf("BER decode failed: %w (hex: %s)", err, hex.EncodeToString(fullPacket[:min(64, len(fullPacket))]))
	}

	return packet, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (c *Client) bindWithNTLM() error {
	creds := c.config.Credentials

	if len(creds.NTHash) != 32 {
		return fmt.Errorf("invalid NT hash length: expected 32 hex characters, got %d", len(creds.NTHash))
	}

	_, err := hex.DecodeString(creds.NTHash)
	if err != nil {
		return fmt.Errorf("invalid NT hash format: %w", err)
	}

	err = c.conn.NTLMBindWithHash(creds.Domain, creds.Username, creds.NTHash)
	if err != nil {
		return fmt.Errorf("NTLM bind with hash failed: %w", err)
	}

	return nil
}

func (c *Client) Close() {
	if c.conn != nil {
		c.conn.Close()
	}
}

func (c *Client) SetBaseDN(domain string) {
	parts := strings.Split(domain, ".")
	var dnParts []string
	for _, part := range parts {
		dnParts = append(dnParts, "DC="+part)
	}
	c.baseDN = strings.Join(dnParts, ",")
	c.config.BaseDN = c.baseDN
}

func (c *Client) GetBaseDN() string {
	return c.baseDN
}

// sdFlagsControl returns an LDAP control requesting OWNER + DACL from nTSecurityDescriptor
func (c *Client) sdFlagsControl() ldap.Control {
	return &sdFlagsCtrl{}
}

type sdFlagsCtrl struct{}

func (s *sdFlagsCtrl) GetControlType() string {
	return "1.2.840.113556.1.4.801"
}

func (s *sdFlagsCtrl) Encode() *ber.Packet {
	p := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "1.2.840.113556.1.4.801", "controlType"))
	p.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, true, "criticality"))
	// SDFlagsRequestValue ::= SEQUENCE { Flags INTEGER }
	valPacket := ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "controlValue")
	seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "SDFlagsRequestValue")
	seq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(0x07), "Flags"))
	valPacket.AppendChild(seq)
	p.AppendChild(valPacket)
	return p
}

func (s *sdFlagsCtrl) String() string {
	return "SD Flags Control"
}

func (c *Client) searchWithPaging(filter string, attributes []string, scope int, extraControls ...ldap.Control) ([]*ldap.Entry, error) {
	var entries []*ldap.Entry
	pageSize := uint32(1000)

	searchRequest := ldap.NewSearchRequest(
		c.baseDN,
		scope,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		filter,
		attributes,
		nil,
	)

	pagingControl := ldap.NewControlPaging(pageSize)
	searchRequest.Controls = append(searchRequest.Controls, pagingControl)
	for _, ctrl := range extraControls {
		searchRequest.Controls = append(searchRequest.Controls, ctrl)
	}

	for {
		result, err := c.conn.Search(searchRequest)
		if err != nil {
			return nil, err
		}

		entries = append(entries, result.Entries...)

		pagingResult := ldap.FindControl(result.Controls, ldap.ControlTypePaging)
		if pagingResult == nil {
			break
		}

		cookie := pagingResult.(*ldap.ControlPaging).Cookie
		if len(cookie) == 0 {
			break
		}

		pagingControl.SetCookie(cookie)
	}

	return entries, nil
}

func (c *Client) EnumerateUsers() ([]models.User, error) {
	filter := "(&(objectCategory=person)(objectClass=user))"
	attributes := []string{
		"sAMAccountName", "distinguishedName", "description", "objectSid",
		"homeDirectory", "profilePath", "pwdLastSet", "lastLogon",
		"memberOf", "primaryGroupID", "userAccountControl",
	}
	if c.bloodHoundEnabled() {
		attributes = append(attributes, "adminCount", "servicePrincipalName",
			"nTSecurityDescriptor", "msDS-AllowedToDelegateTo", "sIDHistory",
			"displayName", "mail", "title", "whenCreated")
	}

	var extraControls []ldap.Control
	if c.bloodHoundEnabled() {
		extraControls = append(extraControls, c.sdFlagsControl())
	}

	entries, err := c.searchWithPaging(filter, attributes, ldap.ScopeWholeSubtree, extraControls...)
	if err != nil {
		return nil, fmt.Errorf("user enumeration failed: %w", err)
	}

	var users []models.User
	for _, entry := range entries {
		user := models.User{
			Username:      entry.GetAttributeValue("sAMAccountName"),
			DN:            entry.GetAttributeValue("distinguishedName"),
			Description:   entry.GetAttributeValue("description"),
			HomeDirectory: entry.GetAttributeValue("homeDirectory"),
			ProfilePath:   entry.GetAttributeValue("profilePath"),
			MemberOf:      c.extractGroupNames(entry.GetAttributeValues("memberOf")),
		}

		sidBytes := entry.GetRawAttributeValue("objectSid")
		if len(sidBytes) > 0 {
			user.SID = decodeSID(sidBytes)
		}

		user.PasswordLastSet = parseADTimestamp(entry.GetAttributeValue("pwdLastSet"))
		user.LastLogon = parseADTimestamp(entry.GetAttributeValue("lastLogon"))

		uacStr := entry.GetAttributeValue("userAccountControl")
		if uacStr != "" {
			uac, _ := strconv.Atoi(uacStr)
			user.AccountSettings = parseUACFlags(uac)
			user.Enabled = (uac & models.UACFlags["ACCOUNT_DISABLED"]) == 0
			if c.bloodHoundEnabled() {
				user.UAC = uac
			}
		}

		if c.bloodHoundEnabled() {
			adminCount := entry.GetAttributeValue("adminCount")
			user.AdminCount = adminCount == "1"
			user.SPNs = entry.GetAttributeValues("servicePrincipalName")
			user.RawSD = entry.GetRawAttributeValue("nTSecurityDescriptor")
			user.AllowedToDelegate = entry.GetAttributeValues("msDS-AllowedToDelegateTo")
			user.DisplayName = entry.GetAttributeValue("displayName")
			user.Email = entry.GetAttributeValue("mail")
			user.Title = entry.GetAttributeValue("title")
			user.WhenCreated = parseWhenCreated(entry.GetAttributeValue("whenCreated"))

			for _, rawSIDHist := range entry.GetRawAttributeValues("sIDHistory") {
				if s := decodeSID(rawSIDHist); s != "" {
					user.SIDHistory = append(user.SIDHistory, s)
				}
			}
		}

		primaryGroupID := entry.GetAttributeValue("primaryGroupID")
		if primaryGroupID != "" {
			user.PrimaryGroup = primaryGroupID
			if c.bloodHoundEnabled() {
				user.PrimaryGroupID, _ = strconv.Atoi(primaryGroupID)
			}
		}

		users = append(users, user)
	}

	return users, nil
}

func (c *Client) EnumerateGroups() ([]models.Group, error) {
	filter := "(objectCategory=group)"
	attributes := []string{
		"sAMAccountName", "distinguishedName", "description", "objectSid",
		"memberOf", "member",
	}
	if c.bloodHoundEnabled() {
		attributes = append(attributes, "adminCount", "nTSecurityDescriptor", "whenCreated")
	}

	var extraControls []ldap.Control
	if c.bloodHoundEnabled() {
		extraControls = append(extraControls, c.sdFlagsControl())
	}

	entries, err := c.searchWithPaging(filter, attributes, ldap.ScopeWholeSubtree, extraControls...)
	if err != nil {
		return nil, fmt.Errorf("group enumeration failed: %w", err)
	}

	var groups []models.Group
	for _, entry := range entries {
		group := models.Group{
			Name:        entry.GetAttributeValue("sAMAccountName"),
			DN:          entry.GetAttributeValue("distinguishedName"),
			Description: entry.GetAttributeValue("description"),
			MemberOf:    c.extractGroupNames(entry.GetAttributeValues("memberOf")),
			Members:     c.extractCNs(entry.GetAttributeValues("member")),
		}

		if c.bloodHoundEnabled() {
			group.MemberDNs = entry.GetAttributeValues("member")
			ac := entry.GetAttributeValue("adminCount")
			group.AdminCount = ac == "1"
			group.RawSD = entry.GetRawAttributeValue("nTSecurityDescriptor")
			group.WhenCreated = parseWhenCreated(entry.GetAttributeValue("whenCreated"))
		}

		sidBytes := entry.GetRawAttributeValue("objectSid")
		if len(sidBytes) > 0 {
			group.SID = decodeSID(sidBytes)
		}

		groups = append(groups, group)
	}

	return groups, nil
}

func (c *Client) EnumerateComputers() ([]models.Computer, error) {
	filter := "(objectCategory=computer)"
	attributes := []string{
		"sAMAccountName", "distinguishedName", "description", "objectSid",
		"operatingSystem", "operatingSystemVersion", "memberOf",
		"dNSHostName", "lastLogonTimestamp",
	}
	if c.bloodHoundEnabled() {
		attributes = append(attributes, "userAccountControl", "primaryGroupID", "servicePrincipalName",
			"nTSecurityDescriptor", "msDS-AllowedToDelegateTo",
			"msDS-AllowedToActOnBehalfOfOtherIdentity",
			"whenCreated", "pwdLastSet", "ms-Mcs-AdmPwd")
	}

	var extraControls []ldap.Control
	if c.bloodHoundEnabled() {
		extraControls = append(extraControls, c.sdFlagsControl())
	}

	entries, err := c.searchWithPaging(filter, attributes, ldap.ScopeWholeSubtree, extraControls...)
	if err != nil {
		return nil, fmt.Errorf("computer enumeration failed: %w", err)
	}

	var computers []models.Computer
	for _, entry := range entries {
		name := entry.GetAttributeValue("sAMAccountName")
		name = strings.TrimSuffix(name, "$")

		computer := models.Computer{
			Name:            name,
			DN:              entry.GetAttributeValue("distinguishedName"),
			Description:     entry.GetAttributeValue("description"),
			OperatingSystem: entry.GetAttributeValue("operatingSystem"),
			OSVersion:       entry.GetAttributeValue("operatingSystemVersion"),
			MemberOf:        c.extractGroupNames(entry.GetAttributeValues("memberOf")),
			DNSHostName:     entry.GetAttributeValue("dNSHostName"),
		}

		sidBytes := entry.GetRawAttributeValue("objectSid")
		if len(sidBytes) > 0 {
			computer.SID = decodeSID(sidBytes)
		}

		computer.LastLogonTimestamp = parseADTimestamp(entry.GetAttributeValue("lastLogonTimestamp"))

		if c.bloodHoundEnabled() {
			uacStr := entry.GetAttributeValue("userAccountControl")
			if uacStr != "" {
				uac, _ := strconv.Atoi(uacStr)
				computer.UAC = uac
				computer.Enabled = (uac & models.UACFlags["ACCOUNT_DISABLED"]) == 0
			}
			pgStr := entry.GetAttributeValue("primaryGroupID")
			if pgStr != "" {
				computer.PrimaryGroupID, _ = strconv.Atoi(pgStr)
			}
			computer.SPNs = entry.GetAttributeValues("servicePrincipalName")
			computer.RawSD = entry.GetRawAttributeValue("nTSecurityDescriptor")
			computer.AllowedToDelegate = entry.GetAttributeValues("msDS-AllowedToDelegateTo")
			computer.AllowedToActRaw = entry.GetRawAttributeValue("msDS-AllowedToActOnBehalfOfOtherIdentity")
			computer.WhenCreated = parseWhenCreated(entry.GetAttributeValue("whenCreated"))
			computer.PwdLastSet = parseADTimestamp(entry.GetAttributeValue("pwdLastSet"))
			computer.LAPSPassword = entry.GetAttributeValue("ms-Mcs-AdmPwd")
		}

		computers = append(computers, computer)
	}

	return computers, nil
}

func (c *Client) EnumerateSPNs() ([]models.SPN, error) {
	filter := "(&(servicePrincipalName=*)(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
	attributes := []string{
		"servicePrincipalName", "sAMAccountName", "description",
		"pwdLastSet", "memberOf",
	}

	entries, err := c.searchWithPaging(filter, attributes, ldap.ScopeWholeSubtree)
	if err != nil {
		return nil, fmt.Errorf("SPN enumeration failed: %w", err)
	}

	var spns []models.SPN
	for _, entry := range entries {
		spnValues := entry.GetAttributeValues("servicePrincipalName")
		for _, spnValue := range spnValues {
			spn := models.SPN{
				ServicePrincipalName: spnValue,
				Username:             entry.GetAttributeValue("sAMAccountName"),
				Description:          entry.GetAttributeValue("description"),
				PasswordLastSet:      parseADTimestamp(entry.GetAttributeValue("pwdLastSet")),
				MemberOf:             c.extractGroupNames(entry.GetAttributeValues("memberOf")),
			}
			spns = append(spns, spn)
		}
	}

	return spns, nil
}

func (c *Client) EnumeratePasswordPolicy() (models.PasswordPolicy, error) {
	policy := models.PasswordPolicy{}

	searchRequest := ldap.NewSearchRequest(
		c.baseDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{
			"minPwdLength", "lockoutThreshold", "lockoutDuration",
			"pwdHistoryLength", "pwdProperties", "maxPwdAge", "minPwdAge",
		},
		nil,
	)

	result, err := c.conn.Search(searchRequest)
	if err != nil {
		return policy, fmt.Errorf("password policy enumeration failed: %w", err)
	}

	if len(result.Entries) > 0 {
		entry := result.Entries[0]
		policy.MinPasswordLength, _ = strconv.Atoi(entry.GetAttributeValue("minPwdLength"))
		policy.LockoutThreshold, _ = strconv.Atoi(entry.GetAttributeValue("lockoutThreshold"))
		policy.PasswordsRemembered, _ = strconv.Atoi(entry.GetAttributeValue("pwdHistoryLength"))

		lockoutDur := entry.GetAttributeValue("lockoutDuration")
		if lockoutDur != "" {
			durNano, _ := strconv.ParseInt(lockoutDur, 10, 64)
			if durNano < 0 {
				durNano = -durNano
			}
			policy.LockoutDuration = int(durNano / 600000000)
		}

		pwdProps := entry.GetAttributeValue("pwdProperties")
		if pwdProps != "" {
			props, _ := strconv.Atoi(pwdProps)
			policy.PasswordProperties = parsePasswordProperties(props)
		}
	}

	return policy, nil
}

func (c *Client) EnumerateFGPolicies() ([]models.FineGrainedPasswordPolicy, error) {
	fgppDN := fmt.Sprintf("CN=Password Settings Container,CN=System,%s", c.baseDN)
	filter := "(objectCategory=msDS-PasswordSettings)"
	attributes := []string{
		"cn", "msDS-MinimumPasswordLength", "msDS-LockoutThreshold",
		"msDS-LockoutDuration", "msDS-PasswordHistoryLength",
		"msDS-PasswordComplexityEnabled", "msDS-PSOAppliesTo",
	}

	searchRequest := ldap.NewSearchRequest(
		fgppDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		filter,
		attributes,
		nil,
	)

	result, err := c.conn.Search(searchRequest)
	if err != nil {
		return nil, nil
	}

	var policies []models.FineGrainedPasswordPolicy
	for _, entry := range result.Entries {
		policy := models.FineGrainedPasswordPolicy{
			Name:      entry.GetAttributeValue("cn"),
			AppliesTo: c.extractCNs(entry.GetAttributeValues("msDS-PSOAppliesTo")),
		}

		policy.MinPasswordLength, _ = strconv.Atoi(entry.GetAttributeValue("msDS-MinimumPasswordLength"))
		policy.LockoutThreshold, _ = strconv.Atoi(entry.GetAttributeValue("msDS-LockoutThreshold"))
		policy.PasswordsRemembered, _ = strconv.Atoi(entry.GetAttributeValue("msDS-PasswordHistoryLength"))

		lockoutDur := entry.GetAttributeValue("msDS-LockoutDuration")
		if lockoutDur != "" {
			durNano, _ := strconv.ParseInt(lockoutDur, 10, 64)
			if durNano < 0 {
				durNano = -durNano
			}
			policy.LockoutDuration = int(durNano / 600000000)
		}

		complexity := entry.GetAttributeValue("msDS-PasswordComplexityEnabled")
		policy.PasswordComplexity = complexity == "TRUE"

		policies = append(policies, policy)
	}

	return policies, nil
}

func (c *Client) EnumerateDomainInfo() (models.DomainInfo, error) {
	info := models.DomainInfo{}

	attrs := []string{"objectSid", "msDS-Behavior-Version"}
	if c.bloodHoundEnabled() {
		attrs = append(attrs, "nTSecurityDescriptor")
	}

	var controls []ldap.Control
	if c.bloodHoundEnabled() {
		controls = append(controls, c.sdFlagsControl())
	}

	searchRequest := ldap.NewSearchRequest(
		c.baseDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		attrs,
		controls,
	)

	result, err := c.conn.Search(searchRequest)
	if err != nil {
		return info, err
	}

	if len(result.Entries) > 0 {
		entry := result.Entries[0]
		sidBytes := entry.GetRawAttributeValue("objectSid")
		if len(sidBytes) > 0 {
			info.DomainSID = decodeSID(sidBytes)
		}

		funcLevel := entry.GetAttributeValue("msDS-Behavior-Version")
		info.FunctionalLevel = parseFunctionalLevel(funcLevel)

		if c.bloodHoundEnabled() {
			info.RawSD = entry.GetRawAttributeValue("nTSecurityDescriptor")
		}
	}

	info.Name = c.config.Credentials.Domain

	return info, nil
}

func (c *Client) EnumerateTrusts() ([]models.Trust, error) {
	filter := "(objectClass=trustedDomain)"
	attributes := []string{
		"cn", "trustType", "trustDirection", "trustAttributes",
	}
	if c.bloodHoundEnabled() {
		attributes = append(attributes, "objectSid")
	}

	entries, err := c.searchWithPaging(filter, attributes, ldap.ScopeWholeSubtree)
	if err != nil {
		return nil, nil
	}

	var trusts []models.Trust
	for _, entry := range entries {
		trust := models.Trust{
			TargetDomain: entry.GetAttributeValue("cn"),
		}

		trustType, _ := strconv.Atoi(entry.GetAttributeValue("trustType"))
		trust.TrustType = parseTrustType(trustType)
		trust.TrustTypeRaw = trustType

		trustDir, _ := strconv.Atoi(entry.GetAttributeValue("trustDirection"))
		trust.TrustDirection = parseTrustDirection(trustDir)
		trust.TrustDirectionRaw = trustDir

		trustAttrs, _ := strconv.Atoi(entry.GetAttributeValue("trustAttributes"))
		trust.TrustAttributesRaw = trustAttrs

		if c.bloodHoundEnabled() {
			sidBytes := entry.GetRawAttributeValue("objectSid")
			if len(sidBytes) > 0 {
				trust.TargetDomainSID = decodeSID(sidBytes)
			}
		}

		trusts = append(trusts, trust)
	}

	return trusts, nil
}

// DCOnly enumeration methods - additional LDAP queries gated behind -dconly flag

func (c *Client) EnumerateOUs() ([]models.OU, error) {
	filter := "(objectCategory=organizationalUnit)"
	attributes := []string{
		"ou", "distinguishedName", "objectSid", "nTSecurityDescriptor",
		"gplink", "whenCreated",
	}

	entries, err := c.searchWithPaging(filter, attributes, ldap.ScopeWholeSubtree, c.sdFlagsControl())
	if err != nil {
		return nil, fmt.Errorf("OU enumeration failed: %w", err)
	}

	var ous []models.OU
	for _, entry := range entries {
		ou := models.OU{
			Name:        entry.GetAttributeValue("ou"),
			DN:          entry.GetAttributeValue("distinguishedName"),
			GPLink:      entry.GetAttributeValue("gplink"),
			WhenCreated: parseWhenCreated(entry.GetAttributeValue("whenCreated")),
			RawSD:       entry.GetRawAttributeValue("nTSecurityDescriptor"),
		}

		sidBytes := entry.GetRawAttributeValue("objectSid")
		if len(sidBytes) > 0 {
			ou.SID = decodeSID(sidBytes)
		}

		ous = append(ous, ou)
	}

	return ous, nil
}

func (c *Client) EnumerateGPOs() ([]models.GPO, error) {
	filter := "(objectCategory=groupPolicyContainer)"
	attributes := []string{
		"displayName", "cn", "distinguishedName", "gPCFileSysPath",
		"nTSecurityDescriptor", "whenCreated",
	}

	entries, err := c.searchWithPaging(filter, attributes, ldap.ScopeWholeSubtree, c.sdFlagsControl())
	if err != nil {
		return nil, fmt.Errorf("GPO enumeration failed: %w", err)
	}

	var gpos []models.GPO
	for _, entry := range entries {
		gpo := models.GPO{
			DisplayName:    entry.GetAttributeValue("displayName"),
			Name:           entry.GetAttributeValue("cn"),
			DN:             entry.GetAttributeValue("distinguishedName"),
			GpcFileSysPath: entry.GetAttributeValue("gPCFileSysPath"),
			WhenCreated:    parseWhenCreated(entry.GetAttributeValue("whenCreated")),
			RawSD:          entry.GetRawAttributeValue("nTSecurityDescriptor"),
		}

		gpos = append(gpos, gpo)
	}

	return gpos, nil
}

func (c *Client) EnumerateContainers() ([]models.Container, error) {
	filter := "(objectCategory=container)"
	attributes := []string{
		"cn", "distinguishedName", "objectSid", "nTSecurityDescriptor",
		"whenCreated",
	}

	entries, err := c.searchWithPaging(filter, attributes, ldap.ScopeWholeSubtree, c.sdFlagsControl())
	if err != nil {
		return nil, fmt.Errorf("container enumeration failed: %w", err)
	}

	var containers []models.Container
	for _, entry := range entries {
		container := models.Container{
			Name:        entry.GetAttributeValue("cn"),
			DN:          entry.GetAttributeValue("distinguishedName"),
			WhenCreated: parseWhenCreated(entry.GetAttributeValue("whenCreated")),
			RawSD:       entry.GetRawAttributeValue("nTSecurityDescriptor"),
		}

		sidBytes := entry.GetRawAttributeValue("objectSid")
		if len(sidBytes) > 0 {
			container.SID = decodeSID(sidBytes)
		}

		containers = append(containers, container)
	}

	return containers, nil
}

// Helper functions

func (c *Client) extractGroupNames(dns []string) []string {
	var names []string
	for _, dn := range dns {
		parts := strings.Split(dn, ",")
		if len(parts) > 0 {
			cn := strings.TrimPrefix(parts[0], "CN=")
			names = append(names, cn)
		}
	}
	return names
}

func (c *Client) extractCNs(dns []string) []string {
	return c.extractGroupNames(dns)
}

func decodeSID(b []byte) string {
	if len(b) < 8 {
		return ""
	}

	revision := int(b[0])
	subAuthCount := int(b[1])
	authority := uint64(b[2])<<40 | uint64(b[3])<<32 | uint64(b[4])<<24 |
		uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])

	sid := fmt.Sprintf("S-%d-%d", revision, authority)

	for i := 0; i < subAuthCount && 8+4*i+4 <= len(b); i++ {
		subAuth := binary.LittleEndian.Uint32(b[8+4*i:])
		sid += fmt.Sprintf("-%d", subAuth)
	}

	return sid
}

func parseADTimestamp(timestamp string) time.Time {
	if timestamp == "" || timestamp == "0" {
		return time.Time{}
	}

	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil || ts == 0 {
		return time.Time{}
	}

	const epochDiff = 116444736000000000
	unixNano := (ts - epochDiff) * 100
	return time.Unix(0, unixNano)
}

func parseWhenCreated(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse("20060102150405.0Z", s)
	if err != nil {
		t, _ = time.Parse("20060102150405Z", s)
	}
	return t
}

func parseUACFlags(uac int) []string {
	var flags []string
	for name, value := range models.UACFlags {
		if uac&value != 0 {
			flags = append(flags, name)
		}
	}
	return flags
}

func parsePasswordProperties(props int) []string {
	var properties []string
	for name, value := range models.PasswordPropertyFlags {
		if props&value != 0 {
			properties = append(properties, name)
		}
	}
	return properties
}

func parseFunctionalLevel(level string) string {
	levelMap := map[string]string{
		"0": "Windows 2000",
		"1": "Windows Server 2003 Interim",
		"2": "Windows Server 2003",
		"3": "Windows Server 2008",
		"4": "Windows Server 2008 R2",
		"5": "Windows Server 2012",
		"6": "Windows Server 2012 R2",
		"7": "Windows Server 2016",
	}
	if name, ok := levelMap[level]; ok {
		return name
	}
	return level
}

func parseTrustType(trustType int) string {
	types := map[int]string{
		1: "Downlevel",
		2: "Uplevel",
		3: "MIT",
		4: "DCE",
	}
	if name, ok := types[trustType]; ok {
		return name
	}
	return fmt.Sprintf("%d", trustType)
}

func parseTrustDirection(dir int) string {
	directions := map[int]string{
		0: "Disabled",
		1: "Inbound",
		2: "Outbound",
		3: "Bidirectional",
	}
	if name, ok := directions[dir]; ok {
		return name
	}
	return fmt.Sprintf("%d", dir)
}

func startKDCProxy(socksAddr, kdcAddr string) (string, error) {
	dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		return "", fmt.Errorf("failed to create SOCKS5 dialer: %w", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("failed to listen: %w", err)
	}

	go func() {
		for {
			local, err := listener.Accept()
			if err != nil {
				return
			}
			go func(local net.Conn) {
				defer local.Close()
				remote, err := dialer.Dial("tcp", kdcAddr)
				if err != nil {
					return
				}
				defer remote.Close()
				done := make(chan struct{})
				go func() {
					io.Copy(remote, local)
					done <- struct{}{}
				}()
				io.Copy(local, remote)
				<-done
			}(local)
		}
	}()

	return listener.Addr().String(), nil
}
