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

// Client handles LDAP connections and queries
type Client struct {
	conn    *ldap.Conn
	rawConn net.Conn // kept for Kerberos pre-auth on raw connection
	config  *models.Config
	baseDN  string
}

// NewClient creates a new LDAP client
func NewClient(config *models.Config) *Client {
	return &Client{
		config: config,
	}
}

// Connect establishes an LDAP connection
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

	// Check if we're using a SOCKS5 proxy
	if c.config.ProxyAddr != "" {
		fmt.Printf("[*] Using SOCKS5 proxy: %s\n", c.config.ProxyAddr)
		dialer, err := proxy.SOCKS5("tcp", c.config.ProxyAddr, nil, proxy.Direct)
		if err != nil {
			return fmt.Errorf("failed to create SOCKS5 dialer: %w", err)
		}

		// Use context for timeout
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		fmt.Printf("[*] Dialing %s via proxy...\n", address)
		if contextDialer, ok := dialer.(proxy.ContextDialer); ok {
			tcpConn, err = contextDialer.DialContext(ctx, "tcp", address)
		} else {
			tcpConn, err = dialer.Dial("tcp", address)
		}
	} else {
		fmt.Printf("[*] Dialing %s...\n", address)
		tcpConn, err = net.DialTimeout("tcp", address, 30*time.Second)
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

	// For Kerberos, delay ldap.Conn creation until after SASL bind on raw conn
	if c.config.Credentials.UseKerberos {
		return nil
	}

	c.conn = ldap.NewConn(c.rawConn, c.config.UseLDAPS)
	c.conn.Start()
	c.conn.SetTimeout(30 * time.Second)

	return nil
}

// Bind authenticates to the LDAP server
func (c *Client) Bind() error {
	creds := c.config.Credentials

	if creds.UseKerberos {
		return c.bindWithKerberos()
	}

	// If NT hash is provided, use NTLM authentication
	if creds.NTHash != "" {
		return c.bindWithNTLM()
	}

	// Standard simple bind with password
	bindDN := fmt.Sprintf("%s@%s", creds.Username, creds.Domain)
	err := c.conn.Bind(bindDN, creds.Password)
	if err != nil {
		return fmt.Errorf("LDAP bind failed: %w", err)
	}

	return nil
}

// bindWithKerberos performs Kerberos authentication using a ccache file.
// Uses GSS-SPNEGO SASL bind on the raw connection (same approach as impacket),
// then creates the ldap.Conn for subsequent queries.
func (c *Client) bindWithKerberos() error {
	creds := c.config.Credentials
	realm := strings.ToUpper(creds.Domain)

	// Resolve ccache path
	ccachePath := creds.CCachePath
	if ccachePath == "" {
		ccachePath = os.Getenv("KRB5CCNAME")
	}
	if ccachePath == "" {
		return fmt.Errorf("no ccache path provided and KRB5CCNAME not set")
	}
	ccachePath = strings.TrimPrefix(ccachePath, "FILE:")
	ccachePath = strings.TrimPrefix(ccachePath, "file:")

	// Build krb5 config programmatically
	kdcAddr := fmt.Sprintf("%s:88", c.config.DC)

	// If using a SOCKS proxy, set up a local TCP forwarder for KDC traffic
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

	// Load ccache and create Kerberos client
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

	// Build SPN
	host := creds.DCHost
	if host == "" {
		host = c.config.DC
	}
	spn := fmt.Sprintf("ldap/%s", host)

	// Get service ticket
	tkt, sessionKey, err := cl.GetServiceTicket(spn)
	if err != nil {
		return fmt.Errorf("failed to get service ticket for %s: %w", spn, err)
	}

	// Build KRB5 AP-REQ token WITHOUT ContextFlagInteg/ContextFlagConf.
	// Over LDAPS, TLS provides integrity — requesting sign/seal causes AD to
	// reject with "Cannot bind using sign/seal on a connection on which TLS
	// or SSL is in effect" (error code 53).
	krb5Token, err := spnego.NewKRB5TokenAPREQ(cl, tkt, sessionKey, []int{}, []int{})
	if err != nil {
		return fmt.Errorf("failed to create KRB5 AP-REQ token: %w", err)
	}
	mechTokenBytes, err := krb5Token.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal KRB5 token: %w", err)
	}

	// Wrap in SPNEGO NegTokenInit
	negInit := spnego.NegTokenInit{
		MechTypes:      []asn1.ObjectIdentifier{gssapi.OIDKRB5.OID()},
		MechTokenBytes: mechTokenBytes,
	}
	tokenBytes, err := negInit.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal NegTokenInit: %w", err)
	}

	// Wrap with GSS-API OID header: [APPLICATION 0] { SPNEGO OID || NegTokenInit }
	oidBytes, _ := asn1.Marshal(gssapi.OIDSPNEGO.OID())
	tokenBytes = asn1tools.AddASNAppTag(append(oidBytes, tokenBytes...), 0)

	// Send GSS-SPNEGO SASL bind on raw connection
	if err := c.sendSPNEGOBind(tokenBytes); err != nil {
		return err
	}

	// Auth succeeded — create ldap.Conn on the same connection for queries
	// Over LDAPS, TLS provides integrity so no SASL wrapping needed
	c.conn = ldap.NewConn(c.rawConn, c.config.UseLDAPS)
	c.conn.Start()
	c.conn.SetTimeout(30 * time.Second)

	return nil
}

// sendSPNEGOBind sends a GSS-SPNEGO SASL bind request on the raw connection
// and handles the multi-leg exchange if needed (same approach as impacket/netexec).
func (c *Client) sendSPNEGOBind(token []byte) error {
	// Leg 1: Send SPNEGO NegTokenInit
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

	// Leg 2: Send empty continuation
	resultCode, _, err = c.sendSASLBind(2, "GSS-SPNEGO", nil)
	if err != nil {
		return fmt.Errorf("SPNEGO bind leg 2 failed: %w", err)
	}
	if resultCode != 0 {
		return fmt.Errorf("LDAP SPNEGO bind error on leg 2 (code %d)", resultCode)
	}

	return nil
}

// sendSASLBind sends a single SASL bind request on the raw connection and reads the response.
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

	// Extract server SASL credentials if present
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

// readLDAPPacket reads a single BER-encoded LDAP packet from the raw connection.
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

// bindWithNTLM performs NTLM authentication using pass-the-hash
func (c *Client) bindWithNTLM() error {
	creds := c.config.Credentials

	// Validate the NT hash format (should be 32 hex characters)
	if len(creds.NTHash) != 32 {
		return fmt.Errorf("invalid NT hash length: expected 32 hex characters, got %d", len(creds.NTHash))
	}

	// Validate it's valid hex
	_, err := hex.DecodeString(creds.NTHash)
	if err != nil {
		return fmt.Errorf("invalid NT hash format: %w", err)
	}

	// Use NTLMBindWithHash which accepts the hash as a string
	// The go-ldap library with go-ntlmssp supports this via NTLMBindWithHash
	err = c.conn.NTLMBindWithHash(creds.Domain, creds.Username, creds.NTHash)
	if err != nil {
		return fmt.Errorf("NTLM bind with hash failed: %w", err)
	}

	return nil
}

// Close closes the LDAP connection
func (c *Client) Close() {
	if c.conn != nil {
		c.conn.Close()
	}
}

// SetBaseDN sets the base DN for searches
func (c *Client) SetBaseDN(domain string) {
	parts := strings.Split(domain, ".")
	var dnParts []string
	for _, part := range parts {
		dnParts = append(dnParts, "DC="+part)
	}
	c.baseDN = strings.Join(dnParts, ",")
	c.config.BaseDN = c.baseDN
}

// GetBaseDN returns the current base DN
func (c *Client) GetBaseDN() string {
	return c.baseDN
}

// searchWithPaging performs a paged LDAP search
func (c *Client) searchWithPaging(filter string, attributes []string, scope int) ([]*ldap.Entry, error) {
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

	// Use paging control for large result sets
	pagingControl := ldap.NewControlPaging(pageSize)
	searchRequest.Controls = append(searchRequest.Controls, pagingControl)

	for {
		result, err := c.conn.Search(searchRequest)
		if err != nil {
			return nil, err
		}

		entries = append(entries, result.Entries...)

		// Check if there are more pages
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

// EnumerateUsers enumerates all users in the domain
func (c *Client) EnumerateUsers() ([]models.User, error) {
	filter := "(&(objectCategory=person)(objectClass=user))"
	attributes := []string{
		"sAMAccountName", "distinguishedName", "description", "objectSid",
		"homeDirectory", "profilePath", "pwdLastSet", "lastLogon",
		"memberOf", "primaryGroupID", "userAccountControl",
	}

	entries, err := c.searchWithPaging(filter, attributes, ldap.ScopeWholeSubtree)
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

		// Parse SID
		sidBytes := entry.GetRawAttributeValue("objectSid")
		if len(sidBytes) > 0 {
			user.SID = decodeSID(sidBytes)
		}

		// Parse timestamps
		user.PasswordLastSet = parseADTimestamp(entry.GetAttributeValue("pwdLastSet"))
		user.LastLogon = parseADTimestamp(entry.GetAttributeValue("lastLogon"))

		// Parse UAC flags
		uacStr := entry.GetAttributeValue("userAccountControl")
		if uacStr != "" {
			uac, _ := strconv.Atoi(uacStr)
			user.AccountSettings = parseUACFlags(uac)
			user.Enabled = (uac & models.UACFlags["ACCOUNT_DISABLED"]) == 0
		}

		// Get primary group ID
		primaryGroupID := entry.GetAttributeValue("primaryGroupID")
		if primaryGroupID != "" {
			user.PrimaryGroup = primaryGroupID // Will be resolved later
		}

		users = append(users, user)
	}

	return users, nil
}

// EnumerateGroups enumerates all groups in the domain
func (c *Client) EnumerateGroups() ([]models.Group, error) {
	filter := "(objectCategory=group)"
	attributes := []string{
		"sAMAccountName", "distinguishedName", "description", "objectSid",
		"memberOf", "member",
	}

	entries, err := c.searchWithPaging(filter, attributes, ldap.ScopeWholeSubtree)
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

		// Parse SID
		sidBytes := entry.GetRawAttributeValue("objectSid")
		if len(sidBytes) > 0 {
			group.SID = decodeSID(sidBytes)
		}

		groups = append(groups, group)
	}

	return groups, nil
}

// EnumerateComputers enumerates all computers in the domain
func (c *Client) EnumerateComputers() ([]models.Computer, error) {
	filter := "(objectCategory=computer)"
	attributes := []string{
		"sAMAccountName", "distinguishedName", "description", "objectSid",
		"operatingSystem", "operatingSystemVersion", "memberOf",
		"dNSHostName", "lastLogonTimestamp",
	}

	entries, err := c.searchWithPaging(filter, attributes, ldap.ScopeWholeSubtree)
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

		// Parse SID
		sidBytes := entry.GetRawAttributeValue("objectSid")
		if len(sidBytes) > 0 {
			computer.SID = decodeSID(sidBytes)
		}

		// Parse last logon timestamp
		computer.LastLogonTimestamp = parseADTimestamp(entry.GetAttributeValue("lastLogonTimestamp"))

		computers = append(computers, computer)
	}

	return computers, nil
}

// EnumerateSPNs enumerates Kerberoastable accounts
func (c *Client) EnumerateSPNs() ([]models.SPN, error) {
	// Find user accounts with SPNs set (excludes computers and disabled accounts)
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

// EnumeratePasswordPolicy gets the domain password policy
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

		// Parse lockout duration (stored as negative 100-nanosecond intervals)
		lockoutDur := entry.GetAttributeValue("lockoutDuration")
		if lockoutDur != "" {
			durNano, _ := strconv.ParseInt(lockoutDur, 10, 64)
			if durNano < 0 {
				durNano = -durNano
			}
			policy.LockoutDuration = int(durNano / 600000000) // Convert to minutes
		}

		// Parse password properties
		pwdProps := entry.GetAttributeValue("pwdProperties")
		if pwdProps != "" {
			props, _ := strconv.Atoi(pwdProps)
			policy.PasswordProperties = parsePasswordProperties(props)
		}
	}

	return policy, nil
}

// EnumerateFGPolicies gets Fine-Grained Password Policies
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
		// Fine-grained policies may not exist
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

// EnumerateDomainInfo gets basic domain information
func (c *Client) EnumerateDomainInfo() (models.DomainInfo, error) {
	info := models.DomainInfo{}

	// Get domain info from root
	searchRequest := ldap.NewSearchRequest(
		c.baseDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"objectSid", "msDS-Behavior-Version"},
		nil,
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
	}

	// Extract domain name from baseDN
	info.Name = c.config.Credentials.Domain

	return info, nil
}

// EnumerateTrusts gets domain trust relationships
func (c *Client) EnumerateTrusts() ([]models.Trust, error) {
	filter := "(objectClass=trustedDomain)"
	attributes := []string{
		"cn", "trustType", "trustDirection", "trustAttributes",
	}

	entries, err := c.searchWithPaging(filter, attributes, ldap.ScopeWholeSubtree)
	if err != nil {
		return nil, nil // Trusts may not be accessible
	}

	var trusts []models.Trust
	for _, entry := range entries {
		trust := models.Trust{
			TargetDomain: entry.GetAttributeValue("cn"),
		}

		trustType, _ := strconv.Atoi(entry.GetAttributeValue("trustType"))
		trust.TrustType = parseTrustType(trustType)

		trustDir, _ := strconv.Atoi(entry.GetAttributeValue("trustDirection"))
		trust.TrustDirection = parseTrustDirection(trustDir)

		trusts = append(trusts, trust)
	}

	return trusts, nil
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

// decodeSID decodes a binary SID to string format
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

// parseADTimestamp converts Windows FILETIME to time.Time
func parseADTimestamp(timestamp string) time.Time {
	if timestamp == "" || timestamp == "0" {
		return time.Time{}
	}

	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil || ts == 0 {
		return time.Time{}
	}

	// Windows FILETIME epoch is January 1, 1601
	// Convert 100-nanosecond intervals to Unix timestamp
	const epochDiff = 116444736000000000 // 100-ns intervals between 1601 and 1970
	unixNano := (ts - epochDiff) * 100
	return time.Unix(0, unixNano)
}

// parseUACFlags extracts UAC flag names from the integer value
func parseUACFlags(uac int) []string {
	var flags []string
	for name, value := range models.UACFlags {
		if uac&value != 0 {
			flags = append(flags, name)
		}
	}
	return flags
}

// parsePasswordProperties extracts password property names from the integer value
func parsePasswordProperties(props int) []string {
	var properties []string
	for name, value := range models.PasswordPropertyFlags {
		if props&value != 0 {
			properties = append(properties, name)
		}
	}
	return properties
}

// parseFunctionalLevel converts the functional level integer to a readable string
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

// parseTrustType converts trust type integer to string
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

// parseTrustDirection converts trust direction integer to string
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

// startKDCProxy creates a local TCP listener that forwards connections to the
// KDC through a SOCKS5 proxy. Returns the local address to use as KDC.
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
