package main

import (
	"fmt"
	"os"
	"strings"
	"syscall"

	"govibe/pkg/cli"
	"govibe/pkg/ldap"
	"govibe/pkg/models"
	"govibe/pkg/output"

	"golang.org/x/term"
)

const banner = `
   _____    __      __ _  _
  / ____|   \ \    / /(_)| |
 | |  __  ___\ \  / /  _ | |__    ___
 | | |_ |/ _ \\ \/ /  | || '_ \  / _ \
 | |__| | (_) |\  /   | || |_) ||  __/
  \_____|\___/  \/    |_||_.__/  \___|
`

// Colors
const (
	colorGreen = "\033[92m"
	colorRed   = "\033[91m"
	colorBlue  = "\033[34m"
	colorReset = "\033[0m"
)

func main() {
	fmt.Println(banner)

	config := parseArgs()
	if config == nil {
		return
	}

	// Prompt for password if not provided
	if config.Credentials.Password == "" && config.Credentials.NTHash == "" {
		fmt.Print("Password: ")
		passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			fmt.Printf("%s[-]%s Failed to read password: %v\n", colorRed, colorReset, err)
			os.Exit(1)
		}
		config.Credentials.Password = string(passwordBytes)
	}

	// Create output directory
	if config.OutputDir == "" {
		config.OutputDir = "./" + config.Credentials.Domain
	}

	// Connect and authenticate
	fmt.Printf("%s[*]%s Connecting to %s:%d\n", colorBlue, colorReset, config.DC, config.Port)

	client := ldap.NewClient(config)
	if err := client.Connect(); err != nil {
		fmt.Printf("%s[-]%s Connection failed: %v\n", colorRed, colorReset, err)
		os.Exit(1)
	}
	defer client.Close()

	client.SetBaseDN(config.Credentials.Domain)

	authMethod := "password"
	if config.Credentials.NTHash != "" {
		authMethod = "NTLM hash (pass-the-hash)"
	}
	fmt.Printf("%s[*]%s Authenticating with %s\n", colorBlue, colorReset, authMethod)

	if err := client.Bind(); err != nil {
		fmt.Printf("%s[-]%s Authentication failed: %v\n", colorRed, colorReset, err)
		os.Exit(1)
	}

	fmt.Printf("%s[+]%s Authentication successful\n", colorGreen, colorReset)

	// Enumerate domain
	data := &models.DomainData{}

	fmt.Printf("%s[+]%s Enumerating domain info...\n", colorGreen, colorReset)
	domainInfo, err := client.EnumerateDomainInfo()
	if err != nil {
		fmt.Printf("%s[-]%s Warning: %v\n", colorRed, colorReset, err)
	}
	data.Domain = domainInfo

	fmt.Printf("%s[+]%s Enumerating users...\n", colorGreen, colorReset)
	users, err := client.EnumerateUsers()
	if err != nil {
		fmt.Printf("%s[-]%s Warning: %v\n", colorRed, colorReset, err)
	}
	data.Users = users
	fmt.Printf("%s[+]%s Found %d users\n", colorGreen, colorReset, len(users))

	fmt.Printf("%s[+]%s Enumerating groups...\n", colorGreen, colorReset)
	groups, err := client.EnumerateGroups()
	if err != nil {
		fmt.Printf("%s[-]%s Warning: %v\n", colorRed, colorReset, err)
	}
	data.Groups = groups
	fmt.Printf("%s[+]%s Found %d groups\n", colorGreen, colorReset, len(groups))

	// Resolve primary group names for users
	groupSIDMap := make(map[string]string)
	for _, group := range groups {
		// Extract the RID from the SID
		parts := strings.Split(group.SID, "-")
		if len(parts) > 0 {
			rid := parts[len(parts)-1]
			groupSIDMap[rid] = group.Name
		}
	}
	for i := range data.Users {
		if name, ok := groupSIDMap[data.Users[i].PrimaryGroup]; ok {
			data.Users[i].PrimaryGroup = name
		}
	}

	fmt.Printf("%s[+]%s Enumerating computers...\n", colorGreen, colorReset)
	computers, err := client.EnumerateComputers()
	if err != nil {
		fmt.Printf("%s[-]%s Warning: %v\n", colorRed, colorReset, err)
	}
	data.Computers = computers
	fmt.Printf("%s[+]%s Found %d computers\n", colorGreen, colorReset, len(computers))

	fmt.Printf("%s[+]%s Enumerating SPNs (Kerberoastable accounts)...\n", colorGreen, colorReset)
	spns, err := client.EnumerateSPNs()
	if err != nil {
		fmt.Printf("%s[-]%s Warning: %v\n", colorRed, colorReset, err)
	}
	data.SPNs = spns
	fmt.Printf("%s[+]%s Found %d Kerberoastable accounts\n", colorGreen, colorReset, len(spns))

	fmt.Printf("%s[+]%s Enumerating password policy...\n", colorGreen, colorReset)
	policy, err := client.EnumeratePasswordPolicy()
	if err != nil {
		fmt.Printf("%s[-]%s Warning: %v\n", colorRed, colorReset, err)
	}
	data.PasswordPolicy = policy

	fmt.Printf("%s[+]%s Enumerating fine-grained password policies...\n", colorGreen, colorReset)
	fgpp, err := client.EnumerateFGPolicies()
	if err != nil {
		fmt.Printf("%s[-]%s Warning: %v\n", colorRed, colorReset, err)
	}
	data.FGPolicies = fgpp

	fmt.Printf("%s[+]%s Enumerating domain trusts...\n", colorGreen, colorReset)
	trusts, err := client.EnumerateTrusts()
	if err != nil {
		fmt.Printf("%s[-]%s Warning: %v\n", colorRed, colorReset, err)
	}
	data.Trusts = trusts

	// Always write JSON and HTML output
	fmt.Printf("\n%s[+]%s Writing JSON output to %s\n", colorGreen, colorReset, config.OutputDir)
	jsonWriter := output.NewJSONWriter(config.OutputDir, config.Credentials.Domain)
	if err := jsonWriter.WriteAll(data); err != nil {
		fmt.Printf("%s[-]%s Failed to write JSON: %v\n", colorRed, colorReset, err)
	}

	fmt.Printf("\n%s[+]%s Writing HTML output to %s\n", colorGreen, colorReset, config.OutputDir)
	htmlWriter := output.NewHTMLWriter(config.OutputDir, config.Credentials.Domain)
	if err := htmlWriter.WriteAll(data); err != nil {
		fmt.Printf("%s[-]%s Failed to write HTML: %v\n", colorRed, colorReset, err)
	}

	fmt.Printf("\n%s[+]%s Enumeration complete!\n", colorGreen, colorReset)

	// Start interactive shell
	shell := cli.NewShell(data)
	shell.Run()
}

func parseArgs() *models.Config {
	config := &models.Config{
		UseLDAPS: true,
		Port:     636,
	}

	args := os.Args[1:]

	if len(args) == 0 {
		printUsage()
		return nil
	}

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-U", "--username":
			if i+1 < len(args) {
				config.Credentials.Username = args[i+1]
				i++
			}
		case "-P", "--password":
			if i+1 < len(args) {
				config.Credentials.Password = args[i+1]
				i++
			}
		case "-H", "--hash":
			if i+1 < len(args) {
				hash := args[i+1]
				// Support both full hash (LM:NT) and just NT hash
				if strings.Contains(hash, ":") {
					parts := strings.Split(hash, ":")
					if len(parts) == 2 {
						hash = parts[1] // Use NT hash
					}
				}
				config.Credentials.NTHash = hash
				i++
			}
		case "-D", "--domain":
			if i+1 < len(args) {
				config.Credentials.Domain = args[i+1]
				i++
			}
		case "-I", "--dc-ip":
			if i+1 < len(args) {
				config.DC = args[i+1]
				i++
			}
		case "-p", "--port":
			if i+1 < len(args) {
				fmt.Sscanf(args[i+1], "%d", &config.Port)
				i++
			}
		case "-o", "--output":
			if i+1 < len(args) {
				config.OutputDir = args[i+1]
				i++
			}
		case "-u", "--unencrypted":
			config.UseLDAPS = false
			if config.Port == 636 {
				config.Port = 389
			}
		case "-x", "--proxy":
			if i+1 < len(args) {
				config.ProxyAddr = args[i+1]
				i++
			}
		case "-h", "--help":
			printUsage()
			return nil
		}
	}

	// Validate required arguments
	if config.Credentials.Username == "" {
		fmt.Printf("%s[-]%s Username is required (-U)\n", colorRed, colorReset)
		return nil
	}
	if config.Credentials.Domain == "" {
		fmt.Printf("%s[-]%s Domain is required (-D)\n", colorRed, colorReset)
		return nil
	}
	if config.DC == "" {
		fmt.Printf("%s[-]%s Domain Controller IP is required (-I)\n", colorRed, colorReset)
		return nil
	}

	return config
}

func printUsage() {
	fmt.Println("Usage: govibe [options]")
	fmt.Println("")
	fmt.Println("Required:")
	fmt.Println("  -U, --username    Username for authentication")
	fmt.Println("  -D, --domain      Fully Qualified Domain Name")
	fmt.Println("  -I, --dc-ip       IP address of Domain Controller")
	fmt.Println("")
	fmt.Println("Authentication (one required):")
	fmt.Println("  -P, --password    Password for authentication")
	fmt.Println("  -H, --hash        NT hash for pass-the-hash (format: LMHASH:NTHASH or just NTHASH)")
	fmt.Println("")
	fmt.Println("Optional:")
	fmt.Println("  -p, --port        LDAP port (default: 636 for LDAPS, 389 for LDAP)")
	fmt.Println("  -u, --unencrypted Use unencrypted LDAP instead of LDAPS")
	fmt.Println("  -x, --proxy       SOCKS5 proxy address (e.g., 127.0.0.1:1080)")
	fmt.Println("  -o, --output      Output directory for JSON/HTML files (default: ./<domain>)")
	fmt.Println("  -h, --help        Show this help message")
	fmt.Println("")
	fmt.Println("Examples:")
	fmt.Println("  govibe -U admin -P 'Password123' -D corp.local -I 192.168.1.10")
	fmt.Println("  govibe -U admin -H 'aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0' -D corp.local -I 192.168.1.10")
	fmt.Println("  govibe -U admin -H '31d6cfe0d16ae931b73c59d7e0c089c0' -D corp.local -I 192.168.1.10")
	fmt.Println("")
	fmt.Println("With SOCKS5 proxy (instead of proxychains):")
	fmt.Println("  govibe -U admin -P 'Password123' -D corp.local -I 10.10.10.10 -x 127.0.0.1:1080")
	fmt.Println("  govibe -U admin -H 'hash' -D corp.local -I 10.10.10.10 -x 127.0.0.1:1080 -u")
}
