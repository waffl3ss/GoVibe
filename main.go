package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"govibe/pkg/cache"
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
                          @waffl3ss
`

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

	// Set default output directory
	if config.OutputDir == "" {
		config.OutputDir = "./" + config.Credentials.Domain
	}

	// Handle --rm-db early exit
	if config.RemoveDB {
		path := cache.CachePath(config.OutputDir, config.Credentials.Domain)
		if err := cache.RemoveCache(config.OutputDir, config.Credentials.Domain); err != nil {
			fmt.Printf("%s[-]%s %v\n", colorRed, colorReset, err)
			os.Exit(1)
		}
		fmt.Printf("%s[+]%s Removed cache: %s\n", colorGreen, colorReset, path)
		return
	}

	var data *models.DomainData

	if config.Offline {
		// Offline mode: load from cache
		fmt.Printf("%s[*]%s Loading cached data for %s...\n", colorBlue, colorReset, config.Credentials.Domain)
		var err error
		data, err = cache.LoadCache(config.OutputDir, config.Credentials.Domain)
		if err != nil {
			fmt.Printf("%s[-]%s %v\n", colorRed, colorReset, err)
			os.Exit(1)
		}
		fmt.Printf("%s[+]%s Loaded %d users, %d groups, %d computers from cache\n",
			colorGreen, colorReset, len(data.Users), len(data.Groups), len(data.Computers))
	} else {
		// Online mode: connect and enumerate
		if config.Credentials.Password == "" && config.Credentials.NTHash == "" && !config.Credentials.UseKerberos && !config.Credentials.NoPass {
			fmt.Print("Password: ")
			passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
			fmt.Println()
			if err != nil {
				fmt.Printf("%s[-]%s Failed to read password: %v\n", colorRed, colorReset, err)
				os.Exit(1)
			}
			config.Credentials.Password = string(passwordBytes)
		}

		fmt.Printf("%s[*]%s Connecting to %s:%d\n", colorBlue, colorReset, config.DC, config.Port)

		client := ldap.NewClient(config)
		if err := client.Connect(); err != nil {
			fmt.Printf("%s[-]%s Connection failed: %v\n", colorRed, colorReset, err)
			os.Exit(1)
		}
		defer client.Close()

		client.SetBaseDN(config.Credentials.Domain)

		authMethod := "password"
		if config.Credentials.UseKerberos {
			authMethod = "Kerberos (ccache)"
		} else if config.Credentials.NTHash != "" {
			authMethod = "NTLM hash (pass-the-hash)"
		}
		fmt.Printf("%s[*]%s Authenticating with %s\n", colorBlue, colorReset, authMethod)

		if err := client.Bind(); err != nil {
			fmt.Printf("%s[-]%s Authentication failed: %v\n", colorRed, colorReset, err)
			os.Exit(1)
		}

		fmt.Printf("%s[+]%s Authentication successful\n", colorGreen, colorReset)

		data = &models.DomainData{}

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

		// DCOnly enumeration (additional LDAP queries)
		if config.DCOnly {
			fmt.Printf("%s[+]%s DCOnly: Enumerating OUs...\n", colorGreen, colorReset)
			ous, err := client.EnumerateOUs()
			if err != nil {
				fmt.Printf("%s[-]%s Warning: %v\n", colorRed, colorReset, err)
			}
			data.OUs = ous
			fmt.Printf("%s[+]%s Found %d OUs\n", colorGreen, colorReset, len(ous))

			fmt.Printf("%s[+]%s DCOnly: Enumerating GPOs...\n", colorGreen, colorReset)
			gpos, err := client.EnumerateGPOs()
			if err != nil {
				fmt.Printf("%s[-]%s Warning: %v\n", colorRed, colorReset, err)
			}
			data.GPOs = gpos
			fmt.Printf("%s[+]%s Found %d GPOs\n", colorGreen, colorReset, len(gpos))

			fmt.Printf("%s[+]%s DCOnly: Enumerating containers...\n", colorGreen, colorReset)
			containers, err := client.EnumerateContainers()
			if err != nil {
				fmt.Printf("%s[-]%s Warning: %v\n", colorRed, colorReset, err)
			}
			data.Containers = containers
			fmt.Printf("%s[+]%s Found %d containers\n", colorGreen, colorReset, len(containers))
		}

		// Save cache for offline use
		fmt.Printf("%s[*]%s Saving cache...\n", colorBlue, colorReset)
		if err := cache.SaveCache(config.OutputDir, config.Credentials.Domain, data); err != nil {
			fmt.Printf("%s[-]%s Warning: failed to save cache: %v\n", colorRed, colorReset, err)
		}
	}

	if !config.Offline {
		// Write output
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

		if config.BloodHound {
			fmt.Printf("\n%s[+]%s Writing BloodHound CE output...\n", colorGreen, colorReset)
			bhWriter := output.NewBloodHoundWriter(config.OutputDir, config.Credentials.Domain)
			zipPath, err := bhWriter.WriteAll(data)
			if err != nil {
				fmt.Printf("%s[-]%s Failed to write BloodHound data: %v\n", colorRed, colorReset, err)
			} else {
				fmt.Printf("%s[+]%s BloodHound CE zip: %s\n", colorGreen, colorReset, zipPath)
			}
		}

		if config.BloodHoundLegacy {
			fmt.Printf("\n%s[+]%s Writing BloodHound Legacy output...\n", colorGreen, colorReset)
			bhWriter := output.NewBloodHoundLegacyWriter(config.OutputDir, config.Credentials.Domain)
			zipPath, err := bhWriter.WriteAll(data)
			if err != nil {
				fmt.Printf("%s[-]%s Failed to write BloodHound Legacy data: %v\n", colorRed, colorReset, err)
			} else {
				fmt.Printf("%s[+]%s BloodHound Legacy zip: %s\n", colorGreen, colorReset, zipPath)
			}
		}

		fmt.Printf("\n%s[+]%s Enumeration complete!\n", colorGreen, colorReset)
	}

	// Start interactive shell
	shell := cli.NewShell(data)
	shell.Run()
}

func parseArgs() *models.Config {
	config := &models.Config{
		UseLDAPS: true,
		Port:     636,
		Timeout:  30 * time.Second,
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
				if strings.Contains(hash, ":") {
					parts := strings.Split(hash, ":")
					if len(parts) == 2 {
						hash = parts[1]
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
		case "-k", "--kerberos":
			config.Credentials.UseKerberos = true
		case "--no-pass":
			config.Credentials.NoPass = true
		case "--ccache":
			if i+1 < len(args) {
				config.Credentials.CCachePath = args[i+1]
				config.Credentials.UseKerberos = true
				i++
			}
		case "--dc-host":
			if i+1 < len(args) {
				config.Credentials.DCHost = args[i+1]
				i++
			}
		case "-b", "--bloodhound":
			config.BloodHound = true
		case "--bloodhound-legacy":
			config.BloodHoundLegacy = true
		case "-t", "--timeout":
			if i+1 < len(args) {
				sec, err := strconv.Atoi(args[i+1])
				if err == nil && sec > 0 {
					config.Timeout = time.Duration(sec) * time.Second
				}
				i++
			}
		case "--dconly", "-dconly":
			config.DCOnly = true
		case "--offline":
			config.Offline = true
		case "--rm-db":
			config.RemoveDB = true
		case "-h", "--help":
			printUsage()
			return nil
		}
	}

	// Validate
	if config.Credentials.Domain == "" {
		fmt.Printf("%s[-]%s Domain is required (-D)\n", colorRed, colorReset)
		return nil
	}

	if config.Offline || config.RemoveDB {
		// These modes only need -D
		return config
	}

	if config.Credentials.Username == "" {
		fmt.Printf("%s[-]%s Username is required (-U)\n", colorRed, colorReset)
		return nil
	}
	if config.DC == "" {
		fmt.Printf("%s[-]%s Domain Controller IP is required (-I)\n", colorRed, colorReset)
		return nil
	}

	if config.DCOnly && !config.BloodHound && !config.BloodHoundLegacy {
		fmt.Printf("%s[-]%s --dconly requires -b or --bloodhound-legacy\n", colorRed, colorReset)
		return nil
	}

	return config
}

func printUsage() {
	fmt.Println("Usage: govibe [options]")
	fmt.Println("")
	fmt.Println("Required:")
	fmt.Println("  -U, --username        Username for authentication")
	fmt.Println("  -D, --domain          Fully Qualified Domain Name")
	fmt.Println("  -I, --dc-ip           IP address of Domain Controller")
	fmt.Println("")
	fmt.Println("Authentication (one required):")
	fmt.Println("  -P, --password        Password for authentication")
	fmt.Println("  -H, --hash            NT hash for pass-the-hash (format: LMHASH:NTHASH or just NTHASH)")
	fmt.Println("  -k, --kerberos        Use Kerberos authentication (ccache)")
	fmt.Println("  --no-pass             Don't prompt for password")
	fmt.Println("")
	fmt.Println("Kerberos:")
	fmt.Println("  --ccache <path>       Path to ccache file (default: KRB5CCNAME env var)")
	fmt.Println("  --dc-host <host>      DC hostname for Kerberos SPN (e.g., dc01.corp.local)")
	fmt.Println("")
	fmt.Println("BloodHound:")
	fmt.Println("  -b, --bloodhound      Generate BloodHound CE (v5) compatible zip file")
	fmt.Println("  --bloodhound-legacy   Generate BloodHound Legacy (v4) compatible zip file")
	fmt.Println("  --dconly              Expand collection with OUs, GPOs, and Containers (requires -b or --bloodhound-legacy)")
	fmt.Println("")
	fmt.Println("Optional:")
	fmt.Println("  -p, --port            LDAP port (default: 636 for LDAPS, 389 for LDAP)")
	fmt.Println("  -u, --unencrypted     Use unencrypted LDAP instead of LDAPS")
	fmt.Println("  -x, --proxy           SOCKS5 proxy address (e.g., 127.0.0.1:1080)")
	fmt.Println("  -o, --output          Output directory for JSON/HTML files (default: ./<domain>)")
	fmt.Println("  -t, --timeout         Connection timeout in seconds (default: 30)")
	fmt.Println("  --offline             Load cached data and open interactive shell (no LDAP, no file writes)")
	fmt.Println("  --rm-db               Remove cached data for the specified domain")
	fmt.Println("  -h, --help            Show this help message")
	fmt.Println("")
	fmt.Println("Examples:")
	fmt.Println("  govibe -U admin -P 'Password123' -D corp.local -I 192.168.1.10")
	fmt.Println("  govibe -U admin -H '31d6cfe0d16ae931b73c59d7e0c089c0' -D corp.local -I 192.168.1.10")
	fmt.Println("  govibe -U admin -P 'Password123' -D corp.local -I 192.168.1.10 -b")
	fmt.Println("  govibe -U admin -P 'Password123' -D corp.local -I 192.168.1.10 -b --dconly")
	fmt.Println("  govibe -U admin -P 'Password123' -D corp.local -I 192.168.1.10 --bloodhound-legacy")
	fmt.Println("  govibe -U admin -P 'Password123' -D corp.local -I 192.168.1.10 -t 60")
	fmt.Println("")
	fmt.Println("With Kerberos (ccache):")
	fmt.Println("  govibe -k -U admin -D corp.local -I 192.168.1.10 --dc-host dc01.corp.local")
	fmt.Println("  govibe -k -U admin -D corp.local -I 192.168.1.10 --ccache /tmp/admin.ccache --dc-host dc01.corp.local")
	fmt.Println("")
	fmt.Println("With SOCKS5 proxy:")
	fmt.Println("  govibe -U admin -P 'Password123' -D corp.local -I 10.10.10.10 -x 127.0.0.1:1080")
	fmt.Println("")
	fmt.Println("Offline / Cache:")
	fmt.Println("  govibe --offline -D corp.local                    # Load cached data, open interactive shell")
	fmt.Println("  govibe --rm-db -D corp.local                      # Remove cached data for domain")
}
