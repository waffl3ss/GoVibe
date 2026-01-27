package cli

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"govibe/pkg/models"
)

// Colors for terminal output
const (
	ColorGreen  = "\033[92m"
	ColorRed    = "\033[91m"
	ColorBlue   = "\033[34m"
	ColorYellow = "\033[93m"
	ColorReset  = "\033[0m"
)

// Shell provides an interactive command-line interface
type Shell struct {
	data   *models.DomainData
	prompt string
}

// NewShell creates a new interactive shell
func NewShell(data *models.DomainData) *Shell {
	return &Shell{
		data:   data,
		prompt: ">> ",
	}
}

// Run starts the interactive shell
func (s *Shell) Run() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("\nType 'help' for available commands")
	fmt.Println()

	for {
		fmt.Print(s.prompt)
		input, err := reader.ReadString('\n')
		if err != nil {
			break
		}

		input = strings.TrimSpace(input)
		if input == "" {
			continue
		}

		parts := strings.SplitN(input, " ", 2)
		cmd := strings.ToLower(parts[0])
		args := ""
		if len(parts) > 1 {
			args = parts[1]
		}

		switch cmd {
		case "help":
			s.cmdHelp()
		case "show":
			s.cmdShow(args)
		case "net":
			s.cmdNet(args)
		case "search":
			s.cmdSearch(args)
		case "list":
			s.cmdList(args)
		case "columns":
			s.cmdColumns(args)
		case "clear":
			s.cmdClear()
		case "exit", "quit":
			fmt.Printf("%s[*]%s Exiting...\n", ColorBlue, ColorReset)
			return
		default:
			fmt.Printf("%s[-]%s Unknown command: %s\n", ColorRed, ColorReset, cmd)
		}
	}
}

func (s *Shell) cmdHelp() {
	fmt.Println("Commands")
	fmt.Println("========")
	fmt.Println("clear                       Clear the screen")
	fmt.Println("help                        Display this help menu")
	fmt.Println("show <type>                 Show data (users, groups, computers, spns, pwdpolicy, fgpolicy)")
	fmt.Println("net <type> <name>           View details for a specific user, group, or computer")
	fmt.Println("search <term>               Search all tables for a keyword")
	fmt.Println("list <type>                 List names only (users, groups, computers, spns)")
	fmt.Println("columns <type>              Display column names for a table")
	fmt.Println("exit                        Exit GoVibe")
}

func (s *Shell) cmdShow(args string) {
	switch strings.ToLower(args) {
	case "users":
		s.showUsers()
	case "groups":
		s.showGroups()
	case "computers":
		s.showComputers()
	case "spns", "spn":
		s.showSPNs()
	case "pwdpolicy", "policy":
		s.showPasswordPolicy()
	case "fgpolicy", "fgpp":
		s.showFGPolicy()
	default:
		fmt.Printf("%s[-]%s Usage: show <users|groups|computers|spns|pwdpolicy|fgpolicy>\n", ColorRed, ColorReset)
	}
}

func (s *Shell) showUsers() {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "USERNAME\tSTATUS\tDESCRIPTION\tPASSWORD LAST SET\tLAST LOGON\tMEMBER OF")
	fmt.Fprintln(w, "--------\t------\t-----------\t-----------------\t----------\t---------")

	for _, user := range s.data.Users {
		status := "Enabled"
		if !user.Enabled {
			status = "Disabled"
		}
		desc := truncate(user.Description, 40)
		memberOf := truncate(strings.Join(user.MemberOf, ", "), 50)
		pwdSet := formatTime(user.PasswordLastSet)
		lastLogon := formatTime(user.LastLogon)

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			user.Username, status, desc, pwdSet, lastLogon, memberOf)
	}
	w.Flush()
	fmt.Printf("\n%s[+]%s Total: %d users\n", ColorGreen, ColorReset, len(s.data.Users))
}

func (s *Shell) showGroups() {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tDESCRIPTION\tMEMBERS")
	fmt.Fprintln(w, "----\t-----------\t-------")

	for _, group := range s.data.Groups {
		desc := truncate(group.Description, 40)
		members := truncate(strings.Join(group.Members, ", "), 60)
		fmt.Fprintf(w, "%s\t%s\t%s\n", group.Name, desc, members)
	}
	w.Flush()
	fmt.Printf("\n%s[+]%s Total: %d groups\n", ColorGreen, ColorReset, len(s.data.Groups))
}

func (s *Shell) showComputers() {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tOPERATING SYSTEM\tVERSION\tDESCRIPTION")
	fmt.Fprintln(w, "----\t----------------\t-------\t-----------")

	for _, computer := range s.data.Computers {
		desc := truncate(computer.Description, 40)
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
			computer.Name, computer.OperatingSystem, computer.OSVersion, desc)
	}
	w.Flush()
	fmt.Printf("\n%s[+]%s Total: %d computers\n", ColorGreen, ColorReset, len(s.data.Computers))
}

func (s *Shell) showSPNs() {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "SPN\tUSERNAME\tPASSWORD LAST SET\tMEMBER OF")
	fmt.Fprintln(w, "---\t--------\t-----------------\t---------")

	for _, spn := range s.data.SPNs {
		memberOf := truncate(strings.Join(spn.MemberOf, ", "), 50)
		pwdSet := formatTime(spn.PasswordLastSet)
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
			spn.ServicePrincipalName, spn.Username, pwdSet, memberOf)
	}
	w.Flush()
	fmt.Printf("\n%s[+]%s Total: %d SPNs (Kerberoastable accounts)\n", ColorGreen, ColorReset, len(s.data.SPNs))
}

func (s *Shell) showPasswordPolicy() {
	fmt.Println("Password Policy")
	fmt.Println("---------------")
	fmt.Printf("Minimum Password Length: %d\n", s.data.PasswordPolicy.MinPasswordLength)
	fmt.Printf("Lockout Threshold: %d\n", s.data.PasswordPolicy.LockoutThreshold)
	fmt.Printf("Lockout Duration: %d minutes\n", s.data.PasswordPolicy.LockoutDuration)
	fmt.Printf("Passwords Remembered: %d\n", s.data.PasswordPolicy.PasswordsRemembered)
	fmt.Printf("Password Properties: %s\n", strings.Join(s.data.PasswordPolicy.PasswordProperties, ", "))
}

func (s *Shell) showFGPolicy() {
	if len(s.data.FGPolicies) == 0 {
		fmt.Printf("%s[*]%s No Fine-Grained Password Policies found\n", ColorBlue, ColorReset)
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tMIN LENGTH\tLOCKOUT\tHISTORY\tCOMPLEXITY\tAPPLIES TO")
	fmt.Fprintln(w, "----\t----------\t-------\t-------\t----------\t----------")

	for _, fg := range s.data.FGPolicies {
		complexity := "No"
		if fg.PasswordComplexity {
			complexity = "Yes"
		}
		appliesTo := truncate(strings.Join(fg.AppliesTo, ", "), 40)
		fmt.Fprintf(w, "%s\t%d\t%d\t%d\t%s\t%s\n",
			fg.Name, fg.MinPasswordLength, fg.LockoutThreshold,
			fg.PasswordsRemembered, complexity, appliesTo)
	}
	w.Flush()
}

func (s *Shell) cmdNet(args string) {
	parts := strings.SplitN(args, " ", 2)
	if len(parts) < 2 {
		fmt.Printf("%s[-]%s Usage: net <user|group|computer> <name>\n", ColorRed, ColorReset)
		return
	}

	objType := strings.ToLower(parts[0])
	name := parts[1]

	switch objType {
	case "user":
		s.netUser(name)
	case "group":
		s.netGroup(name)
	case "computer":
		s.netComputer(name)
	default:
		fmt.Printf("%s[-]%s Invalid type. Use: user, group, or computer\n", ColorRed, ColorReset)
	}
}

func (s *Shell) netUser(name string) {
	for _, user := range s.data.Users {
		if strings.EqualFold(user.Username, name) {
			fmt.Printf("Username: %s\n", user.Username)
			fmt.Printf("SID: %s\n", user.SID)
			fmt.Printf("Description: %s\n", user.Description)
			fmt.Printf("Home Directory: %s\n", user.HomeDirectory)
			fmt.Printf("Profile Path: %s\n", user.ProfilePath)
			fmt.Printf("Password Last Set: %s\n", formatTime(user.PasswordLastSet))
			fmt.Printf("Last Logon: %s\n", formatTime(user.LastLogon))
			fmt.Printf("Account Settings: %s\n", strings.Join(user.AccountSettings, ", "))
			fmt.Println("-" + strings.Repeat("-", 79))
			fmt.Printf("Primary Group: %s\n", user.PrimaryGroup)
			fmt.Println("Group Membership:")
			for _, group := range user.MemberOf {
				fmt.Printf("  - %s\n", group)
			}
			return
		}
	}
	fmt.Printf("%s[*]%s User '%s' not found\n", ColorBlue, ColorReset, name)
}

func (s *Shell) netGroup(name string) {
	for _, group := range s.data.Groups {
		if strings.EqualFold(group.Name, name) {
			fmt.Printf("Group Name: %s\n", group.Name)
			fmt.Printf("SID: %s\n", group.SID)
			fmt.Printf("Description: %s\n", group.Description)
			fmt.Println("Member Of:")
			for _, g := range group.MemberOf {
				fmt.Printf("  - %s\n", g)
			}
			fmt.Println("-" + strings.Repeat("-", 79))
			fmt.Println("Members:")
			for _, member := range group.Members {
				fmt.Printf("  - %s\n", member)
			}
			return
		}
	}
	fmt.Printf("%s[*]%s Group '%s' not found\n", ColorBlue, ColorReset, name)
}

func (s *Shell) netComputer(name string) {
	for _, computer := range s.data.Computers {
		if strings.EqualFold(computer.Name, name) || strings.EqualFold(computer.Name+"$", name) {
			fmt.Printf("Computer Name: %s\n", computer.Name)
			fmt.Printf("DNS Hostname: %s\n", computer.DNSHostName)
			fmt.Printf("SID: %s\n", computer.SID)
			fmt.Printf("Description: %s\n", computer.Description)
			fmt.Printf("Operating System: %s\n", computer.OperatingSystem)
			fmt.Printf("OS Version: %s\n", computer.OSVersion)
			fmt.Printf("Last Logon: %s\n", formatTime(computer.LastLogonTimestamp))
			fmt.Println("-" + strings.Repeat("-", 79))
			fmt.Println("Group Membership:")
			for _, group := range computer.MemberOf {
				fmt.Printf("  - %s\n", group)
			}
			return
		}
	}
	fmt.Printf("%s[*]%s Computer '%s' not found\n", ColorBlue, ColorReset, name)
}

func (s *Shell) cmdSearch(term string) {
	if term == "" {
		fmt.Printf("%s[-]%s Usage: search <term>\n", ColorRed, ColorReset)
		return
	}

	term = strings.ToLower(term)
	found := false

	// Search users
	var matchedUsers []models.User
	for _, user := range s.data.Users {
		if containsIgnoreCase(user.Username, term) ||
			containsIgnoreCase(user.Description, term) ||
			containsIgnoreCase(user.SID, term) ||
			containsIgnoreCase(strings.Join(user.MemberOf, " "), term) {
			matchedUsers = append(matchedUsers, user)
		}
	}
	if len(matchedUsers) > 0 {
		found = true
		fmt.Println("\nUsers")
		fmt.Println("-----")
		for _, u := range matchedUsers {
			fmt.Printf("  %s - %s\n", u.Username, truncate(u.Description, 60))
		}
	}

	// Search groups
	var matchedGroups []models.Group
	for _, group := range s.data.Groups {
		if containsIgnoreCase(group.Name, term) ||
			containsIgnoreCase(group.Description, term) ||
			containsIgnoreCase(strings.Join(group.Members, " "), term) {
			matchedGroups = append(matchedGroups, group)
		}
	}
	if len(matchedGroups) > 0 {
		found = true
		fmt.Println("\nGroups")
		fmt.Println("------")
		for _, g := range matchedGroups {
			fmt.Printf("  %s - %s\n", g.Name, truncate(g.Description, 60))
		}
	}

	// Search computers
	var matchedComputers []models.Computer
	for _, computer := range s.data.Computers {
		if containsIgnoreCase(computer.Name, term) ||
			containsIgnoreCase(computer.Description, term) ||
			containsIgnoreCase(computer.OperatingSystem, term) {
			matchedComputers = append(matchedComputers, computer)
		}
	}
	if len(matchedComputers) > 0 {
		found = true
		fmt.Println("\nComputers")
		fmt.Println("---------")
		for _, c := range matchedComputers {
			fmt.Printf("  %s - %s (%s)\n", c.Name, c.OperatingSystem, truncate(c.Description, 40))
		}
	}

	// Search SPNs
	var matchedSPNs []models.SPN
	for _, spn := range s.data.SPNs {
		if containsIgnoreCase(spn.ServicePrincipalName, term) ||
			containsIgnoreCase(spn.Username, term) {
			matchedSPNs = append(matchedSPNs, spn)
		}
	}
	if len(matchedSPNs) > 0 {
		found = true
		fmt.Println("\nSPNs")
		fmt.Println("----")
		for _, spn := range matchedSPNs {
			fmt.Printf("  %s (%s)\n", spn.ServicePrincipalName, spn.Username)
		}
	}

	if !found {
		fmt.Printf("%s[*]%s No results found for '%s'\n", ColorBlue, ColorReset, term)
	}
	fmt.Println()
}

func (s *Shell) cmdList(args string) {
	switch strings.ToLower(args) {
	case "users":
		names := make([]string, len(s.data.Users))
		for i, u := range s.data.Users {
			names[i] = u.Username
		}
		sort.Strings(names)
		for _, name := range names {
			fmt.Println(name)
		}
		fmt.Printf("\n%s[+]%s Total: %d users\n", ColorGreen, ColorReset, len(names))

	case "groups":
		names := make([]string, len(s.data.Groups))
		for i, g := range s.data.Groups {
			names[i] = g.Name
		}
		sort.Strings(names)
		for _, name := range names {
			fmt.Println(name)
		}
		fmt.Printf("\n%s[+]%s Total: %d groups\n", ColorGreen, ColorReset, len(names))

	case "computers":
		names := make([]string, len(s.data.Computers))
		for i, c := range s.data.Computers {
			names[i] = c.Name
		}
		sort.Strings(names)
		for _, name := range names {
			fmt.Println(name)
		}
		fmt.Printf("\n%s[+]%s Total: %d computers\n", ColorGreen, ColorReset, len(names))

	case "spns":
		for _, spn := range s.data.SPNs {
			fmt.Println(spn.Username)
		}
		fmt.Printf("\n%s[+]%s Total: %d SPNs\n", ColorGreen, ColorReset, len(s.data.SPNs))

	default:
		fmt.Printf("%s[-]%s Usage: list <users|groups|computers|spns>\n", ColorRed, ColorReset)
	}
}

func (s *Shell) cmdColumns(args string) {
	switch strings.ToLower(args) {
	case "users":
		fmt.Println("User Table Columns:")
		fmt.Println("  Username, SID, Description, HomeDirectory, ProfilePath,")
		fmt.Println("  PasswordLastSet, LastLogon, AccountSettings, PrimaryGroup, MemberOf")
	case "groups":
		fmt.Println("Group Table Columns:")
		fmt.Println("  Name, SID, Description, MemberOf, Members")
	case "computers":
		fmt.Println("Computer Table Columns:")
		fmt.Println("  Name, SID, Description, OperatingSystem, OSVersion, MemberOf, DNSHostName")
	case "spns":
		fmt.Println("SPN Table Columns:")
		fmt.Println("  ServicePrincipalName, Username, Description, PasswordLastSet, MemberOf")
	default:
		fmt.Printf("%s[-]%s Usage: columns <users|groups|computers|spns>\n", ColorRed, ColorReset)
	}
}

func (s *Shell) cmdClear() {
	fmt.Print("\033[H\033[2J")
}

// Helper functions

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func formatTime(t time.Time) string {
	if t.IsZero() || t.Year() < 1970 {
		return "Never"
	}
	return t.Format("2006-01-02 15:04")
}

func containsIgnoreCase(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}
