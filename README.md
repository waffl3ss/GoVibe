# GoVibe

A Go rewrite of the Vibe Active Directory enumeration tool with pass-the-hash support.

## Features

- **LDAP/LDAPS Enumeration**: Enumerate users, groups, computers, SPNs, password policies
- **Pass-the-Hash Authentication**: Authenticate using password or NTLM hashe
- **Multiple Output Formats**: JSON and HTML output (similar to ldapdomaindump)
- **Interactive Shell**: Query and search enumerated data
- **Cross-Platform**: Compiles for Linux, Windows, and macOS

## Installation

```bash
# Build from source
make build

# Or build for all platforms
make build-all

# Install to /usr/local/bin
sudo make install
```

## Usage

### With Password
```bash
./govibe -U administrator -P 'Password123' -D corp.local -I 192.168.1.10
```

### With NTLM Hash (Pass-the-Hash)
```bash
# Using full LM:NT hash format
./govibe -U administrator -H 'aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0' -D corp.local -I 192.168.1.10

# Using just the NT hash
./govibe -U administrator -H '31d6cfe0d16ae931b73c59d7e0c089c0' -D corp.local -I 192.168.1.10
```

### With Unencrypted LDAP
```bash
./govibe -U administrator -P 'Password123' -D corp.local -I 192.168.1.10 -u
```

### Specify Output Directory
```bash
./govibe -U administrator -P 'Password123' -D corp.local -I 192.168.1.10 -o /tmp/output
```

## Command Line Options

| Option | Description |
|--------|-------------|
| `-U, --username` | Username for authentication (required) |
| `-P, --password` | Password for authentication |
| `-H, --hash` | NT hash for pass-the-hash authentication |
| `-D, --domain` | Fully Qualified Domain Name (required) |
| `-I, --dc-ip` | IP address of Domain Controller (required) |
| `-p, --port` | LDAP port (default: 636 for LDAPS, 389 for LDAP) |
| `-u, --unencrypted` | Use unencrypted LDAP instead of LDAPS |
| `-o, --output` | Output directory for JSON/HTML files |
| `-h, --help` | Show help message |

## Interactive Shell Commands

| Command | Description |
|---------|-------------|
| `show <type>` | Show data (users, groups, computers, spns, pwdpolicy, fgpolicy) |
| `net <type> <name>` | View details for a specific user, group, or computer |
| `search <term>` | Search all tables for a keyword |
| `list <type>` | List names only (users, groups, computers, spns) |
| `columns <type>` | Display column names for a table |
| `clear` | Clear the screen |
| `help` | Display help menu |
| `exit` | Exit GoVibe |

## Output Files

The tool generates both JSON and HTML files in the output directory:

### JSON Files
- `domain_users.json` - All user objects
- `domain_groups.json` - All group objects
- `domain_computers.json` - All computer objects
- `domain_spns.json` - Kerberoastable accounts
- `domain_password_policy.json` - Domain password policy
- `domain_fgpp.json` - Fine-grained password policies
- `domain_trusts.json` - Domain trust relationships
- `domain_all.json` - Combined data

### HTML Files
- `domain_users.html` - User table with filtering
- `domain_groups.html` - Group table with filtering
- `domain_computers.html` - Computer table with filtering
- `domain_spns.html` - SPN table (Kerberoastable accounts)
- `domain_policy.html` - Password policies
- `domain_index.html` - Overview with statistics

## Dependencies

- `github.com/go-ldap/ldap/v3` - LDAP client library
- `github.com/Azure/go-ntlmssp` - NTLM authentication (for pass-the-hash)
- `golang.org/x/term` - Terminal password input

## References

Original Vibe tool by Tylous [Vibe](https://github.com/Tylous/Vibe)