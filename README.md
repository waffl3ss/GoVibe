# GoVibe

A Go rewrite of the Vibe Active Directory enumeration tool with pass-the-hash and Kerberos authentication support.

## Features

- **LDAP/LDAPS Enumeration**: Enumerate users, groups, computers, SPNs, password policies
- **Multiple Authentication Methods**:
  - Password authentication
  - Pass-the-Hash (NTLM)
  - Kerberos authentication via ccache (TGT)
- **SOCKS5 Proxy Support**: Route traffic through a SOCKS5 proxy (including Kerberos KDC traffic)
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

### With Kerberos (ccache)
```bash
# Using a ccache file from impacket's getTGT.py, Rubeus, or similar
./govibe -k --ccache /tmp/administrator.ccache -D corp.local -I 192.168.1.10 --dc-host dc01.corp.local

# Using KRB5CCNAME environment variable
export KRB5CCNAME=/tmp/administrator.ccache
./govibe -k -D corp.local -I 192.168.1.10 --dc-host dc01.corp.local

# Kerberos with no password prompt (useful in scripts)
./govibe -k --no-pass --ccache /tmp/admin.ccache -D corp.local -I 192.168.1.10 --dc-host dc01.corp.local
```

### With SOCKS5 Proxy
```bash
# Password auth through SOCKS5
./govibe -U administrator -P 'Password123' -D corp.local -I 192.168.1.10 -x 127.0.0.1:1080

# Kerberos through SOCKS5 (KDC traffic is also proxied)
./govibe -k --ccache /tmp/admin.ccache -D corp.local -I 192.168.1.10 --dc-host dc01.corp.local -x 127.0.0.1:1080
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
| `-U, --username` | Username for authentication |
| `-P, --password` | Password for authentication |
| `-H, --hash` | NT hash for pass-the-hash authentication |
| `-D, --domain` | Fully Qualified Domain Name (required) |
| `-I, --dc-ip` | IP address of Domain Controller (required) |
| `-p, --port` | LDAP port (default: 636 for LDAPS, 389 for LDAP) |
| `-u, --unencrypted` | Use unencrypted LDAP instead of LDAPS |
| `-o, --output` | Output directory for JSON/HTML files |
| `-x, --proxy` | SOCKS5 proxy address (e.g., 127.0.0.1:1080) |
| `-k, --kerberos` | Use Kerberos authentication |
| `--ccache` | Path to ccache file (or use KRB5CCNAME env var) |
| `--dc-host` | Hostname of DC for Kerberos SPN (e.g., dc01.corp.local) |
| `--no-pass` | Skip password prompt (for Kerberos or when not needed) |
| `-h, --help` | Show help message |

## Kerberos Authentication

GoVibe supports Kerberos authentication using a ccache file containing a valid TGT. This is useful for:

- **Pass-the-Ticket attacks**: Use tickets extracted from memory
- **Delegation attacks**: Use tickets obtained through delegation
- **Avoiding password exposure**: Authenticate without transmitting credentials

### Obtaining a ccache file

```bash
# Using impacket's getTGT.py
getTGT.py corp.local/administrator:'Password123' -dc-ip 192.168.1.10

# Using Rubeus (convert .kirbi to .ccache with ticketConverter.py)
ticketConverter.py administrator.kirbi administrator.ccache
```

### Important Notes

- The `--dc-host` flag should be the **hostname** (FQDN) of the DC, not the IP address. This is used to build the Kerberos SPN (`ldap/dc01.corp.local`).
- If `--dc-host` is not specified, the `-I` (dc-ip) value is used, which may fail if the SPN was registered with a hostname.
- LDAPS (port 636) is recommended for Kerberos authentication. Plain LDAP (port 389) requires SASL signing which is not currently supported.

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
- `github.com/jcmturner/gokrb5/v8` - Kerberos 5 library (for Kerberos auth)
- `golang.org/x/net/proxy` - SOCKS5 proxy support
- `golang.org/x/term` - Terminal password input

## References

Original Vibe tool by Tylous [Vibe](https://github.com/Tylous/Vibe)
