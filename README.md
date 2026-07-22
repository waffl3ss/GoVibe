# GoVibe

A Go rewrite of the Vibe Active Directory enumeration tool with pass-the-hash and Kerberos authentication support.

## Features

- **LDAP/LDAPS Enumeration**: Enumerate users, groups, computers, SPNs, password policies, trusts
- **Multiple Authentication Methods**:
  - Password authentication
  - Pass-the-Hash (NTLM)
  - Kerberos authentication via ccache (TGT)
- **SOCKS5 Proxy Support**: Route traffic through a SOCKS5 proxy (including Kerberos KDC traffic)
- **Multiple Output Formats**: JSON and HTML output (similar to ldapdomaindump but prettier)
- **BloodHound CE (v5)**: Generate BloodHound Community Edition compatible zip with ACLs, delegation, SID history, and RBCD data
- **BloodHound Legacy (v4)**: Generate BloodHound Legacy (bloodhound-python) compatible zip
- **DCOnly Expansion**: Optional deeper collection of OUs, GPOs, and Containers (gated behind `--dconly`)
- **Offline Mode**: Re-process cached data without touching LDAP again
- **Configurable Timeout**: Adjust connection timeout (default 30s)
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

### Basic Enumeration

```bash
# With password
./govibe -U administrator -P 'Password123' -D corp.local -I 192.168.1.10

# With NTLM hash (pass-the-hash)
./govibe -U administrator -H 'aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0' -D corp.local -I 192.168.1.10

# With just the NT hash
./govibe -U administrator -H '31d6cfe0d16ae931b73c59d7e0c089c0' -D corp.local -I 192.168.1.10
```

### With Kerberos (ccache)

```bash
# Using a ccache file
./govibe -k --ccache /tmp/administrator.ccache -D corp.local -I 192.168.1.10 --dc-host dc01.corp.local

# Using KRB5CCNAME environment variable
export KRB5CCNAME=/tmp/administrator.ccache
./govibe -k -D corp.local -I 192.168.1.10 --dc-host dc01.corp.local
```

### BloodHound Output

GoVibe supports three collection tiers, each building on the previous:

**Tier 1 - Lean (no BH flags):** Standard enumeration only. No extra LDAP attributes are requested beyond what GoVibe needs for its own output. Fastest and quietest.

**Tier 2 - BloodHound (`-b` or `--bloodhound-legacy`):** Adds nTSecurityDescriptor (ACLs), delegation attributes, SID history, LAPS, and RBCD data to existing queries. No additional LDAP searches are made — these attributes ride on the same user/group/computer queries. Produces a zip importable into BloodHound.

**Tier 3 - DCOnly (`--dconly`):** Adds three new LDAP searches for OUs, GPOs, and Containers. These are separate queries that increase the LDAP footprint. Requires `-b` or `--bloodhound-legacy`.

```bash
# BloodHound CE (v5) output
./govibe -U admin -P 'Password123' -D corp.local -I 192.168.1.10 -b

# BloodHound CE with DCOnly expansion (OUs, GPOs, Containers)
./govibe -U admin -P 'Password123' -D corp.local -I 192.168.1.10 -b --dconly

# BloodHound Legacy (v4) output
./govibe -U admin -P 'Password123' -D corp.local -I 192.168.1.10 --bloodhound-legacy

# Both formats at once
./govibe -U admin -P 'Password123' -D corp.local -I 192.168.1.10 -b --bloodhound-legacy --dconly
```

### With SOCKS5 Proxy

```bash
./govibe -U administrator -P 'Password123' -D corp.local -I 192.168.1.10 -x 127.0.0.1:1080

# Kerberos through SOCKS5 (KDC traffic is also proxied)
./govibe -k --ccache /tmp/admin.ccache -D corp.local -I 192.168.1.10 --dc-host dc01.corp.local -x 127.0.0.1:1080
```

### Custom Timeout

```bash
# Set timeout to 60 seconds (default is 30)
./govibe -U admin -P 'Password123' -D corp.local -I 192.168.1.10 -t 60
```

### Offline Mode and Cache

Every successful run automatically saves a binary cache file (`<domain>.govibe`) in the output directory. This file contains **all** enumerated data — users, groups, computers, SPNs, password policies, trusts, domain info, and (if `--dconly` was used) OUs, GPOs, and Containers — including raw security descriptors, delegation attributes, SID history, and LAPS data.

Use `--offline` to load cached data and drop straight into the interactive shell without connecting to LDAP:

```bash
# Normal run — creates ./corp.local/corp.local.govibe automatically
./govibe -U admin -P 'Password123' -D corp.local -I 192.168.1.10

# Load from cache, open interactive shell (no LDAP connection, no files rewritten)
./govibe --offline -D corp.local

# Load from cache with custom output directory
./govibe --offline -D corp.local -o /path/to/output

# Remove cached data for a domain (deletes the .govibe cache file only — JSON, HTML, and BloodHound zip files are not touched)
./govibe --rm-db -D corp.local
```

The default cache location is `./<domain>/<domain>.govibe`. If you used `-o /custom/path` during enumeration, use the same `-o` with `--offline` or `--rm-db` so GoVibe finds the cache file.

### With Unencrypted LDAP

```bash
./govibe -U administrator -P 'Password123' -D corp.local -I 192.168.1.10 -u
```

## Command Line Options

| Option | Description |
|--------|-------------|
| `-U, --username` | Username for authentication |
| `-P, --password` | Password for authentication |
| `-H, --hash` | NT hash for pass-the-hash authentication |
| `-D, --domain` | Fully Qualified Domain Name (required) |
| `-I, --dc-ip` | IP address of Domain Controller |
| `-p, --port` | LDAP port (default: 636 for LDAPS, 389 for LDAP) |
| `-u, --unencrypted` | Use unencrypted LDAP instead of LDAPS |
| `-o, --output` | Output directory for JSON/HTML files |
| `-x, --proxy` | SOCKS5 proxy address (e.g., 127.0.0.1:1080) |
| `-k, --kerberos` | Use Kerberos authentication |
| `-b, --bloodhound` | Generate BloodHound CE (v5) compatible zip file |
| `--bloodhound-legacy` | Generate BloodHound Legacy (v4) compatible zip file |
| `--dconly` | Expand collection with OUs, GPOs, Containers (requires `-b` or `--bloodhound-legacy`) |
| `-t, --timeout` | Connection timeout in seconds (default: 30) |
| `--offline` | Load cached data and open interactive shell (no LDAP, no file writes) |
| `--rm-db` | Delete the `.govibe` cache file for the specified domain (output files are not removed) |
| `--ccache` | Path to ccache file (or use KRB5CCNAME env var) |
| `--dc-host` | Hostname of DC for Kerberos SPN (e.g., dc01.corp.local) |
| `--no-pass` | Skip password prompt |
| `-h, --help` | Show help message |

## BloodHound Data Collected

When `-b` or `--bloodhound-legacy` is used, the following additional data is collected on existing queries (no extra LDAP connections):

- **ACLs (nTSecurityDescriptor)**: GenericAll, GenericWrite, WriteOwner, WriteDacl, ForceChangePassword, AddMember, AllExtendedRights, ReadLAPSPassword, AddKeyCredentialLink, WriteSPN, Owns
- **Delegation**: Constrained delegation targets (msDS-AllowedToDelegateTo), unconstrained delegation (UAC flag)
- **RBCD**: Resource-Based Constrained Delegation (msDS-AllowedToActOnBehalfOfOtherIdentity)
- **SID History**: sIDHistory attribute for detecting SID history abuse paths
- **LAPS**: ms-Mcs-AdmPwd presence detection
- **Trust SIDs**: objectSid on trusted domain objects
- **Timestamps**: whenCreated, pwdLastSet on all objects

When `--dconly` is also used, three additional LDAP searches are made:

- **OUs**: Organizational Units with ACLs and GP links
- **GPOs**: Group Policy Objects with ACLs and file system paths
- **Containers**: Container objects with ACLs

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

### BloodHound Files
- `<timestamp>_GoVibe_BloodHound.zip` - BloodHound CE (v5) data (when `-b` is used)
- `<timestamp>_GoVibe_BloodHound_Legacy.zip` - BloodHound Legacy (v4) data (when `--bloodhound-legacy` is used)

### Cache Files
- `<domain>.govibe` - Cached enumeration data for offline mode

## References

Original Vibe tool by Tylous [Vibe](https://github.com/Tylous/Vibe)
