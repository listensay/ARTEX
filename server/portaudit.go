package server

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// 台账外监听端口审计(F13 轻量版,只观测不处置):worker 的 Bash 能起任意监听
// (python -m http.server 之类的孤儿服务是通病),平台每 5 分钟扫一次本机监听,
// 凡不在平台台账、且绑在非 loopback 的监听者打 WARN。不自动 kill——先只观测,
// 误杀平台不知道的正当服务比漏报更糟。

const portAuditInterval = 5 * time.Minute

// listenSock 是 /proc/net/tcp{,6} 里一条 LISTEN 状态的本地监听。
type listenSock struct {
	IP   net.IP
	Port int
}

// startPortAudit 参照 startLLMRecordsRetention 的模式:启动即扫一次,之后每 5 分钟。
// 仅 Linux(/proc/net/tcp{,6}),其它平台直接跳过。
// StartPortAudit is called after the HTTP listener has successfully bound, so
// port 0 and custom ports are registered using their actual addresses.
func (m *Manager) StartPortAudit(addr net.Addr) {
	if runtime.GOOS != "linux" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.auditCancel != nil {
		return
	}
	if addr != nil {
		if _, port, err := net.SplitHostPort(addr.String()); err == nil {
			if n, err := strconv.Atoi(port); err == nil {
				m.managedPorts.Store(n, true)
			}
		}
	}
	if m.traffic != nil {
		if u, err := url.Parse(m.traffic.ProxyAddr()); err == nil {
			if n, err := strconv.Atoi(u.Port()); err == nil && n > 0 {
				m.managedPorts.Store(n, true)
			}
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.auditCancel = cancel
	m.auditWG.Add(1)
	go func() { defer m.auditWG.Done(); m.portAuditLoop(ctx, portAuditInterval) }()
}

func (m *Manager) portAuditLoop(ctx context.Context, interval time.Duration) {
	audit := func() {
		known := map[int]bool{}
		m.managedPorts.Range(func(k, v any) bool { known[k.(int)] = true; return true })
		for _, w := range scanUnmanagedListeners(known) {
			log.Printf("[portaudit] WARN 台账外非回环 TCP 监听: %s (当前网络命名空间；请人工核查)", w)
		}
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		audit()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// scanUnmanagedListeners 读取 /proc/net/tcp{,6},返回所有「非台账端口 + 非 loopback」
// 的监听描述。文件读不到(容器裁剪等)静默跳过——审计降级不影响主流程。
func scanUnmanagedListeners(known map[int]bool) []string {
	var out []string
	seen := map[string]bool{}
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, ls := range parseProcNetTCP(string(data)) {
			if known[ls.Port] || ls.IP.IsLoopback() {
				continue
			}
			desc := net.JoinHostPort(ls.IP.String(), strconv.Itoa(ls.Port))
			if !seen[desc] {
				seen[desc] = true
				out = append(out, desc)
			}
		}
	}
	return out
}

// parseProcNetTCP 解析 /proc/net/tcp 或 /proc/net/tcp6 内容,返回 LISTEN(状态 0A)
// 的本地地址。纯函数,方便用 fixture 单测。
func parseProcNetTCP(content string) []listenSock {
	var out []listenSock
	for _, line := range strings.Split(content, "\n") {
		f := strings.Fields(line)
		// 列:sl local_address rem_address st ...(数据行首列形如 "  0:")
		if len(f) < 4 || !strings.HasSuffix(f[0], ":") || f[3] != "0A" {
			continue
		}
		ip, port, err := parseProcAddr(f[1])
		if err != nil {
			continue
		}
		out = append(out, listenSock{IP: ip, Port: port})
	}
	return out
}

// parseProcAddr 解析 "0100007F:1F91" 这样的 hex 地址。IPv4 是 8 hex(整体小端);
// IPv6 是 32 hex(4 个 32 位字,每个字内部小端)。
func parseProcAddr(s string) (net.IP, int, error) {
	host, portHex, ok := strings.Cut(s, ":")
	if !ok {
		return nil, 0, fmt.Errorf("bad addr %q", s)
	}
	if len(portHex) != 4 {
		return nil, 0, fmt.Errorf("bad port")
	}
	n, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return nil, 0, err
	}
	port := int(n)
	raw, err := hex.DecodeString(host)
	if err != nil {
		return nil, 0, err
	}
	switch len(raw) {
	case 4: // IPv4,小端
		return net.IPv4(raw[3], raw[2], raw[1], raw[0]), port, nil
	case 16: // IPv6,按 32 位字小端
		ip := make(net.IP, 16)
		for w := 0; w < 4; w++ {
			ip[w*4+0] = raw[w*4+3]
			ip[w*4+1] = raw[w*4+2]
			ip[w*4+2] = raw[w*4+1]
			ip[w*4+3] = raw[w*4+0]
		}
		return ip, port, nil
	}
	return nil, 0, fmt.Errorf("bad addr len %d", len(raw))
}

func (m *Manager) registerManagedPort(port int)   { m.managedPorts.Store(port, true) }
func (m *Manager) unregisterManagedPort(port int) { m.managedPorts.Delete(port) }
