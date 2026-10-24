// 反测绘伪装门控(F14):未通过门控的请求拿不到任何 ARTEX 特征——静态 SPA、
// /api/*、SSE、favicon、错误页一律返回逐字节固定的假 nginx 默认欢迎页。
// 门控包在 Handler() 最外层(requireAuth 之前),独立随机口令与管理员会话
// 分开验证。隐藏 HTTP 指纹不能替代网络隔离或修复外部网关。
package server

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	pathpkg "path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	gatePathFilename  = "gate.path" // dataDir 下,0600,记录当前入口路径
	gateKeyFilename   = "gate.key"  // keyDir 下(与 jwt.key 同处,工作区外),0600
	gateTokenFilename = "gate.token"
	gateCookieName    = "artex_gate"
	defaultGateTTL    = 7 * 24 * time.Hour
	gateRateLimit     = 10 // 每 IP 每分钟口令尝试上限
	gateRateWindow    = time.Minute
)

// decoyPage 是逐字节固定的伪装响应体,与真实 nginx 默认欢迎页一致。伪装响应
// 必须固定——不固定的伪装本身就成了新指纹。所有未过门控的请求(含错误口令、
// 错误路径、/api/*)都返回这一份,逐字节一致,防枚举。
var decoyPage = []byte(`<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
html { color-scheme: light dark; }
body { width: 35em; margin: 0 auto;
font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>
`)

// gateLoginPage 是门禁页:极简纯 HTML、无外链资源、title 不含 artex。
// action="" 提交回当前 URL,页面字节与入口路径解耦。
var gateLoginPage = []byte(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Access</title>
<style>
body { margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center; background: #f5f5f5; font-family: Tahoma, Verdana, Arial, sans-serif; }
form { background: #fff; padding: 2em; border: 1px solid #ddd; border-radius: 4px; }
input { padding: .5em; width: 16em; border: 1px solid #ccc; border-radius: 3px; }
button { padding: .5em 1em; margin-left: .5em; border: 1px solid #ccc; border-radius: 3px; background: #fff; cursor: pointer; }
</style>
</head>
<body>
<form method="post" action="">
<input type="password" name="password" autocomplete="off" autofocus>
<button type="submit">Enter</button>
</form>
</body>
</html>
`)

// Gate 是伪装门控。path 为随机入口,token 为独立握手口令,
// key 为 cookie 的 HMAC-SHA256 签名密钥。
type Gate struct {
	resourceAuthorized func(*http.Request) bool
	path               string
	token              string
	key                []byte
	ttl                time.Duration
	limiter            *ipRateLimiter
}

// NewGate 按环境变量与监听地址解析门控配置;返回 (nil, nil) 表示门控关闭。
//
//	ARTEX_GATE        off/0/false 显式关闭,on/1/true 开启;未设置时默认开启。
//	ARTEX_GATE_PATH   显式指定入口路径;未设置时生成 /g-<16 字节随机 token>。
//	ARTEX_GATE_TOKEN  独立握手口令;未设置时随机生成并持久化到 keyDir/gate.token。
//	ARTEX_GATE_TTL_HOURS  cookie 有效期(小时),默认 168(7 天)。
//
// 启用时入口路径写入 dataDir/gate.path(0600)并在启动日志打印一次。
func NewGate(addr, dataDir, keyDir string) (*Gate, error) {
	enabled, explicit := gateEnabled(addr)
	if !enabled {
		if explicit {
			log.Printf("[gate] ARTEX_GATE=off — 伪装门控已关闭")
		}
		return nil, nil
	}
	if !explicit {
		log.Printf("[gate] 伪装门控默认开启(包括回环监听；ARTEX_GATE=off 可显式关闭)")
	}

	path := strings.TrimSpace(os.Getenv("ARTEX_GATE_PATH"))
	if path == "" {
		// 入口路径持久化:优先复用 gate.path 里已存的(重启不换地址,书签不失效);
		// 仅首次或文件缺失时生成新随机路径(UX 欠账修复——原来每次重启都重随机)。
		if prev, err := os.ReadFile(filepath.Join(dataDir, gatePathFilename)); err == nil {
			if p := strings.TrimSpace(string(prev)); strings.HasPrefix(p, "/g-") {
				path = p
			}
		}
	}
	if path == "" {
		tok, err := randomGateToken(16) // 16 字节 → 22 个 URL-safe 字符
		if err != nil {
			return nil, fmt.Errorf("generate gate path: %w", err)
		}
		path = "/g-" + tok
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if path == "/" || pathpkg.Clean(path) != path || strings.ContainsAny(path, "?#%\\\r\n\t ") || strings.HasPrefix(path, "/api/") || strings.HasPrefix(path, "/_next/") {
		return nil, fmt.Errorf("invalid gate path: use a dedicated absolute path without query, fragment, or escapes")
	}

	token := strings.TrimSpace(os.Getenv("ARTEX_GATE_TOKEN"))
	if token == "" {
		var err error
		token, err = loadOrCreateGateToken(keyDir)
		if err != nil {
			return nil, err
		}
	} else if len(token) < 24 || len(token) > 256 {
		return nil, fmt.Errorf("ARTEX_GATE_TOKEN must contain 24–256 bytes")
	}

	ttl := defaultGateTTL
	if v := strings.TrimSpace(os.Getenv("ARTEX_GATE_TTL_HOURS")); v != "" {
		h, err := strconv.Atoi(v)
		if err != nil || h <= 0 || h > 8760 {
			return nil, fmt.Errorf("ARTEX_GATE_TTL_HOURS must be between 1 and 8760")
		}
		ttl = time.Duration(h) * time.Hour
	}

	key, err := loadOrCreateGateKey(keyDir)
	if err != nil {
		return nil, err
	}
	g := newGate(path, token, key, ttl)

	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, fmt.Errorf("data dir: %w", err)
	}
	pf := filepath.Join(dataDir, gatePathFilename)
	if err := os.WriteFile(pf, []byte(path+"\n"), 0o600); err != nil {
		return nil, fmt.Errorf("write gate path file: %w", err)
	}
	if err := os.Chmod(pf, 0o600); err != nil {
		return nil, fmt.Errorf("protect gate path: %w", err)
	}
	log.Printf("[gate] 伪装门控已启用,入口路径: %s (已写入 %s,cookie 有效期 %s)", path, pf, ttl)
	return g, nil
}

// newGate 直接构造一个 Gate(配置解析见 NewGate);测试也用它。
func newGate(path, token string, key []byte, ttl time.Duration) *Gate {
	return &Gate{
		path:    path,
		token:   token,
		key:     key,
		ttl:     ttl,
		limiter: &ipRateLimiter{hits: map[string][]time.Time{}, limit: gateRateLimit, window: gateRateWindow},
	}
}

// gateEnabled 解析 ARTEX_GATE;未设置时开启,不依赖回环安全假设。explicit 表示开关
// 来自显式配置而非自动判定。
func gateEnabled(addr string) (enabled, explicit bool) {
	return GateEnabled(addr)
}

// GateEnabled exposes the side-effect-free gate policy for deployment checks.
func GateEnabled(addr string) (enabled, explicit bool) {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("ARTEX_GATE"))) {
	case "off", "0", "false":
		return false, true
	case "on", "1", "true":
		return true, true
	}
	return true, false
}

func loadOrCreateGateToken(keyDir string) (string, error) {
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(keyDir, gateTokenFilename)
	if data, err := os.ReadFile(path); err == nil {
		token := strings.TrimSpace(string(data))
		if len(token) < 24 || len(token) > 256 {
			return "", fmt.Errorf("invalid stored gate token")
		}
		if err := os.Chmod(path, 0o600); err != nil {
			return "", err
		}
		return token, nil
	} else if !os.IsNotExist(err) {
		return "", err
	}
	token, err := randomGateToken(32)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		return "", err
	}
	return token, nil
}

// isLoopbackAddr 判定监听地址是否只绑回环。空 host(:8787)= 全网卡,不算回环。
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// randomGateToken 生成 n 字节 crypto/rand 随机数的 URL-safe base64(无填充)。
func randomGateToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// loadOrCreateGateKey 读取 keyDir/gate.key(与 jwt.key 同处,不放进可浏览的
// dataDir 工作区);首次运行生成 32 字符随机密钥并以 0600 持久化。
func loadOrCreateGateKey(keyDir string) ([]byte, error) {
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(keyDir, gateKeyFilename)
	if data, err := os.ReadFile(path); err == nil {
		if len(strings.TrimSpace(string(data))) < 32 {
			return nil, fmt.Errorf("invalid gate key: %s", path)
		}
		if err := os.Chmod(path, 0o600); err != nil {
			return nil, err
		}
		return []byte(strings.TrimSpace(string(data))), nil
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read gate key: %w", err)
	}
	buf := make([]byte, 32)
	for i := range buf {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(keyChars))))
		if err != nil {
			return nil, fmt.Errorf("generate gate key: %w", err)
		}
		buf[i] = keyChars[n.Int64()]
	}
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		return nil, fmt.Errorf("write gate key: %w", err)
	}
	log.Printf("[gate] 新 gate key 已写入 %s", path)
	return buf, nil
}

// wrap 把门控包到 next 最外层。nil Gate(门控关闭)时直通。
func (g *Gate) wrap(next http.Handler) http.Handler {
	if g == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if g.resourceAuthorized != nil && g.resourceAuthorized(r) {
			next.ServeHTTP(w, r)
			return
		}
		if r.URL.Path == g.path {
			switch r.Method {
			case http.MethodGet:
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.Header().Set("Cache-Control", "no-store")
				w.Header().Set("Referrer-Policy", "no-referrer")
				_, _ = w.Write(gateLoginPage)
			case http.MethodPost:
				g.handleLogin(w, r)
			default:
				writeDecoy(w)
			}
			return
		}
		if c, err := r.Cookie(gateCookieName); err == nil && g.validCookie(c.Value) {
			// Authenticated HTML/assets must never populate a shared proxy cache.
			w.Header().Set("Cache-Control", "private, no-store")
			w.Header().Add("Vary", "Cookie")
			next.ServeHTTP(w, r)
			return
		}
		writeDecoy(w)
	})
}

// handleLogin 校验口令并下发签名 cookie。口令错误、限流命中与错误路径的响应
// 逐字节一致(都是伪装页),不给出任何枚举信号。
func (g *Gate) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || ip == "" {
		ip = r.RemoteAddr
	}
	if !g.limiter.allow(ip) {
		writeDecoy(w)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil ||
		subtle.ConstantTimeCompare([]byte(r.PostForm.Get("password")), []byte(g.token)) != 1 {
		writeDecoy(w)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     gateCookieName,
		Value:    g.signCookie(),
		Path:     "/",
		MaxAge:   int(g.ttl.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   isHTTPS(r),
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// isHTTPS 判定当前请求是否经 TLS 到达(含前置反代终止 TLS 的场景),
// Secure 属性仅在 https 时设置。
func isHTTPS(r *http.Request) bool {
	return r.TLS != nil || (trustedProxy(r) && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https"))
}

// signCookie 签发 "expiry.hmac" 形式的签名 cookie 值。
func (g *Gate) signCookie() string {
	exp := time.Now().Add(g.ttl).Unix()
	mac := hmac.New(sha256.New, g.key)
	fmt.Fprintf(mac, "gate|%s|%d", g.path, exp)
	return fmt.Sprintf("%d.%s", exp, hex.EncodeToString(mac.Sum(nil)))
}

// validCookie 校验签名与有效期(常量时间比较)。
func (g *Gate) validCookie(v string) bool {
	parts := strings.Split(v, ".")
	if len(parts) != 2 {
		return false
	}
	exp, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || time.Now().Unix() >= exp {
		return false
	}
	mac := hmac.New(sha256.New, g.key)
	fmt.Fprintf(mac, "gate|%s|%d", g.path, exp)
	want, err := hex.DecodeString(parts[1])
	if err != nil {
		return false
	}
	return hmac.Equal(want, mac.Sum(nil))
}

// writeDecoy 写伪装响应:固定 nginx 欢迎页 + nginx 典型头(Go 默认不吐
// Server 头,这里主动补上)。所有未过门控的响应都必须走这里,保证逐字节一致。
func writeDecoy(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Server", "nginx")
	h.Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(decoyPage)
}

// ipRateLimiter 是内存版每 IP 固定窗口计数器(口令尝试限速用)。
type ipRateLimiter struct {
	mu     sync.Mutex
	hits   map[string][]time.Time
	limit  int
	window time.Duration
}

// allow 记录一次尝试并报告是否仍在限额内。
func (l *ipRateLimiter) allow(ip string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	// 防内存膨胀:IP 数异常多时整体清一次(限速语义不受影响,只影响极端攻击面)。
	if len(l.hits) > 100000 {
		l.hits = map[string][]time.Time{}
	}
	cutoff := now.Add(-l.window)
	kept := l.hits[ip][:0]
	for _, t := range l.hits[ip] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= l.limit {
		l.hits[ip] = kept
		return false
	}
	l.hits[ip] = append(kept, now)
	return true
}
