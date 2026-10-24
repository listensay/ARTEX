package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

func TestBrowserSessionLifecycle(t *testing.T) {
	s := securityServer(t)
	previous, existed, err := s.m.pg.GetSetting(authPassKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = s.m.pg.Exec(`DELETE FROM auth_sessions`)
		if existed {
			_ = s.m.pg.SetSetting(authPassKey, previous)
		} else {
			_, _ = s.m.pg.Exec(`DELETE FROM settings WHERE key=$1`, authPassKey)
		}
	})
	hash, _ := bcrypt.GenerateFromPassword([]byte("correct-test-password"), bcrypt.MinCost)
	if err := s.m.pg.SetSetting(authPassKey, string(hash)); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/auth/status", s.authStatus)
	mux.HandleFunc("POST /api/auth/login", s.authLogin)
	mux.HandleFunc("POST /api/auth/logout", s.authLogout)
	mux.HandleFunc("POST /api/auth/change-password", s.authChangePassword)
	mux.HandleFunc("GET /api/private", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]bool{"ok": true}) })
	mux.HandleFunc("POST /api/private", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]bool{"ok": true}) })
	s.SetGate(newTestGate())
	server := httptest.NewTLSServer(s.gate.wrap(cors(s.requireAuth(mux))))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	newClient := func() *http.Client {
		jar, _ := cookiejar.New(nil)
		jar.SetCookies(u, []*http.Cookie{{Name: gateCookieName, Value: s.gate.signCookie(), Path: "/"}})
		return &http.Client{Jar: jar, Transport: server.Client().Transport}
	}
	cookie := func(client *http.Client, name string) string {
		for _, c := range client.Jar.Cookies(u) {
			if c.Name == name {
				return c.Value
			}
		}
		return ""
	}
	request := func(client *http.Client, method, path, body, csrf, origin string, want int) (*http.Response, []byte) {
		t.Helper()
		r, _ := http.NewRequest(method, server.URL+path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		if csrf != "" {
			r.Header.Set(csrfHeaderName, csrf)
		}
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if response.StatusCode != want {
			t.Fatalf("%s %s: status=%d want=%d body=%s", method, path, response.StatusCode, want, data)
		}
		return response, data
	}
	login := func(client *http.Client) string {
		t.Helper()
		request(client, "GET", "/api/auth/status", "", "", "", 200)
		response, data := request(client, "POST", "/api/auth/login", `{"username":"ARTEX","password":"correct-test-password"}`, cookie(client, csrfCookieName), server.URL, 200)
		var result map[string]any
		if err := json.Unmarshal(data, &result); err != nil || result["authenticated"] != true || result["token"] != nil {
			t.Fatal("login must not return a browser credential")
		}
		token := cookie(client, sessionCookieName)
		if len(token) != 43 {
			t.Fatal("missing random session")
		}
		for _, c := range response.Cookies() {
			if c.Name == sessionCookieName && (!c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode) {
				t.Fatal("unsafe session cookie")
			}
		}
		var count int
		if err := s.m.pg.QueryRow(`SELECT count(*) FROM auth_sessions WHERE token_hash=$1 AND token_hash<>$2`, tokenDigest(token), token).Scan(&count); err != nil || count != 1 {
			t.Fatal("session must be stored hashed")
		}
		return token
	}
	client := newClient()
	request(client, "POST", "/api/auth/login", `{"username":"ARTEX","password":"correct-test-password"}`, "", "", 403)
	first := login(client)
	request(client, "GET", "/api/private", "", "", "", 200)
	request(client, "POST", "/api/private", "{}", "", "", 403)
	request(client, "POST", "/api/private", "{}", "forged", "", 403)
	request(client, "POST", "/api/private", "{}", cookie(client, csrfCookieName), "https://untrusted.invalid", 403)
	request(client, "POST", "/api/private", "{}", cookie(client, csrfCookieName), server.URL, 200)
	second := login(client)
	if second == first {
		t.Fatal("login must rotate the session")
	}
	oldClient := newClient()
	oldClient.Jar.SetCookies(u, []*http.Cookie{{Name: sessionCookieName, Value: first, Path: "/"}})
	request(oldClient, "GET", "/api/private", "", "", "", 401)
	request(client, "POST", "/api/auth/logout", "", cookie(client, csrfCookieName), server.URL, 200)
	oldClient.Jar.SetCookies(u, []*http.Cookie{{Name: sessionCookieName, Value: second, Path: "/"}})
	request(oldClient, "GET", "/api/private", "", "", "", 401)
	login(client)
	other := newClient()
	login(other)
	request(client, "POST", "/api/auth/change-password", `{"old_password":"correct-test-password","new_password":"new-correct-password"}`, cookie(client, csrfCookieName), server.URL, 200)
	request(other, "GET", "/api/private", "", "", "", 401)
	request(client, "GET", "/api/private", "", "", "", 401)

	// Legacy bearer, JS-written cookie and URL tokens cannot survive migration.
	legacy, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{Subject: "ARTEX", ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))}).SignedString(s.jwtKey)
	legacyClient := newClient()
	legacyClient.Jar.SetCookies(u, []*http.Cookie{{Name: "artex_token", Value: legacy, Path: "/"}})
	request(legacyClient, "GET", "/api/private?token="+url.QueryEscape(legacy), "", "", "", 401)
	if verifyJWT(legacy, s.jwtKey) {
		t.Fatal("legacy bearer accepted")
	}
}

func TestBrowserSessionExpiredAndDatabaseFailure(t *testing.T) {
	s := securityServer(t)
	password, _ := bcrypt.GenerateFromPassword([]byte("test-password"), bcrypt.MinCost)
	if err := s.m.pg.SetSetting(authPassKey, string(password)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = s.m.pg.Exec(`DELETE FROM auth_sessions`)
		_, _ = s.m.pg.Exec(`DELETE FROM settings WHERE key=$1`, authPassKey)
	})
	token, _ := randomGateToken(32)
	if err := s.m.pg.CreateAuthSession(tokenDigest(token), tokenDigest(string(password)), time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/api/private", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	if ok, err := s.authenticated(r); err != nil || ok {
		t.Fatal("expired session accepted")
	}
	_, _ = s.m.pg.Exec(`DELETE FROM auth_sessions`)
	_, _ = s.m.pg.Exec(`DELETE FROM settings WHERE key=$1`, authPassKey)
	if err := s.m.pg.Close(); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.authenticated(r); err == nil || ok {
		t.Fatal("database failure must fail closed")
	}
}

func TestBrowserProxyTrustAndCSRF(t *testing.T) {
	r := httptest.NewRequest("POST", "http://localhost/api/private", nil)
	r.RemoteAddr = "127.0.0.1:23456"
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", "management.invalid")
	if isHTTPS(r) {
		t.Fatal("untrusted forwarded header accepted")
	}
	t.Setenv("ARTEX_TRUSTED_PROXIES", "127.0.0.1/32")
	if !isHTTPS(r) {
		t.Fatal("trusted TLS terminator ignored")
	}
	r.Header.Set("Origin", "https://management.invalid")
	if !originAllowed(r) {
		t.Fatal("trusted external origin rejected")
	}
	r.RemoteAddr = "192.0.2.10:23456"
	if originAllowed(r) {
		t.Fatal("spoofed forwarded host accepted")
	}
	r.Header.Set("Origin", "null")
	if originAllowed(r) {
		t.Fatal("opaque origin accepted")
	}
}
