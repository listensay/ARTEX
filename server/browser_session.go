package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	sessionCookieName = "artex_session"
	csrfCookieName    = "artex_csrf"
	csrfHeaderName    = "X-Artex-CSRF"
	sessionTTL        = 8 * time.Hour
)

func tokenDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// Forwarded headers are authoritative only when the immediate peer is trusted.
func trustedProxy(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	for _, value := range strings.Split(os.Getenv("ARTEX_TRUSTED_PROXIES"), ",") {
		value = strings.TrimSpace(value)
		if prefix, err := netip.ParsePrefix(value); err == nil && prefix.Contains(addr.Unmap()) {
			return true
		}
		if peer, err := netip.ParseAddr(value); err == nil && peer.Unmap() == addr.Unmap() {
			return true
		}
	}
	return false
}

func originAllowed(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.User != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	host := r.Host
	if trustedProxy(r) {
		if forwarded := r.Header.Get("X-Forwarded-Host"); forwarded != "" && !strings.Contains(forwarded, ",") {
			host = forwarded
		}
	}
	scheme := "http"
	if isHTTPS(r) {
		scheme = "https"
	}
	if strings.EqualFold(origin, scheme+"://"+host) {
		return true
	}
	for _, allowed := range strings.Split(os.Getenv("ARTEX_ALLOWED_ORIGINS"), ",") {
		if strings.EqualFold(origin, strings.TrimSpace(allowed)) {
			return true
		}
	}
	return false
}

func (s *Server) validCSRFToken(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 2 || len(parts[0]) != 43 {
		return false
	}
	mac := hmac.New(sha256.New, s.jwtKey)
	mac.Write([]byte("csrf|" + parts[0]))
	return hmac.Equal([]byte(parts[1]), []byte(hex.EncodeToString(mac.Sum(nil))))
}

func (s *Server) ensureCSRF(w http.ResponseWriter, r *http.Request) error {
	if c, err := r.Cookie(csrfCookieName); err == nil && s.validCSRFToken(c.Value) {
		return nil
	}
	nonce, err := randomGateToken(32)
	if err != nil {
		return err
	}
	mac := hmac.New(sha256.New, s.jwtKey)
	mac.Write([]byte("csrf|" + nonce))
	http.SetCookie(w, &http.Cookie{Name: csrfCookieName, Value: nonce + "." + hex.EncodeToString(mac.Sum(nil)), Path: "/", MaxAge: int(sessionTTL.Seconds()), SameSite: http.SameSiteStrictMode, Secure: isHTTPS(r)})
	return nil
}

func (s *Server) validCSRF(r *http.Request) bool {
	c, err := r.Cookie(csrfCookieName)
	value := r.Header.Get(csrfHeaderName)
	return err == nil && value != "" && subtle.ConstantTimeCompare([]byte(value), []byte(c.Value)) == 1 && s.validCSRFToken(value) && originAllowed(r)
}

func (s *Server) authenticated(r *http.Request) (bool, error) {
	if r.Header.Get("Authorization") != "" {
		return verifyJWT(extractToken(r), s.jwtKey), nil
	}
	c, err := r.Cookie(sessionCookieName)
	if err != nil || len(c.Value) != 43 {
		return false, nil
	}
	if s.m == nil || s.m.pg == nil {
		return false, fmt.Errorf("session database unavailable")
	}
	record, ok, err := s.m.pg.AuthSession(tokenDigest(c.Value))
	if err != nil || !ok {
		return false, err
	}
	password, _, err := s.m.pg.GetSetting(authPassKey)
	return password != "" && record.PasswordVersion == tokenDigest(password), err
}

func clearSessionCookies(w http.ResponseWriter, r *http.Request) {
	for _, name := range []string{sessionCookieName, "artex_token"} {
		http.SetCookie(w, &http.Cookie{Name: name, Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: isHTTPS(r)})
	}
}

func (s *Server) issueBrowserSession(w http.ResponseWriter, r *http.Request, passwordHash string) {
	token, err := randomGateToken(32)
	if err != nil {
		writeErr(w, 500, "会话生成失败")
		return
	}
	if _, err := s.m.pg.Exec(`DELETE FROM auth_sessions WHERE expires_at<=now()`); err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if err := s.m.pg.CreateAuthSession(tokenDigest(token), tokenDigest(passwordHash), time.Now().Add(sessionTTL)); err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	// A successful login replaces the previous browser session rather than fixing it.
	if previous, err := r.Cookie(sessionCookieName); err == nil {
		if err := s.m.pg.DeleteAuthSession(tokenDigest(previous.Value)); err != nil {
			_ = s.m.pg.DeleteAuthSession(tokenDigest(token))
			writeErr(w, 503, errDataSourceUnavailable)
			return
		}
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: token, Path: "/", MaxAge: int(sessionTTL.Seconds()), HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: isHTTPS(r)})
	http.SetCookie(w, &http.Cookie{Name: "artex_token", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: isHTTPS(r)})
	writeJSON(w, 200, map[string]any{"authenticated": true})
}

func (s *Server) authLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookieName); err == nil {
		if err := s.m.pg.DeleteAuthSession(tokenDigest(c.Value)); err != nil {
			writeErr(w, 503, errDataSourceUnavailable)
			return
		}
	}
	clearSessionCookies(w, r)
	writeJSON(w, 200, map[string]any{"ok": true})
}
