package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
)

func ssCoverageMode(link db.ScopeSentryLink) string {
	if link.CoverageMode != "" {
		return link.CoverageMode
	}
	if link.TemplateCoverage != "" {
		return link.TemplateCoverage
	}
	return "http"
}

func ssMaxAge(link db.ScopeSentryLink) int64 {
	if link.MaxAgeSeconds > 0 {
		return link.MaxAgeSeconds
	}
	return 86400
}

func ssScanKey(link db.ScopeSentryLink) string {
	ports, urls := append([]int{}, link.RequiredPorts...), append([]string{}, link.RequiredURLs...)
	sort.Ints(ports)
	sort.Strings(urls)
	raw := ssJSON([]any{link.ScopeHash, strings.ToLower(link.TemplateID), ssCoverageMode(link), ssMaxAge(link), slices.Compact(ports), slices.Compact(urls)})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func ssSameScan(link db.ScopeSentryLink) bool {
	return link.ScanName != "" && link.ScanScopeHash == link.ScopeHash && (link.ScanRequestHash == "" || link.ScanRequestHash == ssScanKey(link))
}

func ssPreserveScanIdentity(link *db.ScopeSentryLink) {
	if link.ScanName != "" && link.ScanRequestHash == "" {
		link.ScanRequestHash = ssScanKey(*link)
	}
}

func ssObservationTime(raw map[string]json.RawMessage) int64 {
	for _, key := range []string{"last_seen", "lastSeen", "updated_at", "updatedAt", "time", "timestamp", "created_at"} {
		value := strings.Trim(string(raw[key]), "\"")
		if n, err := strconv.ParseInt(value, 10, 64); err == nil && n > 0 {
			if n > 1e12 {
				n /= 1000
			}
			return n
		}
		for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05"} {
			if stamp, err := time.Parse(layout, value); err == nil {
				return stamp.Unix()
			}
		}
	}
	return 0 // Unknown observation time is not evidence of freshness.
}

type ssCoverage struct {
	link    db.ScopeSentryLink
	ports   map[string]map[int]bool
	urls    map[string]bool
	http    map[string]bool
	domains map[string]bool
}

func (c *ssCoverage) observe(typ string, data json.RawMessage, targets []ssTarget) {
	if typ != "asset" && typ != "subdomain" {
		return
	}
	var raw map[string]json.RawMessage
	if json.Unmarshal(data, &raw) != nil {
		return
	}
	stamp := ssObservationTime(raw)
	now := time.Now().Unix()
	if stamp <= 0 || stamp > now+300 || now-stamp > ssMaxAge(c.link) {
		return
	}
	var record struct {
		URL, Domain, Host string
		IP                json.RawMessage
		Port              json.RawMessage
		Status            *int
	}
	if json.Unmarshal(data, &record) != nil {
		return
	}
	host := record.Domain
	if host == "" {
		host = record.Host
	}
	if host == "" {
		_ = json.Unmarshal(record.IP, &host)
	}
	if typ == "subdomain" {
		if c.domains == nil {
			c.domains = map[string]bool{}
		}
		for _, target := range targets {
			if ssInScope(host, []ssTarget{target}) {
				c.domains[target.Host] = true
			}
		}
		return
	}
	port, _ := strconv.Atoi(strings.Trim(string(record.Port), "\""))
	if u, err := url.Parse(record.URL); err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.User == nil {
		host = u.Hostname()
		if p, err := strconv.Atoi(u.Port()); err == nil {
			port = p
		} else if u.Scheme == "https" {
			port = 443
		} else {
			port = 80
		}
		if record.Status != nil && *record.Status >= 100 && *record.Status < 600 {
			c.http[host] = true
			c.urls[record.URL] = true
		}
	}
	for _, target := range targets {
		if !ssInScope(host, []ssTarget{target}) {
			continue
		}
		if c.ports[target.Host] == nil {
			c.ports[target.Host] = map[int]bool{}
		}
		if port > 0 && port <= 65535 {
			c.ports[target.Host][port] = true
		}
		if c.http[host] {
			c.http[target.Host] = true
		}
	}
}

func (c *ssCoverage) covered(host string) bool {
	matched := len(c.link.RequiredPorts) > 0
	for _, port := range c.link.RequiredPorts {
		if !c.ports[host][port] {
			return false
		}
	}
	for _, raw := range c.link.RequiredURLs {
		u, _ := url.Parse(raw)
		if u != nil && ssInScope(u.Hostname(), []ssTarget{{Host: host, Children: true}}) {
			matched = true
			if !c.urls[raw] {
				return false
			}
		}
	}
	if matched {
		return true
	}
	if ssCoverageMode(c.link) == "http" {
		return c.http[host]
	}
	// A service/crawl inventory requires the matching completed operation, not
	// merely one arbitrary historical asset from the same host.
	mode := ssCoverageMode(c.link)
	now := time.Now().Unix()
	if c.link.TemplateCoverage != mode || !ssSameScan(c.link) || c.link.ScanState != "completed" ||
		c.link.ScanStartedAt <= 0 || c.link.ScanStartedAt > now+300 || now-c.link.ScanStartedAt > ssMaxAge(c.link) {
		return false
	}
	switch mode {
	case "services":
		return len(c.ports[host]) > 0
	case "subdomains":
		return c.domains[host]
	case "urls":
		return c.http[host]
	}
	return false
}

func ssValidateCoverage(link *db.ScopeSentryLink, targets []ssTarget) error {
	switch link.CoverageMode {
	case "", "http", "services", "subdomains", "urls":
	default:
		return fmt.Errorf("coverage_mode 必须为 http/services/subdomains/urls")
	}
	if link.MaxAgeSeconds < 0 {
		return fmt.Errorf("max_age_seconds 不能为负数")
	}
	for _, port := range link.RequiredPorts {
		if port < 1 || port > 65535 {
			return fmt.Errorf("required_ports 超出有效端口范围")
		}
	}
	for _, raw := range link.RequiredURLs {
		u, err := url.Parse(raw)
		if err != nil || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") || !ssInScope(u.Hostname(), targets) {
			return fmt.Errorf("required_urls 必须是任务授权范围内的 HTTP/HTTPS URL")
		}
	}
	sort.Ints(link.RequiredPorts)
	sort.Strings(link.RequiredURLs)
	return nil
}

func ssTemplateCoverage(text string) string {
	ops, err := ssTemplateOperations(text)
	if err != nil {
		return "http"
	}
	if ops["port"] {
		return "services"
	}
	if ops["domains"] {
		return "subdomains"
	}
	if ops["crawl"] || ops["directory"] {
		return "urls"
	}
	return "http"
}
