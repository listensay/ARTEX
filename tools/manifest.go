// Package tools 管理外部工具文件的版本清单与完整性自检。
//
// 清单包括参考仓库的隧道文件（suo5/chisel）与军火库常用工具
// （gogo/naabu/httpx/katana/fscan/impacket/…，通常放 data/tools/ 下）。
// 本包只检查文件，不安装、执行或注册工具。清单（packaging/tools-manifest.json)
// 记录每个工具的名称/用途/版本/平台/sha256/相对路径；sha256 为空串表示「未钉」
// （尚不知道正确哈希，宁可留空也不编造）。启动与 `artex doctor` 共用这里的
// Load/Check：存在的二进制且清单里钉了哈希的才校验，不匹配只警告不阻断（用户
// 可能自编译）；清单文件本身缺失（开发态）由调用方静默跳过。
package tools

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/Autumn-27/artex/config"
)

// Entry 是清单里一个外部工具的记录。
type Entry struct {
	Name     string `json:"name"`           // 工具名（唯一）
	Purpose  string `json:"purpose"`        // 用途（一行话）
	Version  string `json:"version"`        // 钉的版本；空 = 未钉
	Platform string `json:"platform"`       // 适用平台（如 linux/amd64;any = 不限）
	SHA256   string `json:"sha256"`         // 钉的 sha256；空串 = 未钉（不校验）
	Path     string `json:"path"`           // 相对 data 目录的路径（文件或目录）
	Env      string `json:"env"`            // 可选：覆盖路径的环境变量（如 ARTEX_SUO5_PATH)
	Category string `json:"category"`       // tunnel（隧道） | arsenal（军火库）
	Kind     string `json:"kind,omitempty"` // file (default) or directory
}

// Manifest 是 tools-manifest.json 的整体结构。
type Manifest struct {
	Tools []Entry `json:"tools"`
}

// ManifestPath 解析清单文件路径：
//
//	env ARTEX_TOOLS_MANIFEST  >  BaseDir()/packaging/tools-manifest.json
//
// 返回的路径可能不存在（开发态/裁剪部署）——调用方用 os.IsNotExist 判断后静默跳过。
func ManifestPath() string {
	if v := strings.TrimSpace(os.Getenv("ARTEX_TOOLS_MANIFEST")); v != "" {
		return v
	}
	return filepath.Join(config.BaseDir(), "packaging", "tools-manifest.json")
}

// Load 读取并解析清单文件。文件缺失时返回的 error 满足 os.IsNotExist。
func Load(path string) (*Manifest, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	if len(m.Tools) == 0 {
		return nil, fmt.Errorf("empty tools manifest")
	}
	seen := make(map[string]bool)
	for _, e := range m.Tools {
		if e.Name == "" || seen[e.Name] {
			return nil, fmt.Errorf("empty or duplicate tool name: %q", e.Name)
		}
		seen[e.Name] = true
		p := filepath.Clean(filepath.FromSlash(e.Path))
		if e.Path == "" || p == "." || filepath.IsAbs(p) || p == ".." || strings.HasPrefix(p, ".."+string(filepath.Separator)) || strings.Contains(e.Path, "\\") || strings.Contains(e.Path, ":") {
			return nil, fmt.Errorf("invalid data-relative path for %s", e.Name)
		}
		if e.Kind != "" && e.Kind != "file" && e.Kind != "directory" {
			return nil, fmt.Errorf("invalid kind for %s", e.Name)
		}
		if e.Kind == "directory" && e.SHA256 != "" {
			return nil, fmt.Errorf("directory hash is not supported: %s", e.Name)
		}
		if e.SHA256 != "" {
			sum, err := hex.DecodeString(e.SHA256)
			if err != nil || len(sum) != sha256.Size {
				return nil, fmt.Errorf("invalid sha256 for %s", e.Name)
			}
		}
	}
	return &m, nil
}

// Status 是单个工具的自检结论。
type Status int

const (
	StatusOK         Status = iota // 存在；若钉了哈希则一致
	StatusUnpinned                 // 存在，但清单未钉哈希（只报存在，不校验）
	StatusMissing                  // 缺失（精简环境常态，不视为故障）
	StatusMismatch                 // 存在但哈希与清单不符（只警告，可能自编译）
	StatusUnreadable               // 不可读、非普通文件或类型与清单不符
)

// CheckResult 是单个工具的自检结果。
type CheckResult struct {
	Entry         Entry
	Status        Status
	Path          string // 实际解析出的绝对/相对路径（env 覆盖优先）
	Actual        string // 实际 sha256（算了才有）
	PlatformMatch bool   // Reference platform matches this process; target payloads may differ.
}

// Check 对清单里每个工具做存在性 + （钉了哈希的）sha256 校验。dataDir 是 data
// 目录；条目带 env 且环境变量已设置时优先用环境变量指定的路径（与 tunnel 子系统
// 的解析顺序一致）。目录条目只做存在性检查（无法对目录算单哈希）。
func Check(m *Manifest, dataDir string) []CheckResult {
	if m == nil {
		return nil
	}
	out := make([]CheckResult, 0, len(m.Tools))
	for _, e := range m.Tools {
		out = append(out, CheckEntry(e, dataDir))
	}
	return out
}

// CheckEntry 校验单个清单条目（见 Check)。
func CheckEntry(e Entry, dataDir string) CheckResult {
	r := CheckResult{Entry: e, Status: StatusMissing,
		PlatformMatch: e.Platform == "" || e.Platform == "any" || e.Platform == runtime.GOOS+"/"+runtime.GOARCH}
	p := ""
	if e.Env != "" {
		p = strings.TrimSpace(os.Getenv(e.Env))
	}
	if p == "" {
		p = filepath.Join(dataDir, filepath.FromSlash(e.Path))
	}
	if abs, err := filepath.Abs(p); err == nil {
		p = abs
	}
	r.Path = p
	st, err := os.Stat(p)
	if err != nil {
		if !os.IsNotExist(err) {
			r.Status = StatusUnreadable
		}
		return r
	}
	want := strings.ToLower(strings.TrimSpace(e.SHA256))
	if e.Kind == "directory" {
		if st.IsDir() {
			r.Status = StatusUnpinned
		} else {
			r.Status = StatusUnreadable
		}
		return r
	}
	if !st.Mode().IsRegular() {
		r.Status = StatusUnreadable
		return r
	}
	if want == "" {
		// Even an unpinned file must be readable; never execute tools to check them.
		f, err := os.Open(p)
		if err != nil {
			r.Status = StatusUnreadable
			return r
		}
		_ = f.Close()
		r.Status = StatusUnpinned
		return r
	}
	sum, err := fileSHA256(p)
	if err != nil {
		r.Status = StatusUnreadable
		return r
	}
	r.Actual = sum
	if sum == want {
		r.Status = StatusOK
	} else {
		r.Status = StatusMismatch
	}
	return r
}

// fileSHA256 streams the complete file without invoking the tool.
func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
