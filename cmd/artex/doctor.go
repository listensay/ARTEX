// Adapted from panda0x123/artex-ymh deployment diagnostics.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Autumn-27/artex/config"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/server"
	"github.com/Autumn-27/artex/tools"
)

type doctorStatus string

const (
	docOK   doctorStatus = "OK"
	docWarn doctorStatus = "WARN"
	docFail doctorStatus = "FAIL"
	docSkip doctorStatus = "SKIP"
)

func runDoctor(args []string) int {
	return doctor(args, os.Stdout, os.Stderr)
}

// doctor bypasses all service initialization. The only filesystem writes are
// temporary write probes, removed immediately; no directories are created.
func doctor(args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(errOut)
	addr := fs.String("addr", "127.0.0.1:8787", "HTTP listen address, same as service -addr")
	proxy := fs.String("proxy", "127.0.0.1:8788", "recording proxy address, empty disables it")
	data := fs.String("data", filepath.Join(config.BaseDir(), "data"), "data directory, same as service -data")
	timeout := fs.Duration("timeout", 5*time.Second, "total PostgreSQL probe timeout (max 60s)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 || *timeout <= 0 || *timeout > time.Minute {
		fmt.Fprintln(errOut, "doctor: unexpected arguments or invalid timeout (0 < timeout <= 60s)")
		return 2
	}
	fmt.Fprintf(out, "ARTEX doctor — 部署预检 (%s/%s)\n不启动服务、不写 DB；目录可写性仅用临时文件检查并删除。\n\n", runtime.GOOS, runtime.GOARCH)
	counts := map[doctorStatus]int{}
	check := func(status doctorStatus, name, note string) {
		counts[status]++
		fmt.Fprintf(out, "[%-4s] %s: %s\n", status, name, note)
	}

	// Never print the DSN or raw driver errors: either can contain credentials.
	dsn, source, err := db.DSN()
	profiles := -1
	dbOK := false
	if err != nil {
		check(docFail, "PostgreSQL", "未配置；设置 ARTEX_PG_DSN 或 config.json 的 database")
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), *timeout)
		profiles, err = db.Probe(ctx, dsn)
		cancel()
		if err != nil {
			check(docFail, "PostgreSQL", "连接或只读查询失败；检查连接配置、网络、凭据及 llm_profiles 读取权限（连接信息已隐藏）")
		} else {
			dbOK = true
			check(docOK, "PostgreSQL", "可连接，来源: "+source+"（连接信息已隐藏）")
		}
	}
	switch {
	case !dbOK:
		check(docSkip, "LLM profile", "数据库预检失败，无法检查")
	case profiles < 0:
		check(docWarn, "LLM profile", "llm_profiles 表尚未初始化；由正常启动初始化")
	case profiles == 0:
		check(docWarn, "LLM profile", "未配置；请在 UI 添加 LLM profile")
	default:
		check(docOK, "LLM profile", fmt.Sprintf("已配置 %d 个；未调用模型，不验证模型凭据或连通性", profiles))
	}
	status, note := doctorWritableDir(*data)
	check(status, "data 目录", note)
	status, note = doctorWritableDir(config.SecretDir())
	check(status, "密钥目录", note)
	status, note = doctorSecretLayout(*data, config.SecretDir())
	check(status, "密钥隔离", note)

	manifest, err := tools.Load(tools.ManifestPath())
	if err != nil {
		if os.IsNotExist(err) && strings.TrimSpace(os.Getenv("ARTEX_TOOLS_MANIFEST")) == "" {
			check(docWarn, "工具清单", "默认清单缺失，无法校验；请部署 packaging/tools-manifest.json")
		} else {
			check(docFail, "工具清单", "清单缺失、不可读或格式/路径/哈希不合法；检查 ARTEX_TOOLS_MANIFEST")
		}
		check(docSkip, "隧道工具", "无有效清单")
		check(docSkip, "军火库工具", "无有效清单")
	} else {
		check(docOK, "工具清单", fmt.Sprintf("已加载 %d 项: %s", len(manifest.Tools), tools.ManifestPath()))
		results := tools.Check(manifest, *data)
		for _, category := range []string{"tunnel", "arsenal"} {
			total, present, verified, warned := 0, 0, 0, false
			for _, r := range results {
				if r.Entry.Category != category {
					continue
				}
				total++
				s := docWarn
				if r.Status == tools.StatusOK {
					verified++
					s = docOK
				}
				if r.Status == tools.StatusOK || r.Status == tools.StatusUnpinned || r.Status == tools.StatusMismatch {
					present++
				}
				if r.Entry.Kind == "directory" && r.Status == tools.StatusUnpinned {
					s = docOK
				}
				if !r.PlatformMatch {
					s = docWarn
				}
				warned = warned || s == docWarn
				check(s, "工具 "+r.Entry.Name, doctorToolNote(r))
			}
			label := "军火库工具"
			if category == "tunnel" {
				label = "隧道工具"
			}
			s := docOK
			if warned {
				s = docWarn
			} else if total == 0 {
				s = docSkip
			}
			check(s, label, fmt.Sprintf("存在 %d/%d，文件 sha256 一致 %d；不安装、不执行工具", present, total, verified))
		}
	}

	if !doctorValidAddr(*addr) {
		check(docFail, "HTTP 监听", "地址无效，请使用 host:port")
	} else {
		enabled, explicit := server.GateEnabled(*addr)
		switch {
		case !enabled:
			check(docWarn, "伪装门控", "ARTEX_GATE 显式关闭，包括经网关转发的本机入口会直接暴露")
		case explicit:
			check(docOK, "伪装门控", "显式开启（预检不创建入口、口令或密钥）")
		default:
			check(docOK, "伪装门控", "默认开启，包括回环监听（预检不创建入口、口令或密钥）")
		}
	}
	switch {
	case *proxy == "":
		check(docSkip, "录制代理", "已禁用")
	case !doctorValidAddr(*proxy):
		check(docFail, "录制代理", "地址无效，请使用 host:port")
	case !doctorLoopback(*proxy):
		check(docWarn, "录制代理", "监听非回环地址；门控不保护独立录制代理端口，需在网络层限制访问")
	default:
		check(docOK, "录制代理", "仅回环监听")
	}
	if callback := config.CallbackAddr(); callback == "" {
		check(docWarn, "回连地址", "未配置；chisel 部署需要操作者配置目标可达的地址，预检不发包")
	} else if !doctorValidAddr(callback) {
		check(docFail, "回连地址", "地址无效，需要 host:port")
	} else {
		check(docOK, "回连地址", "已配置；需自行确认目标可达性，预检不发包")
	}
	fmt.Fprintf(out, "\n汇总：OK %d · WARN %d · FAIL %d · SKIP %d\n", counts[docOK], counts[docWarn], counts[docFail], counts[docSkip])
	if counts[docFail] > 0 {
		return 1
	}
	return 0
}

func doctorToolNote(r tools.CheckResult) string {
	note := "缺失"
	switch r.Status {
	case tools.StatusOK:
		note = "sha256 一致"
	case tools.StatusUnpinned:
		note = "文件存在，sha256 未钉"
		if r.Entry.Kind == "directory" {
			note = "目录存在，未校验目录内容"
		}
	case tools.StatusMismatch:
		note = fmt.Sprintf("sha256 不匹配（期望 %s，实际 %s；只告警）", r.Entry.SHA256, r.Actual)
	case tools.StatusUnreadable:
		note = "不可读或文件/目录类型错误"
	}
	version := r.Entry.Version
	if version == "" {
		version = "未知"
	}
	note += fmt.Sprintf("；版本 %s；路径 %s", version, r.Path)
	if !r.PlatformMatch {
		note += fmt.Sprintf("；参考平台 %s 与宿主不同（目标侧文件可不同；宿主工具需采用对应平台清单）", r.Entry.Platform)
	}
	return note
}

func doctorWritableDir(dir string) (doctorStatus, string) {
	p := filepath.Clean(dir)
	missing := false
	for {
		st, err := os.Stat(p)
		if err == nil {
			if !st.IsDir() {
				return docFail, dir + " 或其父路径不是目录"
			}
			break
		}
		if !os.IsNotExist(err) || filepath.Dir(p) == p {
			return docFail, dir + " 无法访问"
		}
		missing = true
		p = filepath.Dir(p)
	}
	f, err := os.CreateTemp(p, ".artex-doctor-*")
	if err != nil {
		return docFail, dir + " 或最近父目录不可写"
	}
	closeErr := f.Close()
	removeErr := os.Remove(f.Name())
	if closeErr != nil || removeErr != nil {
		return docFail, dir + " 临时探测文件关闭或清理失败"
	}
	if missing {
		return docWarn, dir + " 尚不存在；最近父目录可写，未创建目录"
	}
	return docOK, dir + " 可写"
}

// Resolve existing parent symlinks so a secret path alias into data is detected.
func doctorResolvedPath(p string) string {
	abs, _ := filepath.Abs(p)
	var tail []string
	for {
		if real, err := filepath.EvalSymlinks(abs); err == nil {
			for i := len(tail) - 1; i >= 0; i-- {
				real = filepath.Join(real, tail[i])
			}
			return real
		}
		parent := filepath.Dir(abs)
		if parent == abs {
			return p
		}
		tail = append(tail, filepath.Base(abs))
		abs = parent
	}
}

func doctorSecretLayout(data, secrets string) (doctorStatus, string) {
	data, secrets = doctorResolvedPath(data), doctorResolvedPath(secrets)
	if rel, err := filepath.Rel(data, secrets); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return docFail, "密钥目录位于可浏览 data 工作目录内；请设置独立 ARTEX_SECRET_DIR"
	}
	for _, name := range []string{"jwt.key", "gate.key", "gate.token"} {
		st, err := os.Lstat(filepath.Join(secrets, name))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil || !st.Mode().IsRegular() {
			return docFail, name + " 不可访问或不是普通文件"
		}
		if runtime.GOOS != "windows" && st.Mode().Perm()&0o077 != 0 {
			return docWarn, name + " 权限过宽；建议 0600（未读取密钥内容）"
		}
	}
	return docOK, "位于 data 目录之外；未读取或创建密钥内容"
}

func doctorValidAddr(addr string) bool {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	n, err := net.LookupPort("tcp", port)
	return err == nil && n > 0 && n <= 65535
}

func doctorLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
