package tunnel

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/session"
	"github.com/Autumn-27/artex/stage"
	xproxy "golang.org/x/net/proxy"
)

// localFixtureSession executes only generated tunnel management commands inside
// the isolated test container; no external hosts or real sessions are involved.
type localFixtureSession struct {
	id  int64
	dir string
}

func (f *localFixtureSession) ID() int64 {
	if f.id > 0 {
		return f.id
	}
	return 1234
}
func (*localFixtureSession) Kind() string               { return "http_phpcmd" }
func (*localFixtureSession) Test(context.Context) error { return nil }
func (f *localFixtureSession) Exec(ctx context.Context, cmd string, timeout time.Duration) (string, string, error) {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	c := exec.CommandContext(ctx, "sh", "-c", cmd)
	if f.dir != "" {
		c.Dir = f.dir
	}
	out, err := c.CombinedOutput()
	return string(out), "", err
}
func (*localFixtureSession) ReadFile(_ context.Context, path string) ([]byte, error) {
	return os.ReadFile(path)
}
func (*localFixtureSession) WriteFile(_ context.Context, path string, data []byte) error {
	return os.WriteFile(path, data, 0700)
}
func (*localFixtureSession) Close(context.Context) error { return nil }
func TestManagedChiselTransferAndRollback(t *testing.T) {
	binary := os.Getenv("ARTEX_TEST_CHISEL_PATH")
	if binary == "" {
		t.Skip("isolated chisel fixture not mounted")
	}
	dsn, _, err := db.DSN()
	if err != nil {
		t.Fatal(err)
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	st, err := stage.New(t.Context(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	stageServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(r.URL.Path, "/")
		if len(parts) != 4 {
			http.NotFound(w, r)
			return
		}
		st.Download(w, r, parts[2], parts[3])
	}))
	defer stageServer.Close()
	st.SetBaseURL(stageServer.URL)
	reg := session.NewRegistry()
	reg.Add(&localFixtureSession{})
	store := db.NewTunnelStore(d)
	m, err := NewManager(Options{Store: store, Stage: st, Sessions: reg, ChiselPath: binary, DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "managed tunnel fixture response") }))
	defer target.Close()
	addr := strings.TrimPrefix(target.URL, "http://")
	for _, kind := range []string{KindSocks, KindPortfwd} {
		t.Run(kind, func(t *testing.T) {
			o := &PlanOpts{TaskID: 222333444, ViaSessionID: 1234, CallbackHost: "127.0.0.1", DataDir: m.PlanDataDir(), PortMin: 24000, PortMax: 24099, CanListen: CanListen, VerifyAddr: addr}
			var p *Plan
			var err error
			if kind == KindSocks {
				p, err = PlanSocks(o)
			} else {
				host, port, _ := net.SplitHostPort(addr)
				o.TargetHost = host
				o.TargetPort, _ = strconv.Atoi(port)
				p, err = PlanPortfwd(o)
			}
			if err != nil {
				t.Fatal(err)
			}
			rec, err := m.Deploy(t.Context(), p)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Delete(context.Background(), rec.ID)
			if rec.State != db.TunnelAlive {
				t.Fatal("verified tunnel not alive")
			}
			transport := &http.Transport{}
			defer transport.CloseIdleConnections()
			endpoint := target.URL
			if kind == KindSocks {
				dialer, err := xproxy.SOCKS5("tcp", m.EntryAddr(p), nil, xproxy.Direct)
				if err != nil {
					t.Fatal(err)
				}
				transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
					return dialer.Dial(network, address)
				}
			} else {
				endpoint = "http://" + m.EntryAddr(p)
			}
			client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
			response, err := client.Get(endpoint)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(response.Body)
			response.Body.Close()
			if string(body) != "managed tunnel fixture response" {
				t.Fatal("no application traffic through tunnel")
			}
			if err := m.CleanupSession(context.Background(), p.ViaSessionID); err != nil {
				t.Fatal(err)
			}
			row, _ := store.Get(t.Context(), rec.ID)
			if row.State != db.TunnelStopped {
				t.Fatal("teardown did not update ledger")
			}
			if conn, err := net.DialTimeout("tcp", m.EntryAddr(p), time.Second); err == nil {
				conn.Close()
				t.Fatal("session cleanup left tunnel listener running")
			}
			for _, path := range []string{p.AuthFile, p.RemoteDir} {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatalf("managed resource remains: %s", filepath.Base(path))
				}
			}
		})
	}
	// Server starts, but target rejects CONNECT. Deployment must roll back all layers.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := ln.Addr().String()
	ln.Close()
	p, err := PlanSocks(&PlanOpts{TaskID: 222333444, ViaSessionID: 1234, CallbackHost: "127.0.0.1", DataDir: m.PlanDataDir(), PortMin: 24000, PortMax: 24099, CanListen: CanListen, VerifyAddr: closed})
	if err != nil {
		t.Fatal(err)
	}
	if rec, err := m.Deploy(t.Context(), p); err == nil {
		_ = m.Teardown(context.Background(), rec.ID)
		_ = store.Delete(context.Background(), rec.ID)
		t.Fatal("failed decisive CONNECT accepted")
	}
	recs, err := store.ListByTask(t.Context(), 222333444)
	if err != nil || len(recs) != 0 {
		t.Fatal("failed deploy retained ledger", err, len(recs))
	}
	for _, path := range []string{p.AuthFile, p.RemoteDir} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("failed deploy leaked managed files")
		}
	}
}

func TestManagedSuo5HTTPTransfer(t *testing.T) {
	binary := os.Getenv("ARTEX_TEST_SUO5_PATH")
	phpBase := os.Getenv("ARTEX_TEST_SUO5_PHP_URL")
	if binary == "" || phpBase == "" {
		t.Skip("isolated PHP/Suo5 fixture not configured")
	}
	dsn, _, err := db.DSN()
	if err != nil {
		t.Fatal(err)
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "suo5 application fixture") }))
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	target.Listener = ln
	target.Start()
	defer target.Close()
	address := net.JoinHostPort("artex-intranet-tests", strconv.Itoa(ln.Addr().(*net.TCPAddr).Port))
	reg := session.NewRegistry()
	reg.Add(&localFixtureSession{id: 1235, dir: "/fixturephp"})
	store := db.NewTunnelStore(d)
	m, err := NewManager(Options{Store: store, Sessions: reg, Suo5Path: binary, Suo5PayloadsDir: "/fixture-tools/suo5-payloads", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	p, err := PlanSuo5(&Suo5PlanOpts{TaskID: 222333555, ViaSessionID: 1235, ShellURL: phpBase + "/shell.php", SessionKind: "http_phpcmd", VerifyAddr: address, PortMin: 25000, PortMax: 25099, CanListen: CanListen, DataDir: m.PlanDataDir()})
	if err != nil {
		t.Fatal(err)
	}
	rec, err := m.Deploy(t.Context(), p)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Delete(context.Background(), rec.ID)
	defer m.Teardown(context.Background(), rec.ID)
	dialer, err := xproxy.SOCKS5("tcp", m.EntryAddr(p), &xproxy.Auth{User: p.AuthUser, Password: p.AuthPass}, xproxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	tr := &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) { return dialer.Dial(network, addr) }}
	defer tr.CloseIdleConnections()
	response, err := (&http.Client{Transport: tr, Timeout: 8 * time.Second}).Get("http://" + address)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if string(body) != "suo5 application fixture" {
		t.Fatal("Suo5 did not carry HTTP response")
	}
	if err := m.Teardown(context.Background(), rec.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p.PayloadPath); !os.IsNotExist(err) {
		t.Fatal("Suo5 payload remained after teardown")
	}
}
