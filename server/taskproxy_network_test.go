package server

import (
	"context"
	"encoding/binary"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/tunnel"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func TestTaskProxyNetworkRouting(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "task proxy fixture") }))
	defer target.Close()
	socks, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer socks.Close()
	var dials atomic.Int32
	go func() {
		for {
			conn, err := socks.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				header := make([]byte, 2)
				if _, err := io.ReadFull(c, header); err != nil {
					return
				}
				methods := make([]byte, int(header[1]))
				if _, err := io.ReadFull(c, methods); err != nil {
					return
				}
				c.Write([]byte{5, 0})
				request := make([]byte, 4)
				if _, err := io.ReadFull(c, request); err != nil {
					return
				}
				var host string
				switch request[3] {
				case 1:
					b := make([]byte, 4)
					if _, err := io.ReadFull(c, b); err != nil {
						return
					}
					host = net.IP(b).String()
				case 3:
					b := make([]byte, 1)
					io.ReadFull(c, b)
					name := make([]byte, int(b[0]))
					io.ReadFull(c, name)
					host = string(name)
				default:
					return
				}
				ports := make([]byte, 2)
				if _, err := io.ReadFull(c, ports); err != nil {
					return
				}
				address := net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(ports))))
				upstream, err := net.DialTimeout("tcp", address, time.Second)
				if err != nil {
					return
				}
				defer upstream.Close()
				dials.Add(1)
				c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
				go io.Copy(upstream, c)
				io.Copy(c, upstream)
			}(conn)
		}
	}()
	lister := &fakeTunnelLister{recs: []*db.TunnelRecord{socksRec(1, db.TunnelAlive, socks.Addr().(*net.TCPAddr).Port)}}
	port := freePort(t)
	m := newTaskProxyManager(t.TempDir(), lister, func() string { return "" }, port, port)
	defer m.Close()
	addr, _ := m.ForTask(context.Background(), 900)
	if addr == "" {
		t.Fatal("no task proxy")
	}
	parsed, err := url.Parse(addr)
	if err != nil {
		t.Fatal(err)
	}
	tr := &http.Transport{Proxy: http.ProxyURL(parsed)}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 2 * time.Second}
	fetch := func() {
		t.Helper()
		var response *http.Response
		var err error
		until := time.Now().Add(3 * time.Second)
		for {
			response, err = client.Get(target.URL)
			if err == nil || time.Now().After(until) {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if string(body) != "task proxy fixture" {
			t.Fatalf("wrong forwarded response: %s", body)
		}
	}
	fetch()
	if dials.Load() != 1 {
		t.Fatal("task did not route through selected SOCKS tunnel")
	}
	tr.CloseIdleConnections()
	lister.recs = []*db.TunnelRecord{socksRec(1, db.TunnelError, socks.Addr().(*net.TCPAddr).Port)}
	m.Refresh(context.Background(), 900)
	fetch()
	if dials.Load() != 1 {
		t.Fatal("dead tunnel remained selected")
	}
	tr.CloseIdleConnections()
	m.CloseTask(900)
	until := time.Now().Add(time.Second)
	for !tunnel.CanListen(port) && time.Now().Before(until) {
		time.Sleep(10 * time.Millisecond)
	}
	if !tunnel.CanListen(port) {
		t.Fatal("task proxy listener remained after close")
	}
}
