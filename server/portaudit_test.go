package server

import (
	"testing"
)

func TestPortAuditParseAddresses(t *testing.T) {
	for _, c := range []struct {
		raw, ip string
		port    int
	}{{"0100007F:1F91", "127.0.0.1", 8081}, {"00000000:FFFF", "0.0.0.0", 65535}, {"00000000000000000000000001000000:0016", "::1", 22}} {
		ip, port, err := parseProcAddr(c.raw)
		if err != nil || ip.String() != c.ip || port != c.port {
			t.Fatalf("%s => %v:%d err=%v", c.raw, ip, port, err)
		}
	}
	for _, s := range []string{"0100007F:10000", "0100007F:12xx", "0100007F:0016junk", "x:0001", "0000:0016", "0100007F:-001", "0100007F:0016:0"} {
		if _, _, err := parseProcAddr(s); err == nil {
			t.Fatalf("accepted %q", s)
		}
	}
}
func TestPortAuditIgnoresNonListeningRows(t *testing.T) {
	rows := parseProcNetTCP(" sl local_address rem_address st\n 0: 00000000:1F91 00000000:0000 0A\n 1: 00000000:1F92 00000000:0000 01\n 2: broken 00000000:0000 0A\n")
	if len(rows) != 1 || rows[0].Port != 8081 {
		t.Fatalf("rows=%+v", rows)
	}
}
