package flows

import (
	"net"
	"net/netip"
	"os"
	"testing"
	"time"
)

// TestAttributorLive exercises the real sock_diag dump and /proc scan
// against this test process's own sockets (no privileges needed).
func TestAttributorLive(t *testing.T) {
	if _, err := (NetlinkSockets{}).Dump(6); err != nil {
		t.Skipf("sock_diag unavailable: %v", err)
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			defer c.Close()
			time.Sleep(2 * time.Second)
		}
	}()
	c, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()

	local := netip.MustParseAddrPort(c.LocalAddr().String())
	remote := netip.MustParseAddrPort(c.RemoteAddr().String())
	uport := uint16(u.LocalAddr().(*net.UDPAddr).Port)

	a := NewAttributor(NetlinkSockets{}, ProcFS{Root: "/proc"}, AttribConfig{})
	now := time.Now()
	a.New(1, 6, DirOut, ep(local.Addr(), local.Port()), ep(remote.Addr(), remote.Port()), now)
	a.New(2, 6, DirIn, ep(remote.Addr(), remote.Port()), ep(local.Addr(), local.Port()), now)
	a.New(3, 17, DirOut, ep(netip.MustParseAddr("10.9.9.9"), uport), ep(netip.MustParseAddr("192.0.2.1"), 53), now)
	a.Round(now)

	self := os.Getpid()
	for id := uint32(1); id <= 3; id++ {
		p, _ := a.Take(id)
		if p == nil {
			t.Errorf("flow %d: not attributed", id)
			continue
		}
		if p.PID != self || p.UID != os.Getuid() || p.Comm == "" {
			t.Errorf("flow %d: proc = %+v, want pid %d uid %d", id, p, self, os.Getuid())
		}
	}
}
