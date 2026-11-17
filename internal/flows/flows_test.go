package flows

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"mongo-journald/internal/model"
)

var (
	hostIP = netip.MustParseAddr("10.0.0.5")
	webIP  = netip.MustParseAddr("140.82.112.3")
	scanIP = netip.MustParseAddr("203.0.113.9")
	ctrIP  = netip.MustParseAddr("172.17.0.2")
)

func isLocal(a netip.Addr) bool { return a == hostIP || a.IsLoopback() }

func ep(a netip.Addr, p uint16) Endpoint { return Endpoint{a, p} }

func mirror(src, dst Endpoint) (Tuple, Tuple) {
	return Tuple{src, dst}, Tuple{dst, src}
}

func outbound() Info {
	o, r := mirror(ep(hostIP, 50000), ep(webIP, 443))
	return Info{ID: 1, Proto: 6, Orig: o, Reply: r, OrigBytes: 1000, OrigPkts: 10, ReplyBytes: 50000, ReplyPkts: 40,
		Start: time.Unix(100, 0), Stop: time.Unix(102, 500e6), TCPState: 7, SeenReply: true, ICMPType: -1}
}

func inbound() Info {
	o, r := mirror(ep(scanIP, 61000), ep(hostIP, 22))
	return Info{ID: 2, Proto: 6, Orig: o, Reply: r, OrigBytes: 300, OrigPkts: 5, ReplyBytes: 4000, ReplyPkts: 6,
		TCPState: 8, SeenReply: true, ICMPType: -1}
}

func TestClassifyAndBuild(t *testing.T) {
	f := outbound()
	dir, local, remote := Classify(f, isLocal)
	if dir != DirOut || local != ep(hostIP, 50000) || remote != ep(webIP, 443) {
		t.Fatalf("out: %s %v %v", dir, local, remote)
	}
	proc := &Proc{PID: 42, Comm: "curl", Exe: "/usr/bin/curl", UID: 1000, Unit: "cron.service"}
	d := Build(f, dir, proc, "h1", time.Unix(999, 0), time.Time{}, 72*time.Hour)
	want := map[string]any{"dir": "out", "proto": "tcp", "src": "10.0.0.5", "dst": "140.82.112.3", "peer": "140.82.112.3",
		"port": 443, "sport": 50000, "dport": 443, "tx_bytes": int64(1000), "rx_bytes": int64(50000),
		"tx_pkts": int64(10), "rx_pkts": int64(40), "tcp_state": "TIME_WAIT", "dur_ms": int64(2500), "replied": true}
	for k, v := range want {
		if d[k] != v {
			t.Errorf("out %s = %v (%T), want %v", k, d[k], d[k], v)
		}
	}
	if d["nat"] != nil {
		t.Error("mirrored tuple must not be nat")
	}
	if !d["at"].(time.Time).Equal(time.Unix(102, 500e6)) || !d["expireAt"].(time.Time).Equal(time.Unix(102, 500e6).Add(72*time.Hour)) {
		t.Errorf("at/expireAt = %v %v", d["at"], d["expireAt"])
	}
	if p := d["proc"].(model.Doc); p["comm"] != "curl" || p["unit"] != "cron.service" || p["pid"] != 42 {
		t.Errorf("proc = %v", p)
	}

	f = inbound()
	dir, local, remote = Classify(f, isLocal)
	if dir != DirIn || local != ep(hostIP, 22) || remote != ep(scanIP, 61000) {
		t.Fatalf("in: %s %v %v", dir, local, remote)
	}
	seen := time.Unix(500, 0)
	d = Build(f, dir, nil, "h1", time.Unix(510, 0), seen, 0)
	if d["peer"] != "203.0.113.9" || d["port"] != 22 || d["tx_bytes"] != int64(4000) || d["rx_bytes"] != int64(300) {
		t.Errorf("in doc = %v", d)
	}
	if d["dur_ms"] != int64(10000) || d["proc"] != nil || d["expireAt"] != nil {
		t.Errorf("in timing/proc = %v %v %v", d["dur_ms"], d["proc"], d["expireAt"])
	}

	// docker port-forward: host:8080 DNATed to a container
	o := Tuple{ep(scanIP, 40000), ep(hostIP, 8080)}
	r := Tuple{ep(ctrIP, 80), ep(scanIP, 40000)}
	f = Info{Proto: 6, Orig: o, Reply: r, TCPState: -1, ICMPType: -1}
	if dir, _, _ := Classify(f, isLocal); dir != DirFwd {
		t.Errorf("dnat to container: %s", dir)
	}
	if d := Build(f, DirFwd, nil, "h1", time.Now(), time.Time{}, 0); d["nat"] != true || d["start"] != nil {
		t.Errorf("fwd doc = %v", d)
	}
}

func TestICMP(t *testing.T) {
	o, r := mirror(ep(hostIP, 0), ep(webIP, 0))
	f := Info{Proto: 1, Orig: o, Reply: r, TCPState: -1, ICMPType: 8, ICMPCode: 0}
	d := Build(f, DirOut, nil, "h1", time.Now(), time.Time{}, 0)
	if d["proto"] != "icmp" || d["icmp_type"] != 8 || d["port"] != nil || d["sport"] != nil {
		t.Errorf("icmp doc = %v", d)
	}
}

func TestFilter(t *testing.T) {
	lo := netip.MustParseAddr("127.0.0.1")
	o, r := mirror(ep(lo, 40000), ep(lo, 53))
	loop := Info{Proto: 17, Orig: o, Reply: r}
	if !(Filter{}).Drop(loop) || (Filter{IncludeLoopback: true}).Drop(loop) {
		t.Error("loopback filter")
	}
	f := Filter{IgnoreNets: []netip.Prefix{netip.MustParsePrefix("140.82.0.0/16")}}
	if !f.Drop(outbound()) || f.Drop(inbound()) {
		t.Error("cidr filter")
	}
	f = Filter{IgnorePorts: map[uint16]bool{22: true}}
	if !f.Drop(inbound()) || f.Drop(outbound()) {
		t.Error("port filter")
	}
}

func TestRollupKey(t *testing.T) {
	f := outbound()
	d := Build(f, DirOut, &Proc{Comm: "curl", Unit: "cron.service"}, "h1", time.Now(), time.Time{}, 0)
	k, inc := RollupKey(d)
	if fmt.Sprint(k) != "[out tcp 140.82.112.3 443 curl cron.service]" || inc["flows"] != 1 || inc["rx_bytes"] != 50000 {
		t.Errorf("key=%v inc=%v", k, inc)
	}
	k, _ = RollupKey(Build(inbound(), DirIn, nil, "h1", time.Now(), time.Time{}, 0))
	if fmt.Sprint(k) != "[in tcp 203.0.113.9 22 <nil> <nil>]" {
		t.Errorf("in key=%v", k)
	}
}

func TestUnitFromCgroup(t *testing.T) {
	cases := map[string]string{
		"0::/system.slice/ssh.service\n":                         "ssh.service",
		"0::/user.slice/user-0.slice/session-1.scope\n":          "session-1.scope",
		"0::/system.slice/docker-abc.scope/init\n":               "docker-abc.scope",
		"12:cpu:/x\n1:name=systemd:/system.slice/cron.service\n": "cron.service",
		"0::/\n": "",
		"0::/user.slice/user-1000.slice/user@1000.service/app.slice/x.service\n": "x.service",
	}
	for in, want := range cases {
		if got := UnitFromCgroup(in); got != want {
			t.Errorf("UnitFromCgroup(%q) = %q, want %q", in, got, want)
		}
	}
}

// fakeProc builds a /proc tree: pid → (comm, cgroup, socket inodes).
func fakeProc(t *testing.T, procs map[int]struct {
	comm, cgroup string
	inodes       []uint64
}) string {
	root := t.TempDir()
	for pid, p := range procs {
		dir := filepath.Join(root, fmt.Sprint(pid))
		must(t, os.MkdirAll(filepath.Join(dir, "fd"), 0o755))
		must(t, os.WriteFile(filepath.Join(dir, "comm"), []byte(p.comm+"\n"), 0o644))
		must(t, os.WriteFile(filepath.Join(dir, "cgroup"), []byte(p.cgroup), 0o644))
		must(t, os.Symlink("/usr/bin/"+p.comm, filepath.Join(dir, "exe")))
		must(t, os.Symlink("/dev/null", filepath.Join(dir, "fd", "0")))
		for i, ino := range p.inodes {
			must(t, os.Symlink(fmt.Sprintf("socket:[%d]", ino), filepath.Join(dir, "fd", fmt.Sprint(3+i))))
		}
	}
	must(t, os.MkdirAll(filepath.Join(root, "self"), 0o755)) // non-numeric entries are skipped
	return root
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

type fakeSocks map[uint8][]Sock

func (f fakeSocks) Dump(p uint8) ([]Sock, error) { return f[p], nil }

func TestAttributor(t *testing.T) {
	any4 := netip.IPv4Unspecified()
	any6 := netip.IPv6Unspecified()
	root := fakeProc(t, map[int]struct {
		comm, cgroup string
		inodes       []uint64
	}{
		42:   {"curl", "0::/system.slice/cron.service\n", []uint64{1001}},
		800:  {"sshd", "0::/system.slice/ssh.service\n", []uint64{2001}},
		1500: {"sshd", "0::/system.slice/ssh.service\n", []uint64{2001}}, // forked child shares the listener
		900:  {"tailscaled", "0::/system.slice/tailscaled.service\n", []uint64{3001}},
	})
	socks := fakeSocks{
		6: {
			{Local: ep(hostIP, 50000), Remote: ep(webIP, 443), Inode: 1001, UID: 1000},
			{Local: ep(any6, 22), Remote: ep(any6, 0), Inode: 2001, UID: 0},      // dual-stack listener
			{Local: ep(hostIP, 22), Remote: ep(scanIP, 61000), Inode: 0, UID: 0}, // not yet accepted
			{Local: ep(hostIP, 50001), Remote: ep(webIP, 443), Inode: 0, UID: 0}, // TIME_WAIT
		},
		17: {{Local: ep(any4, 41641), Remote: ep(any4, 0), Inode: 3001, UID: 0}}, // unconnected UDP
	}
	a := NewAttributor(socks, ProcFS{Root: root}, AttribConfig{MaxWait: time.Second})
	t0 := time.Unix(1000, 0)

	a.New(1, 6, DirOut, ep(hostIP, 50000), ep(webIP, 443), t0)
	a.New(2, 6, DirIn, ep(hostIP, 22), ep(scanIP, 61000), t0)
	a.New(3, 17, DirOut, ep(hostIP, 41641), ep(webIP, 3478), t0)
	a.New(4, 6, DirOut, ep(hostIP, 50001), ep(webIP, 443), t0) // socket already gone
	a.New(5, 6, DirFwd, Endpoint{}, Endpoint{}, t0)
	a.Round(t0.Add(100 * time.Millisecond))

	check := func(id uint32, comm, unit string, pid, uid int) {
		t.Helper()
		p, seen := a.Take(id)
		if !seen.Equal(t0) {
			t.Errorf("flow %d seen = %v", id, seen)
		}
		if comm == "" {
			if p != nil {
				t.Errorf("flow %d: want no proc, got %+v", id, p)
			}
			return
		}
		if p == nil || p.Comm != comm || p.Unit != unit || p.PID != pid || p.UID != uid || p.Exe != "/usr/bin/"+comm {
			t.Errorf("flow %d: proc = %+v", id, p)
		}
	}
	check(1, "curl", "cron.service", 42, 1000)
	check(2, "sshd", "ssh.service", 800, 0) // falls back to the listener, lowest pid
	check(3, "tailscaled", "tailscaled.service", 900, 0)
	check(5, "", "", 0, 0)

	// flow 4 stays pending until MaxWait, then resolves to nil
	if _, still := a.pending[4]; !still {
		t.Fatal("flow 4 should still be pending")
	}
	a.Round(t0.Add(2 * time.Second))
	check(4, "", "", 0, 0)

	if n, p := a.Stats(); n != 4 || p != 3 { // fwd flow 5 is not counted
		t.Errorf("stats = %d/%d", p, n)
	}
	// unknown flow (started before the shipper)
	if p, seen := a.Take(99); p != nil || !seen.IsZero() {
		t.Error("unknown flow")
	}
}

func TestAttributorRescanRateLimit(t *testing.T) {
	root := fakeProc(t, map[int]struct {
		comm, cgroup string
		inodes       []uint64
	}{42: {"curl", "0::/x.service\n", []uint64{1001}}})
	socks := fakeSocks{6: {{Local: ep(hostIP, 1), Remote: ep(webIP, 443), Inode: 1001}}}
	a := NewAttributor(socks, ProcFS{Root: root}, AttribConfig{MinScan: time.Second})
	t0 := time.Unix(1000, 0)
	a.New(1, 6, DirOut, ep(hostIP, 1), ep(webIP, 443), t0)
	a.Round(t0)
	if p, _ := a.Take(1); p == nil {
		t.Fatal("first flow unattributed")
	}

	// a new process appears; within MinScan the cache is stale, so it waits
	dir := filepath.Join(root, "43")
	must(t, os.MkdirAll(filepath.Join(dir, "fd"), 0o755))
	must(t, os.WriteFile(filepath.Join(dir, "comm"), []byte("wget\n"), 0o644))
	must(t, os.Symlink("socket:[1002]", filepath.Join(dir, "fd", "3")))
	a.socks = fakeSocks{6: {{Local: ep(hostIP, 2), Remote: ep(webIP, 443), Inode: 1002}}}
	a.New(2, 6, DirOut, ep(hostIP, 2), ep(webIP, 443), t0)
	a.Round(t0.Add(200 * time.Millisecond))
	if _, still := a.pending[2]; !still {
		t.Fatal("flow 2 should wait for the next allowed scan")
	}
	a.Round(t0.Add(1100 * time.Millisecond))
	if p, _ := a.Take(2); p == nil || p.Comm != "wget" {
		t.Fatalf("flow 2 proc = %+v", p)
	}
}
