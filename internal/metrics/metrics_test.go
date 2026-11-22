package metrics

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"mongo-journald/internal/model"
)

// fixture is a fake /proc + cgroup tree whose counters tests advance.
type fixture struct {
	t    *testing.T
	root string
}

func (f fixture) write(rel, content string) {
	f.t.Helper()
	p := filepath.Join(f.root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

func (f fixture) cgroup(rel string, cpuUsec, mem, rbytes, wbytes string) {
	f.write("cg/"+rel+"/cpu.stat", "usage_usec "+cpuUsec+"\nuser_usec 1\nsystem_usec 1\n")
	f.write("cg/"+rel+"/memory.current", mem+"\n")
	f.write("cg/"+rel+"/memory.peak", "999999999\n")
	f.write("cg/"+rel+"/pids.current", "7\n")
	f.write("cg/"+rel+"/io.stat", "8:0 rbytes="+rbytes+" wbytes="+wbytes+" rios=1 wios=1\n8:16 rbytes=100 wbytes=0\n")
}

func newFixture(t *testing.T) (fixture, *Sampler) {
	f := fixture{t, t.TempDir()}
	f.write("proc/loadavg", "0.52 0.41 0.36 2/321 5678\n")
	f.write("proc/meminfo", "MemTotal:       8000000 kB\nMemFree: 100 kB\nMemAvailable:   2000000 kB\nSwapTotal:      1000000 kB\nSwapFree:        750000 kB\n")
	f.write("proc/self/mountinfo", "")
	f.write("sys/block/sda/dev", "8:0\n")
	f.write("sys/block/dm-0/dev", "252:0\n")
	s := NewSampler(Options{
		Hostname: "h1", Retention: time.Hour, UnitRetention: 2 * time.Hour, Units: true,
		MinCPUPct: 1, MinMem: 100 << 20,
		Proc: filepath.Join(f.root, "proc"), Cgroup: filepath.Join(f.root, "cg"), SysBlock: filepath.Join(f.root, "sys/block"),
	})
	return f, s
}

func TestSample(t *testing.T) {
	f, s := newFixture(t)
	t0 := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)

	// baseline
	f.write("proc/stat", "cpu  1000 0 500 8000 100 0 0 50 0 0\ncpu0 500 0 250 4000 50 0 0 25 0 0\ncpu1 500 0 250 4000 50 0 0 25 0 0\nbtime 1\n")
	f.write("proc/vmstat", "nr_free_pages 5\noom_kill 3\n")
	f.write("proc/pressure/cpu", "some avg10=0.00 avg60=0.00 avg300=0.00 total=1000000\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=5\n")
	f.write("proc/pressure/memory", "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n")
	f.write("proc/pressure/io", "some avg10=0.00 avg60=0.00 avg300=0.00 total=2000000\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=1000000\n")
	f.write("proc/diskstats", "   8  0 sda 10 0 1000 5 20 0 2000 9 0 0 0\n   8  1 sda1 10 0 1000 5 20 0 2000 9 0 0 0\n 252  0 dm-0 10 0 1000 5 20 0 2000 9 0 0 0\n   7  0 loop0 1 0 8 0 0 0 0 0 0 0 0\n")
	netHdr := "Inter-|   Receive                                                |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"
	f.write("proc/net/dev", netHdr+"    lo: 500 5 0 0 0 0 0 0 500 5 0 0 0 0 0 0\n  eth0: 1000 10 0 1 0 0 0 0 2000 20 0 0 0 0 0 0\n  eth1: 7 1 0 0 0 0 0 0 7 1 0 0 0 0 0 0\nveth12: 1 1 0 0 0 0 0 0 1 1 0 0 0 0 0 0\n")
	f.cgroup("system.slice/busy.service", "1000000", "1000", "0", "0")
	f.cgroup("system.slice/fat.service", "500", "209715200", "0", "0") // 200 MiB, idle
	f.cgroup("system.slice/idle.service", "500", "1000", "0", "0")
	f.cgroup("system.slice/restarted.service", "9000000", "1000", "5000", "5000")
	f.cgroup("system.slice/system-getty.slice/getty@tty1.service", "10", "1000", "0", "0")
	f.cgroup("user.slice/user-1000.slice", "100", "1000", "0", "0")
	f.cgroup("user.slice/user-1000.slice/session-3.scope", "100", "1000", "0", "0")
	f.cgroup("init.scope", "100", "1000", "0", "0")
	f.cgroup("system.slice/dev-hugepages.mount", "100", "1000", "0", "0")

	if h, u := s.Sample(t0); h != nil || u != nil {
		t.Fatalf("first sample must only set the baseline, got %v %v", h, u)
	}

	// 60s later: +6000 jiffies total (user 1200, system 600, idle 3600, iowait 300, steal 300)
	f.write("proc/stat", "cpu  2000 200 1000 11600 400 50 50 350 0 0\ncpu0 1 0 1 1 1 0 0 1 0 0\ncpu1 1 0 1 1 1 0 0 1 0 0\n")
	f.write("proc/vmstat", "oom_kill 5\n")
	f.write("proc/pressure/cpu", "some avg10=0.00 avg60=0.00 avg300=0.00 total=7000000\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=9\n")
	f.write("proc/pressure/io", "some avg10=0.00 avg60=0.00 avg300=0.00 total=5000000\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=2500000\n")
	f.write("proc/diskstats", "   8  0 sda 10 0 3000 5 20 0 2500 9 0 0 0\n   8  1 sda1 10 0 3000 5 20 0 2500 9 0 0 0\n 252  0 dm-0 10 0 3000 5 20 0 2500 9 0 0 0\n")
	f.write("proc/net/dev", netHdr+"    lo: 900 5 0 0 0 0 0 0 900 5 0 0 0 0 0 0\n  eth0: 4000 10 2 4 0 0 0 0 2500 20 1 0 0 0 0 0\n  eth1: 7 1 0 0 0 0 0 0 7 1 0 0 0 0 0 0\n")
	f.cgroup("system.slice/busy.service", "31000000", "2000", "4096", "8192") // 30s CPU in 60s = 50%
	f.cgroup("system.slice/restarted.service", "600000", "1000", "10", "20")  // counter went backwards
	f.cgroup("system.slice/new.service", "1200000", "1000", "0", "0")

	h, units := s.Sample(t0.Add(time.Minute))
	if h == nil {
		t.Fatal("no host doc")
	}
	if h["server"] != "h1" || h["dt_s"] != 60.0 || h["ncpu"] != 2 || h["tasks"] != 321 || h["load1"] != 0.52 ||
		h["oom_kills"] != int64(2) || h["expireAt"] != t0.Add(time.Minute+time.Hour) {
		t.Errorf("host basics: %+v", h)
	}
	cpu := h["cpu"].(model.Doc)
	if cpu["user"] != 20.0 || cpu["system"] != 10.0 || cpu["iowait"] != 5.0 || cpu["steal"] != 5.0 || cpu["busy"] != 35.0 {
		t.Errorf("cpu: %+v", cpu)
	}
	mem := h["mem"].(model.Doc)
	if mem["total"] != int64(8000000*1024) || mem["available"] != int64(2000000*1024) || mem["used_pct"] != 75.0 ||
		mem["swap_used"] != int64(250000*1024) {
		t.Errorf("mem: %+v", mem)
	}
	psi := h["psi"].(model.Doc)
	if psi["cpu_some"] != 10.0 || psi["io_some"] != 5.0 || psi["io_full"] != 2.5 || psi["mem_some"] != 0.0 {
		t.Errorf("psi: %+v", psi)
	}
	if _, ok := psi["cpu_full"]; ok {
		t.Error("cpu_full must be left out")
	}
	// only the whole physical disk counts: not sda1, dm-0 or loop0
	if io := h["io"].(model.Doc); io["read_bytes"] != int64(2000*512) || io["write_bytes"] != int64(500*512) {
		t.Errorf("io: %+v", io)
	}
	nets := h["net"].([]model.Doc)
	if len(nets) != 1 || nets[0]["if"] != "eth0" || nets[0]["rx_bytes"] != int64(3000) || nets[0]["rx_errs"] != int64(2) ||
		nets[0]["rx_drop"] != int64(3) || nets[0]["tx_bytes"] != int64(500) || nets[0]["tx_errs"] != int64(1) {
		t.Errorf("net (want only eth0; lo, veth and idle eth1 skipped): %+v", nets)
	}

	got := map[string]UnitSample{}
	for _, u := range units {
		got[u.Unit] = u
	}
	for _, name := range []string{"busy.service", "fat.service", "idle.service", "restarted.service", "new.service",
		"getty@tty1.service", "user-1000.slice", "init.scope"} {
		if _, ok := got[name]; !ok {
			t.Errorf("missing unit %s", name)
		}
	}
	for _, name := range []string{"session-3.scope", "dev-hugepages.mount", "system.slice", "user.slice"} {
		if _, ok := got[name]; ok {
			t.Errorf("unexpected unit %s", name)
		}
	}
	b := got["busy.service"]
	if b.CPUUsec != 30000000 || b.CPUPct != 50 || b.Mem != 2000 || b.IORead != 4096 || b.IOWrite != 8192 || b.Tasks != 7 || b.MemPeak != 999999999 {
		t.Errorf("busy: %+v", b)
	}
	if r := got["restarted.service"]; r.CPUUsec != 600000 || r.CPUPct != 1 || r.IORead != 110 || r.IOWrite != 20 {
		t.Errorf("restarted (fresh counters count in full): %+v", r)
	}
	if n := got["new.service"]; n.CPUUsec != 1200000 || n.CPUPct != 2 {
		t.Errorf("new: %+v", n)
	}
	if !s.Busy(b) || !s.Busy(got["fat.service"]) || !s.Busy(got["restarted.service"]) || s.Busy(got["idle.service"]) {
		t.Error("busy thresholds")
	}

	at := t0.Add(time.Minute)
	d := s.Doc(b, at)
	if d["unit"] != "busy.service" || d["cpu_pct"] != 50.0 || d["cpu_usec"] != int64(30000000) || d["mem_peak"] != int64(999999999) ||
		d["expireAt"] != at.Add(2*time.Hour) || d["server"] != "h1" {
		t.Errorf("unit doc: %+v", d)
	}
	key, inc, max := Rollup(b)
	if key[0] != "busy.service" || inc["n"] != 1 || inc["cpu_usec"] != 30000000 || inc["mem_sum"] != 2000 || max["mem_max"] != 2000 {
		t.Errorf("rollup: %v %v %v", key, inc, max)
	}
}

func TestMissingSourcesAreOmitted(t *testing.T) {
	f, s := newFixture(t)
	_ = f // no stat, pressure, diskstats or cgroups at all
	t0 := time.Now()
	s.Sample(t0)
	h, units := s.Sample(t0.Add(10 * time.Second))
	if h == nil || len(units) != 0 {
		t.Fatalf("got %v %v", h, units)
	}
	for _, k := range []string{"cpu", "psi", "net", "disks", "ncpu"} {
		if _, ok := h[k]; ok {
			t.Errorf("%s should be omitted when its source is missing: %+v", k, h[k])
		}
	}
}

func TestParseMountinfo(t *testing.T) {
	got := parseMountinfo(`27 32 0:24 / /sys rw,nosuid shared:6 - sysfs sysfs rw
32 1 8:2 / / rw,relatime shared:1 - ext4 /dev/sda2 rw
40 32 8:2 /var/lib/mongo-journald /var/lib/mongo-journald rw,relatime shared:1 - ext4 /dev/sda2 rw
41 32 8:17 / /srv/my\040data rw,relatime shared:30 - xfs /dev/sdb1 rw,attr2
42 32 7:1 / /snap/core/1 ro,nodev shared:31 - squashfs /dev/loop1 ro
43 32 0:50 / /run/user/1000 rw shared:40 - tmpfs tmpfs rw
44 32 0:60 /@home /home rw shared:41 - btrfs /dev/sdc1 rw
45 32 0:60 /@home/x /mnt/x rw shared:41 - btrfs /dev/sdc1 rw
46 32 0:70 / /tank rw shared:42 - zfs tank rw
47 32 8:1 / /boot/efi rw shared:43 - vfat /dev/sda1 rw
`)
	want := []mount{
		{8, 2, "/", "ext4", "/dev/sda2"},
		{8, 17, "/srv/my data", "xfs", "/dev/sdb1"},
		{0, 60, "/home", "btrfs", "/dev/sdc1"},
		{0, 70, "/tank", "zfs", "tank"},
		{8, 1, "/boot/efi", "vfat", "/dev/sda1"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("mount %d: got %+v, want %+v", i, got[i], want[i])
		}
	}
}

// TestLive samples the real machine twice.
func TestLive(t *testing.T) {
	if _, err := os.Stat("/proc/stat"); err != nil {
		t.Skip("no /proc")
	}
	s := NewSampler(Options{Hostname: "h", Units: true})
	s.Sample(time.Now())
	time.Sleep(150 * time.Millisecond)
	h, _ := s.Sample(time.Now())
	if h == nil || h["mem"] == nil || h["load1"] == nil {
		t.Fatalf("host doc: %+v", h)
	}
	for _, d := range readDisks(readFile("/proc/self/mountinfo")) {
		if d["total"].(int64) <= 0 || d["mount"] == "" {
			t.Errorf("disk: %+v", d)
		}
	}
}
