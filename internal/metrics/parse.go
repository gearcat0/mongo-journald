package metrics

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"mongo-journald/internal/model"
)

// cpuTimes are the aggregate jiffies from the "cpu" line of /proc/stat.
type cpuTimes struct {
	user, system, idle, iowait, steal uint64
	ok                                bool
}

// parseStat reads the aggregate CPU line and counts the per-CPU lines.
func parseStat(s string) (c cpuTimes, ncpu int) {
	for line := range strings.Lines(s) {
		f := strings.Fields(line)
		if len(f) < 9 || !strings.HasPrefix(f[0], "cpu") {
			continue
		}
		if f[0] != "cpu" {
			ncpu++
			continue
		}
		// user nice system idle iowait irq softirq steal
		var v [8]uint64
		for i := range v {
			v[i], _ = strconv.ParseUint(f[i+1], 10, 64)
		}
		c = cpuTimes{user: v[0] + v[1], system: v[2] + v[5] + v[6], idle: v[3], iowait: v[4], steal: v[7], ok: true}
	}
	return c, ncpu
}

// cpuPercent is the split of the interval's CPU time, as percentages of
// the whole machine (all cores busy = 100).
func cpuPercent(p, c cpuTimes) (model.Doc, bool) {
	if !p.ok || !c.ok {
		return nil, false
	}
	user, system := delta(p.user, c.user), delta(p.system, c.system)
	idle, iowait, steal := delta(p.idle, c.idle), delta(p.iowait, c.iowait), delta(p.steal, c.steal)
	total := float64(user + system + idle + iowait + steal)
	if total == 0 {
		return nil, false
	}
	pct := func(v uint64) float64 { return round(100*float64(v)/total, 1) }
	return model.Doc{
		"user": pct(user), "system": pct(system), "iowait": pct(iowait), "steal": pct(steal),
		"busy": pct(user + system + steal),
	}, true
}

type loadavg struct {
	l1, l5, l15 float64
	tasks       int
}

// parseLoadavg reads "0.52 0.41 0.36 2/1234 5678".
func parseLoadavg(s string) (l loadavg, ok bool) {
	f := strings.Fields(s)
	if len(f) < 4 {
		return l, false
	}
	var e1, e2, e3 error
	l.l1, e1 = strconv.ParseFloat(f[0], 64)
	l.l5, e2 = strconv.ParseFloat(f[1], 64)
	l.l15, e3 = strconv.ParseFloat(f[2], 64)
	if _, total, found := strings.Cut(f[3], "/"); found {
		l.tasks, _ = strconv.Atoi(total)
	}
	return l, e1 == nil && e2 == nil && e3 == nil
}

// parseMeminfo returns /proc/meminfo values in bytes.
func parseMeminfo(s string) map[string]uint64 {
	m := map[string]uint64{}
	for line := range strings.Lines(s) {
		k, rest, ok := strings.Cut(line, ":")
		f := strings.Fields(rest)
		if !ok || len(f) == 0 {
			continue
		}
		v, err := strconv.ParseUint(f[0], 10, 64)
		if err != nil {
			continue
		}
		if len(f) > 1 && f[1] == "kB" {
			v *= 1024
		}
		m[k] = v
	}
	return m
}

// parseVmstat returns the "name value" counters of /proc/vmstat.
func parseVmstat(s string) map[string]uint64 {
	m := map[string]uint64{}
	for line := range strings.Lines(s) {
		if f := strings.Fields(line); len(f) == 2 {
			if v, err := strconv.ParseUint(f[1], 10, 64); err == nil {
				m[f[0]] = v
			}
		}
	}
	return m
}

// parsePressure reads a /proc/pressure file and returns the cumulative
// stall time in µs per line kind:
//
//	some avg10=0.00 avg60=0.00 avg300=0.00 total=78027046
//	full avg10=0.00 avg60=0.00 avg300=0.00 total=70943913
func parsePressure(s string) map[string]uint64 {
	m := map[string]uint64{}
	for line := range strings.Lines(s) {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		for _, kv := range f[1:] {
			if v, ok := strings.CutPrefix(kv, "total="); ok {
				if n, err := strconv.ParseUint(v, 10, 64); err == nil {
					m[f[0]] = n
				}
			}
		}
	}
	return m
}

type ioBytes struct{ read, write uint64 }

// virtualDisks are block devices layered on, or unrelated to, physical
// disks; counting them would double up the IO of what is beneath.
var virtualDisks = []string{"loop", "ram", "zram", "dm-", "md", "sr", "nbd"}

// parseDiskstats sums bytes read and written over whole physical disks.
// isDisk reports whether a name is a whole disk rather than a partition.
func parseDiskstats(s string, isDisk func(string) bool) (t ioBytes) {
	for line := range strings.Lines(s) {
		// major minor name reads merged sectors ms writes merged sectors …
		f := strings.Fields(line)
		if len(f) < 10 || hasAnyPrefix(f[2], virtualDisks) || !isDisk(f[2]) {
			continue
		}
		r, _ := strconv.ParseUint(f[5], 10, 64)
		w, _ := strconv.ParseUint(f[9], 10, 64)
		t.read += r * 512 // diskstats sectors are always 512 bytes
		t.write += w * 512
	}
	return t
}

// netCounters: rx bytes, errs, drop; tx bytes, errs, drop.
type netCounters [6]uint64

// parseNetDev reads /proc/net/dev, skipping loopback and container veths.
func parseNetDev(s string) map[string]netCounters {
	m := map[string]netCounters{}
	for line := range strings.Lines(s) {
		name, rest, ok := strings.Cut(line, ":")
		f := strings.Fields(rest)
		name = strings.TrimSpace(name)
		if !ok || len(f) < 12 || name == "lo" || strings.HasPrefix(name, "veth") {
			continue
		}
		// rx: bytes packets errs drop fifo frame compressed multicast; tx: bytes packets errs drop …
		var c netCounters
		for i, idx := range []int{0, 2, 3, 8, 10, 11} {
			c[i], _ = strconv.ParseUint(f[idx], 10, 64)
		}
		m[name] = c
	}
	return m
}

type mount struct {
	major, minor          uint32
	mount, fstype, source string
}

// parseMountinfo returns one mount per real filesystem (block-device or
// zfs backed), choosing the top of the filesystem at its shortest path
// when it is mounted several times (bind mounts, btrfs subvolumes, the
// read-only remounts a hardened systemd unit sees).
//
//	36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue
func parseMountinfo(s string) []mount {
	type cand struct {
		m      mount
		isRoot bool
	}
	best := map[[2]uint32]cand{}
	var order [][2]uint32
	for line := range strings.Lines(s) {
		pre, post, ok := strings.Cut(line, " - ")
		a, b := strings.Fields(pre), strings.Fields(post)
		if !ok || len(a) < 5 || len(b) < 2 {
			continue
		}
		fstype, source := b[0], unescape(b[1])
		real := strings.HasPrefix(source, "/dev/") && !strings.HasPrefix(source, "/dev/loop") &&
			fstype != "squashfs" && fstype != "iso9660"
		if !real && fstype != "zfs" {
			continue
		}
		majS, minS, _ := strings.Cut(a[2], ":")
		maj, err1 := strconv.ParseUint(majS, 10, 32)
		mnr, err2 := strconv.ParseUint(minS, 10, 32)
		if err1 != nil || err2 != nil {
			continue
		}
		key := [2]uint32{uint32(maj), uint32(mnr)}
		c := cand{mount{key[0], key[1], unescape(a[4]), fstype, source}, a[3] == "/"}
		old, seen := best[key]
		if !seen {
			order = append(order, key)
		}
		if !seen || (c.isRoot && !old.isRoot) || (c.isRoot == old.isRoot && len(c.m.mount) < len(old.m.mount)) {
			best[key] = c
		}
	}
	out := make([]mount, 0, len(order))
	for _, k := range order {
		out = append(out, best[k].m)
	}
	return out
}

// unescape decodes the octal escapes (\040 for space) of mount tables.
func unescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// unitCounters are one cgroup's readings.
type unitCounters struct {
	cpuUsec, mem, memPeak, ioRead, ioWrite uint64
	tasks                                  int64
}

// readUnits walks the cgroup v2 tree and reads every systemd service and
// scope. Slices are descended into, except per-user slices, which are
// reported whole (user-1000.slice) rather than per session. On a cgroup
// v1 host nothing matches and the result is empty.
func readUnits(root string) map[string]unitCounters {
	units := map[string]unitCounters{}
	var walk func(dir string, depth int)
	walk = func(dir string, depth int) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			name := e.Name()
			if !e.IsDir() {
				continue
			}
			path := filepath.Join(dir, name)
			switch {
			case strings.HasSuffix(name, ".slice") && !strings.HasPrefix(name, "user-"):
				if depth < 8 {
					walk(path, depth+1)
				}
			case strings.HasSuffix(name, ".service"), strings.HasSuffix(name, ".scope"), strings.HasSuffix(name, ".slice"):
				if c, ok := readCgroup(path); ok {
					units[name] = c
				}
			}
		}
	}
	walk(root, 0)
	return units
}

func readCgroup(dir string) (c unitCounters, ok bool) {
	stat := readFile(dir, "cpu.stat")
	if stat == "" {
		return c, false
	}
	for line := range strings.Lines(stat) {
		if v, found := strings.CutPrefix(line, "usage_usec "); found {
			c.cpuUsec = atou(v)
		}
	}
	c.mem = atou(readFile(dir, "memory.current"))
	c.memPeak = atou(readFile(dir, "memory.peak"))
	c.tasks = int64(atou(readFile(dir, "pids.current")))
	// one line per device: "8:0 rbytes=606208 wbytes=0 rios=116 …"
	for line := range strings.Lines(readFile(dir, "io.stat")) {
		for _, kv := range strings.Fields(line) {
			if v, found := strings.CutPrefix(kv, "rbytes="); found {
				c.ioRead += atou(v)
			} else if v, found := strings.CutPrefix(kv, "wbytes="); found {
				c.ioWrite += atou(v)
			}
		}
	}
	return c, true
}

func atou(s string) uint64 {
	n, _ := strconv.ParseUint(strings.TrimSpace(s), 10, 64)
	return n
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}
