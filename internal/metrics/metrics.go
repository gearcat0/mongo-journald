// Package metrics samples the host's workload: a whole-host document
// (CPU, memory, pressure, disks, network) and one per busy systemd unit
// (CPU, memory, IO from its cgroup). Everything is read from /proc, /sys
// and statfs, none of which needs privileges.
//
// Counters (CPU time, bytes, stall time) are reported as the change since
// the previous sample, so each document describes one interval.
package metrics

import (
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"golang.org/x/sys/unix"

	"mongo-journald/internal/model"
)

// Indexes are the lookup indexes for the two raw collections.
var (
	HostIndexes = []bson.D{
		{{Key: "server", Value: 1}, {Key: "at", Value: -1}},
	}
	UnitIndexes = []bson.D{
		{{Key: "server", Value: 1}, {Key: "unit", Value: 1}, {Key: "at", Value: -1}},
		{{Key: "unit", Value: 1}, {Key: "at", Value: -1}},
	}
)

// UnitRollupFields are the key fields of the hourly per-unit rollup.
var UnitRollupFields = []string{"unit"}

// Options configures a Sampler.
type Options struct {
	Hostname      string
	Retention     time.Duration // host documents; 0 = forever
	UnitRetention time.Duration // raw unit documents; 0 = forever
	Units         bool          // sample per-unit cgroups

	// A unit's raw document is written only for an interval in which it
	// used at least MinCPUPct of one core or held at least MinMem bytes.
	// The hourly rollup covers every unit regardless.
	MinCPUPct float64
	MinMem    uint64

	// Roots, overridden by tests. Defaults: /proc, /sys/fs/cgroup, /sys/block.
	Proc, Cgroup, SysBlock string
}

// Sampler turns successive readings into interval documents.
type Sampler struct {
	opt  Options
	prev *snapshot
}

func NewSampler(opt Options) *Sampler {
	if opt.Proc == "" {
		opt.Proc = "/proc"
	}
	if opt.Cgroup == "" {
		opt.Cgroup = "/sys/fs/cgroup"
	}
	if opt.SysBlock == "" {
		opt.SysBlock = "/sys/block"
	}
	return &Sampler{opt: opt}
}

// snapshot holds the cumulative counters of one reading.
type snapshot struct {
	at    time.Time
	cpu   cpuTimes
	oom   uint64
	psi   map[string]uint64 // e.g. "io_full" → total stalled µs
	disk  ioBytes
	net   map[string]netCounters
	units map[string]unitCounters
}

// UnitSample is one unit's usage over one interval.
type UnitSample struct {
	Unit    string
	CPUUsec uint64  // CPU time used in the interval
	CPUPct  float64 // … as a percentage of one core (200 = two cores busy)
	Mem     uint64  // memory.current at the end of the interval
	MemPeak uint64  // memory.peak (since the unit started); 0 if the kernel has none
	IORead  uint64  // bytes in the interval
	IOWrite uint64
	Tasks   int64
}

// Busy reports whether the sample clears the raw-document thresholds.
func (s *Sampler) Busy(u UnitSample) bool {
	return u.CPUPct >= s.opt.MinCPUPct || u.Mem >= s.opt.MinMem
}

// Doc is the raw document for a unit sample taken at time at.
func (s *Sampler) Doc(u UnitSample, at time.Time) model.Doc {
	d := model.Doc{
		"at":             at,
		"server":         s.opt.Hostname,
		"unit":           u.Unit,
		"cpu_pct":        u.CPUPct,
		"cpu_usec":       int64(u.CPUUsec),
		"mem":            int64(u.Mem),
		"io_read_bytes":  int64(u.IORead),
		"io_write_bytes": int64(u.IOWrite),
		"tasks":          u.Tasks,
	}
	if u.MemPeak > 0 {
		d["mem_peak"] = int64(u.MemPeak)
	}
	if s.opt.UnitRetention > 0 {
		d["expireAt"] = at.Add(s.opt.UnitRetention)
	}
	return d
}

// Rollup gives the hourly-rollup increments and high-water marks for a
// unit sample. Average memory over the hour is mem_sum / n.
func Rollup(u UnitSample) (key []any, inc, max map[string]int64) {
	return []any{u.Unit},
		map[string]int64{
			"n":              1,
			"cpu_usec":       int64(u.CPUUsec),
			"mem_sum":        int64(u.Mem),
			"io_read_bytes":  int64(u.IORead),
			"io_write_bytes": int64(u.IOWrite),
		},
		map[string]int64{"mem_max": int64(u.Mem)}
}

// Sample reads the host now and returns the documents for the interval
// since the previous call. The first call only records a baseline and
// returns nothing.
func (s *Sampler) Sample(now time.Time) (host model.Doc, units []UnitSample) {
	now = now.UTC().Truncate(time.Millisecond)
	cur := &snapshot{at: now}
	proc := s.opt.Proc

	ncpu := 0
	cur.cpu, ncpu = parseStat(readFile(proc, "stat"))
	cur.oom = parseVmstat(readFile(proc, "vmstat"))["oom_kill"]
	cur.psi = map[string]uint64{}
	for _, res := range []string{"cpu", "memory", "io"} {
		short := strings.TrimSuffix(res, "ory") // cpu, mem, io
		for kind, total := range parsePressure(readFile(proc, "pressure", res)) {
			if res == "cpu" && kind == "full" {
				continue // not meaningful system-wide
			}
			cur.psi[short+"_"+kind] = total
		}
	}
	cur.disk = parseDiskstats(readFile(proc, "diskstats"), func(name string) bool {
		_, err := os.Stat(filepath.Join(s.opt.SysBlock, name))
		return err == nil
	})
	cur.net = parseNetDev(readFile(proc, "net", "dev"))
	if s.opt.Units {
		cur.units = readUnits(s.opt.Cgroup)
	}

	prev := s.prev
	s.prev = cur
	if prev == nil {
		return nil, nil
	}
	dt := now.Sub(prev.at)
	if dt <= 0 {
		return nil, nil
	}
	dtUsec := float64(dt.Microseconds())

	host = model.Doc{"at": now, "server": s.opt.Hostname, "dt_s": round(dt.Seconds(), 1)}
	if s.opt.Retention > 0 {
		host["expireAt"] = now.Add(s.opt.Retention)
	}

	if l, ok := parseLoadavg(readFile(proc, "loadavg")); ok {
		host["load1"], host["load5"], host["load15"], host["tasks"] = l.l1, l.l5, l.l15, l.tasks
	}
	if ncpu > 0 {
		host["ncpu"] = ncpu
	}
	if c, ok := cpuPercent(prev.cpu, cur.cpu); ok {
		host["cpu"] = c
	}

	if m := parseMeminfo(readFile(proc, "meminfo")); m["MemTotal"] > 0 {
		host["mem"] = model.Doc{
			"total":      int64(m["MemTotal"]),
			"available":  int64(m["MemAvailable"]),
			"used_pct":   round(100*(1-float64(m["MemAvailable"])/float64(m["MemTotal"])), 1),
			"swap_total": int64(m["SwapTotal"]),
			"swap_used":  int64(m["SwapTotal"] - min(m["SwapFree"], m["SwapTotal"])),
		}
	}
	host["oom_kills"] = int64(delta(prev.oom, cur.oom))

	if len(cur.psi) > 0 {
		psi := model.Doc{}
		for k, total := range cur.psi {
			if p, ok := prev.psi[k]; ok {
				// share of the interval in which tasks were stalled
				psi[k] = round(math.Min(100, 100*float64(delta(p, total))/dtUsec), 2)
			}
		}
		if len(psi) > 0 {
			host["psi"] = psi
		}
	}

	if disks := readDisks(readFile(proc, "self", "mountinfo")); len(disks) > 0 {
		host["disks"] = disks
	}
	host["io"] = model.Doc{
		"read_bytes":  int64(delta(prev.disk.read, cur.disk.read)),
		"write_bytes": int64(delta(prev.disk.write, cur.disk.write)),
	}

	var nets []model.Doc
	for _, name := range slices.Sorted(mapKeys(cur.net)) {
		p, ok := prev.net[name]
		if !ok {
			continue
		}
		c := cur.net[name]
		d := [6]uint64{}
		any := false
		for i := range d {
			d[i] = delta(p[i], c[i])
			any = any || d[i] > 0
		}
		if !any {
			continue // idle interface
		}
		nets = append(nets, model.Doc{"if": name,
			"rx_bytes": int64(d[0]), "rx_errs": int64(d[1]), "rx_drop": int64(d[2]),
			"tx_bytes": int64(d[3]), "tx_errs": int64(d[4]), "tx_drop": int64(d[5])})
	}
	if len(nets) > 0 {
		host["net"] = nets
	}

	for _, name := range slices.Sorted(mapKeys(cur.units)) {
		c := cur.units[name]
		// A unit that is new, or whose counters went backwards (it was
		// restarted and got a fresh cgroup), did all its work inside
		// this interval.
		p, ok := prev.units[name]
		if !ok || c.cpuUsec < p.cpuUsec {
			p = unitCounters{}
		}
		u := UnitSample{
			Unit:    name,
			CPUUsec: c.cpuUsec - p.cpuUsec,
			Mem:     c.mem,
			MemPeak: c.memPeak,
			IORead:  delta(p.ioRead, c.ioRead),
			IOWrite: delta(p.ioWrite, c.ioWrite),
			Tasks:   c.tasks,
		}
		u.CPUPct = round(100*float64(u.CPUUsec)/dtUsec, 1)
		units = append(units, u)
	}
	return host, units
}

// readDisks reports space and inodes for each real filesystem.
func readDisks(mountinfo string) []model.Doc {
	var out []model.Doc
	for _, m := range parseMountinfo(mountinfo) {
		// Skip a mount that something else is mounted over (systemd's
		// ProtectHome= hides /home this way): statfs would describe the
		// wrong filesystem.
		var st unix.Stat_t
		if unix.Stat(m.mount, &st) != nil || unix.Major(st.Dev) != m.major || unix.Minor(st.Dev) != m.minor {
			continue
		}
		var fs unix.Statfs_t
		if unix.Statfs(m.mount, &fs) != nil || fs.Blocks == 0 {
			continue
		}
		bs := uint64(fs.Bsize)
		used := (fs.Blocks - fs.Bfree) * bs
		avail := fs.Bavail * bs
		d := model.Doc{
			"mount": m.mount, "dev": m.source, "fs": m.fstype,
			"total": int64(fs.Blocks * bs), "used": int64(used), "avail": int64(avail),
		}
		if used+avail > 0 {
			// like df: the share of the space an unprivileged user can use
			d["used_pct"] = round(100*float64(used)/float64(used+avail), 1)
		}
		if fs.Files > 0 {
			d["inodes_used_pct"] = round(100*float64(fs.Files-fs.Ffree)/float64(fs.Files), 1)
		}
		out = append(out, d)
	}
	return out
}

func readFile(parts ...string) string {
	b, err := os.ReadFile(filepath.Join(parts...))
	if err != nil {
		return ""
	}
	return string(b)
}

// delta is cur - prev for a counter, or 0 if it went backwards (reset).
func delta(prev, cur uint64) uint64 {
	if cur < prev {
		return 0
	}
	return cur - prev
}

func round(v float64, places int) float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0
	}
	p := math.Pow(10, float64(places))
	return math.Round(v*p) / p
}

func mapKeys[V any](m map[string]V) func(func(string) bool) {
	return func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}
