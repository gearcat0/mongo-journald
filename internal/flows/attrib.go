package flows

import (
	"context"
	"net/netip"
	"sync"
	"time"
)

// Sock is one socket from a sock_diag dump.
type Sock struct {
	Local, Remote Endpoint
	Inode         uint64
	UID           int
}

// SocketSource dumps the host's sockets for a protocol (6 tcp, 17 udp).
type SocketSource interface {
	Dump(proto uint8) ([]Sock, error)
}

// ProcSource maps socket inodes to owning processes.
type ProcSource interface {
	// Scan returns socket inode → pid for every process.
	Scan() (map[uint64]int, error)
	// Info reads a process's comm, exe and systemd unit.
	Info(pid int) (*Proc, bool)
}

// AttribConfig tunes the Attributor.
type AttribConfig struct {
	Round   time.Duration // how often pending flows are resolved; default 100ms
	MinScan time.Duration // minimum gap between /proc scans; default 500ms
	MaxWait time.Duration // give up on a flow after this long; default 2s
	MaxAge  time.Duration // forget flows never destroyed after this; default 6d
}

// Attributor resolves NEW flows to their owning local process, so the
// DESTROY event (when the socket is usually gone) can be attributed.
//
// Each round it dumps sockets via sock_diag, matches each pending flow's
// local/remote endpoints to a socket inode, and maps the inode to a pid
// from a cache built by scanning /proc/*/fd (rescanned on a cache miss,
// rate-limited). It is best effort: a socket that closes before the next
// round, forwarded traffic and ICMP get no process.
type Attributor struct {
	socks SocketSource
	procs ProcSource
	cfg   AttribConfig

	mu       sync.Mutex
	pending  map[uint32]*pend
	resolved map[uint32]*result

	inodePID map[uint64]int
	lastScan time.Time

	statMu                 sync.Mutex
	statFlows, statWithPID int
}

type pend struct {
	proto         uint8
	dir           string
	local, remote Endpoint
	seen          time.Time
}

type result struct {
	proc         *Proc
	seen         time.Time
	attributable bool // a local tcp/udp flow (counts toward Stats)
}

// NewAttributor builds an Attributor; call Run to start resolving.
func NewAttributor(socks SocketSource, procs ProcSource, cfg AttribConfig) *Attributor {
	if cfg.Round <= 0 {
		cfg.Round = 100 * time.Millisecond
	}
	if cfg.MinScan <= 0 {
		cfg.MinScan = 500 * time.Millisecond
	}
	if cfg.MaxWait <= 0 {
		cfg.MaxWait = 2 * time.Second
	}
	if cfg.MaxAge <= 0 {
		cfg.MaxAge = 6 * 24 * time.Hour
	}
	return &Attributor{socks: socks, procs: procs, cfg: cfg,
		pending: map[uint32]*pend{}, resolved: map[uint32]*result{}, inodePID: map[uint64]int{}}
}

// New registers a NEW flow. Flows that are not local (fwd) or have no
// ports are only timestamped.
func (a *Attributor) New(id uint32, proto uint8, dir string, local, remote Endpoint, seen time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if dir == DirFwd || (proto != 6 && proto != 17) || a.procs == nil {
		a.resolved[id] = &result{seen: seen}
		return
	}
	a.pending[id] = &pend{proto: proto, dir: dir, local: local, remote: remote, seen: seen}
}

// Take returns and forgets what is known about a flow: its process (nil
// if unknown) and when its NEW event was seen (zero if never).
func (a *Attributor) Take(id uint32) (*Proc, time.Time) {
	a.mu.Lock()
	var proc *Proc
	var seen time.Time
	counted := false
	if r, ok := a.resolved[id]; ok {
		delete(a.resolved, id)
		proc, seen, counted = r.proc, r.seen, r.attributable
	} else if p, ok := a.pending[id]; ok {
		delete(a.pending, id)
		seen, counted = p.seen, true
	}
	a.mu.Unlock()
	if counted {
		a.statMu.Lock()
		a.statFlows++
		if proc != nil {
			a.statWithPID++
		}
		a.statMu.Unlock()
	}
	return proc, seen
}

// Stats returns and resets the counts of taken flows and of those with a
// process attached.
func (a *Attributor) Stats() (flows, withProc int) {
	a.statMu.Lock()
	defer a.statMu.Unlock()
	flows, withProc = a.statFlows, a.statWithPID
	a.statFlows, a.statWithPID = 0, 0
	return
}

// Run resolves pending flows every Round until ctx is done.
func (a *Attributor) Run(ctx context.Context) {
	t := time.NewTicker(a.cfg.Round)
	defer t.Stop()
	prune := time.NewTicker(time.Hour)
	defer prune.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			a.Round(now)
		case now := <-prune.C:
			a.prune(now)
		}
	}
}

// Round does one resolution pass (exported for tests).
func (a *Attributor) Round(now time.Time) {
	a.mu.Lock()
	if len(a.pending) == 0 {
		a.mu.Unlock()
		return
	}
	work := make(map[uint32]pend, len(a.pending))
	protos := map[uint8]bool{}
	for id, p := range a.pending {
		work[id] = *p
		protos[p.proto] = true
	}
	a.mu.Unlock()

	idx := newSockIndex()
	for proto := range protos {
		socks, err := a.socks.Dump(proto)
		if err != nil && len(socks) == 0 {
			continue
		}
		idx.add(proto, socks)
	}

	type hit struct {
		inode uint64
		uid   int
	}
	hits := map[uint32]hit{}
	needScan := false
	for id, p := range work {
		s, ok := idx.match(p.proto, p.local, p.remote)
		if !ok {
			continue
		}
		hits[id] = hit{s.Inode, s.UID}
		if _, known := a.inodePID[s.Inode]; !known {
			needScan = true
		}
	}
	if needScan && now.Sub(a.lastScan) >= a.cfg.MinScan {
		if m, err := a.procs.Scan(); err == nil {
			a.inodePID = m
			a.lastScan = now
		}
	}

	infos := map[int]*Proc{}
	done := map[uint32]*Proc{}
	for id, p := range work {
		h, ok := hits[id]
		if ok {
			if pid, ok := a.inodePID[h.inode]; ok {
				info, seen := infos[pid]
				if !seen {
					info, _ = a.procs.Info(pid)
					infos[pid] = info
				}
				if info != nil {
					c := *info
					c.UID = h.uid
					done[id] = &c
					continue
				}
			}
		}
		if now.Sub(p.seen) >= a.cfg.MaxWait {
			done[id] = nil // give up
		}
	}

	a.mu.Lock()
	for id, proc := range done {
		p, still := a.pending[id]
		if !still {
			continue // destroyed meanwhile
		}
		delete(a.pending, id)
		a.resolved[id] = &result{proc: proc, seen: p.seen, attributable: true}
	}
	a.mu.Unlock()
}

func (a *Attributor) prune(now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for id, r := range a.resolved {
		if now.Sub(r.seen) > a.cfg.MaxAge {
			delete(a.resolved, id)
		}
	}
	for id, p := range a.pending {
		if now.Sub(p.seen) > a.cfg.MaxAge {
			delete(a.pending, id)
		}
	}
}

// sockIndex finds the socket for a flow: first an exact 4-tuple match
// (connected sockets), then a socket bound to the local port with no
// remote (listeners, unconnected UDP).
type sockIndex struct {
	exact map[sockKey]Sock
	bound map[boundKey][]Sock
}

type sockKey struct {
	proto         uint8
	local, remote Endpoint
}

type boundKey struct {
	proto uint8
	port  uint16
}

func newSockIndex() *sockIndex {
	return &sockIndex{exact: map[sockKey]Sock{}, bound: map[boundKey][]Sock{}}
}

func (x *sockIndex) add(proto uint8, socks []Sock) {
	for _, s := range socks {
		s.Local.Addr = s.Local.Addr.Unmap()
		s.Remote.Addr = s.Remote.Addr.Unmap()
		if s.Inode == 0 {
			continue // not yet accepted / orphaned (TIME_WAIT etc.)
		}
		if s.Remote.Port == 0 && (!s.Remote.Addr.IsValid() || s.Remote.Addr.IsUnspecified()) {
			k := boundKey{proto, s.Local.Port}
			x.bound[k] = append(x.bound[k], s)
			continue
		}
		x.exact[sockKey{proto, s.Local, s.Remote}] = s
	}
}

func (x *sockIndex) match(proto uint8, local, remote Endpoint) (Sock, bool) {
	local.Addr, remote.Addr = local.Addr.Unmap(), remote.Addr.Unmap()
	if s, ok := x.exact[sockKey{proto, local, remote}]; ok {
		return s, true
	}
	var wildcard *Sock
	for i, s := range x.bound[boundKey{proto, local.Port}] {
		if s.Local.Addr == local.Addr {
			return s, true
		}
		if wildcard == nil && (!s.Local.Addr.IsValid() || s.Local.Addr.IsUnspecified()) && sameFamilyOrDual(s.Local.Addr, local.Addr) {
			wildcard = &x.bound[boundKey{proto, local.Port}][i]
		}
	}
	if wildcard != nil {
		return *wildcard, true
	}
	return Sock{}, false
}

// sameFamilyOrDual: a [::] socket also accepts IPv4 (dual-stack).
func sameFamilyOrDual(sock, flow netip.Addr) bool {
	if !sock.IsValid() {
		return true
	}
	return sock.Is6() || sock.Is4() == flow.Is4()
}
