package flows

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/mdlayher/netlink"
	"github.com/ti-mo/conntrack"
	"github.com/ti-mo/netfilter"
	"golang.org/x/sys/unix"

	"mongo-journald/internal/model"
)

// Filter drops flows before they are shipped.
type Filter struct {
	IncludeLoopback bool
	IgnoreNets      []netip.Prefix // drop when either endpoint is inside
	IgnorePorts     map[uint16]bool
}

// Drop reports whether a flow should be skipped.
func (f Filter) Drop(i Info) bool {
	s, d := i.Orig.Src.Addr.Unmap(), i.Orig.Dst.Addr.Unmap()
	if !f.IncludeLoopback && (s.IsLoopback() || d.IsLoopback()) {
		return true
	}
	for _, n := range f.IgnoreNets {
		if n.Contains(s) || n.Contains(d) {
			return true
		}
	}
	if hasPorts(i.Proto) && (f.IgnorePorts[i.Orig.Dst.Port] || f.IgnorePorts[i.Reply.Src.Port]) {
		return true
	}
	return false
}

// Options configure the conntrack reader.
type Options struct {
	Hostname  string
	Retention time.Duration
	Filter    Filter
	Proc      bool // attribute flows to processes
	Attrib    AttribConfig
	Notify    func(string, ...any)
}

// Reader subscribes to conntrack NEW/DESTROY events and emits one doc per
// destroyed (finished) flow.
type Reader struct {
	opt    Options
	attr   *Attributor
	locals *localAddrs
}

// NewReader builds a Reader backed by the kernel's conntrack netlink
// groups (needs CAP_NET_ADMIN).
func NewReader(opt Options) *Reader {
	var procs ProcSource
	if opt.Proc {
		procs = ProcFS{Root: "/proc"}
	}
	return &Reader{opt: opt, attr: NewAttributor(NetlinkSockets{}, procs, opt.Attrib), locals: &localAddrs{}}
}

func (r *Reader) notify(f string, a ...any) {
	if r.opt.Notify != nil {
		r.opt.Notify(f, a...)
	}
}

// Run streams records to out until ctx is cancelled, re-subscribing with
// backoff if the netlink socket fails.
func (r *Reader) Run(ctx context.Context, out chan<- model.Record) error {
	r.locals.refresh()
	r.checkSysctls()
	var wg sync.WaitGroup
	defer wg.Wait()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel() // runs before wg.Wait: stops the helpers on any return
	wg.Add(2)
	go func() { defer wg.Done(); r.attr.Run(ctx) }()
	go func() { defer wg.Done(); r.background(ctx) }()

	backoff := time.Second
	for {
		started := time.Now()
		err := r.listen(ctx, out)
		if ctx.Err() != nil {
			return nil
		}
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			return fmt.Errorf("%w (conntrack events need CAP_NET_ADMIN)", err)
		}
		if time.Since(started) > time.Minute {
			backoff = time.Second
		}
		r.notify("conntrack listener stopped (%v); restarting in %s", err, backoff)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > 30*time.Second {
			backoff = 30 * time.Second
		}
	}
}

// checkSysctls warns when the kernel will not report byte counters or
// timestamps (mongo-journald-flows.service enables both in ExecStartPre).
func (r *Reader) checkSysctls() {
	for _, k := range []string{"nf_conntrack_acct", "nf_conntrack_timestamp"} {
		b, err := os.ReadFile("/proc/sys/net/netfilter/" + k)
		if err != nil {
			r.notify("cannot read net.netfilter.%s (is nf_conntrack loaded?): %v", k, err)
			continue
		}
		if strings.TrimSpace(string(b)) != "1" {
			r.notify("net.netfilter.%s=0: flows will lack %s; set it to 1 (mongo-journald-flows.service sets it at start)",
				k, map[string]string{"nf_conntrack_acct": "byte/packet counts", "nf_conntrack_timestamp": "kernel start/stop times"}[k])
		}
	}
}

// background refreshes the local address set and logs attribution stats.
func (r *Reader) background(ctx context.Context) {
	addrs := time.NewTicker(30 * time.Second)
	defer addrs.Stop()
	stats := time.NewTicker(10 * time.Minute)
	defer stats.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-addrs.C:
			r.locals.refresh()
		case <-stats.C:
			if n, p := r.attr.Stats(); n > 0 {
				r.notify("flows: %d local flows in the last 10m, %d (%.0f%%) attributed to a process", n, p, 100*float64(p)/float64(n))
			}
		}
	}
}

func (r *Reader) listen(ctx context.Context, out chan<- model.Record) error {
	c, err := conntrack.Dial(nil)
	if err != nil {
		return fmt.Errorf("dial conntrack: %w", err)
	}
	defer c.Close()
	_ = c.SetReadBuffer(8 << 20)
	// Don't tear the socket down when the kernel drops events under load;
	// those flows are simply missed.
	_ = c.SetOption(netlink.NoENOBUFS, true)

	evs := make(chan conntrack.Event, 4096)
	// One worker: keeps a flow's NEW before its DESTROY, and on error the
	// worker exits after its single send on errc (more would leak, blocked
	// on the unbuffered channel once we stop reading it).
	errc, err := c.Listen(evs, 1, []netfilter.NetlinkGroup{netfilter.GroupCTNew, netfilter.GroupCTDestroy})
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-errc:
			return err
		case ev := <-evs:
			if ev.Flow == nil {
				continue
			}
			switch ev.Type {
			case conntrack.EventNew:
				r.onNew(FromConntrack(*ev.Flow), time.Now())
			case conntrack.EventDestroy:
				r.onDestroy(ctx, FromConntrack(*ev.Flow), time.Now(), out)
			}
		}
	}
}

func (r *Reader) onNew(f Info, now time.Time) {
	if r.opt.Filter.Drop(f) {
		return
	}
	dir, local, remote := Classify(f, r.locals.has)
	r.attr.New(f.ID, f.Proto, dir, local, remote, now)
}

func (r *Reader) onDestroy(ctx context.Context, f Info, now time.Time, out chan<- model.Record) {
	if r.opt.Filter.Drop(f) {
		return
	}
	dir, _, _ := Classify(f, r.locals.has)
	proc, seen := r.attr.Take(f.ID)
	doc := Build(f, dir, proc, r.opt.Hostname, now, seen, r.opt.Retention)
	select {
	case out <- model.Record{Doc: doc}:
	case <-ctx.Done():
	}
}

// FromConntrack converts a library flow to Info.
func FromConntrack(f conntrack.Flow) Info {
	i := Info{
		ID:    f.ID,
		Proto: f.TupleOrig.Proto.Protocol,
		Orig: Tuple{
			Src: Endpoint{f.TupleOrig.IP.SourceAddress.Unmap(), f.TupleOrig.Proto.SourcePort},
			Dst: Endpoint{f.TupleOrig.IP.DestinationAddress.Unmap(), f.TupleOrig.Proto.DestinationPort},
		},
		Reply: Tuple{
			Src: Endpoint{f.TupleReply.IP.SourceAddress.Unmap(), f.TupleReply.Proto.SourcePort},
			Dst: Endpoint{f.TupleReply.IP.DestinationAddress.Unmap(), f.TupleReply.Proto.DestinationPort},
		},
		OrigBytes:  f.CountersOrig.Bytes,
		OrigPkts:   f.CountersOrig.Packets,
		ReplyBytes: f.CountersReply.Bytes,
		ReplyPkts:  f.CountersReply.Packets,
		Start:      f.Timestamp.Start,
		Stop:       f.Timestamp.Stop,
		TCPState:   -1,
		SeenReply:  f.Status.SeenReply(),
		ICMPType:   -1,
	}
	if f.ProtoInfo.TCP != nil {
		i.TCPState = int(f.ProtoInfo.TCP.State)
	}
	if p := f.TupleOrig.Proto; p.ICMPv4 || p.ICMPv6 {
		i.ICMPType, i.ICMPCode = int(p.ICMPType), int(p.ICMPCode)
	}
	return i
}

// localAddrs is the set of this host's addresses, refreshed periodically.
type localAddrs struct {
	mu  sync.RWMutex
	set map[netip.Addr]bool
}

func (l *localAddrs) refresh() {
	as, err := net.InterfaceAddrs()
	if err != nil {
		return
	}
	set := map[netip.Addr]bool{}
	for _, a := range as {
		if n, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(n.IP); ok {
				set[ip.Unmap()] = true
			}
		}
	}
	l.mu.Lock()
	l.set = set
	l.mu.Unlock()
}

func (l *localAddrs) has(a netip.Addr) bool {
	a = a.Unmap()
	if a.IsLoopback() {
		return true
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.set[a]
}
