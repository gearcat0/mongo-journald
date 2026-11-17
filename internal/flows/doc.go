// Package flows ships one document per finished network connection,
// built from Linux conntrack DESTROY events, with best-effort attribution
// of the owning local process.
package flows

import (
	"net/netip"
	"strconv"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"mongo-journald/internal/model"
)

// Endpoint is one side of a tuple.
type Endpoint struct {
	Addr netip.Addr
	Port uint16
}

// Tuple is a conntrack tuple (initiator → responder for the original
// direction).
type Tuple struct {
	Src, Dst Endpoint
}

// Info is the subset of a conntrack flow this package needs. It is
// decoupled from the netlink library so mapping can be unit-tested.
type Info struct {
	ID          uint32
	Proto       uint8
	Orig, Reply Tuple
	OrigBytes   uint64
	OrigPkts    uint64
	ReplyBytes  uint64
	ReplyPkts   uint64
	Start, Stop time.Time // zero unless nf_conntrack_timestamp=1
	TCPState    int       // -1 when not TCP
	SeenReply   bool
	ICMPType    int // -1 when not ICMP
	ICMPCode    int
}

// Proc is the local process that owns the flow's socket.
type Proc struct {
	PID  int
	Comm string
	Exe  string
	UID  int
	Unit string
}

// Direction relative to this host.
const (
	DirOut = "out" // this host initiated
	DirIn  = "in"  // a peer initiated, to a local socket
	DirFwd = "fwd" // routed/NATed through (containers, forwarding)
)

// Indexes are the lookup indexes for the raw flows collection.
var Indexes = []bson.D{
	{{Key: "server", Value: 1}, {Key: "at", Value: -1}},
	{{Key: "peer", Value: 1}, {Key: "at", Value: -1}},
	{{Key: "proc.comm", Value: 1}, {Key: "at", Value: -1}},
}

// RollupFields are the key fields of the flows_hourly collection.
var RollupFields = []string{"dir", "proto", "peer", "port", "comm", "unit"}

// RollupKey returns the hourly rollup key and counters for a flow doc.
func RollupKey(doc model.Doc) ([]any, map[string]int64) {
	var comm, unit any
	if p, ok := doc["proc"].(model.Doc); ok {
		comm, unit = p["comm"], p["unit"]
	}
	return []any{doc["dir"], doc["proto"], doc["peer"], doc["port"], comm, unit}, map[string]int64{
		"flows":    1,
		"tx_bytes": doc["tx_bytes"].(int64),
		"rx_bytes": doc["rx_bytes"].(int64),
	}
}

// Classify works out the flow's direction and, for flows that terminate
// on this host, the local and remote endpoints as the local socket sees
// them. A locally initiated socket sees the original tuple; a socket that
// accepted an inbound flow sees the reply tuple (post-DNAT).
func Classify(f Info, isLocal func(netip.Addr) bool) (dir string, local, remote Endpoint) {
	switch {
	case isLocal(f.Orig.Src.Addr):
		return DirOut, f.Orig.Src, f.Orig.Dst
	case isLocal(f.Reply.Src.Addr):
		return DirIn, f.Reply.Src, f.Reply.Dst
	default:
		return DirFwd, Endpoint{}, Endpoint{}
	}
}

// Build maps a finished flow to a document. tx/rx are from this host's
// point of view (for fwd flows, tx is initiator → responder). now is used
// when the kernel gave no stop time; seen is when the NEW event was seen
// (fallback start time), zero if unknown.
func Build(f Info, dir string, proc *Proc, server string, now, seen time.Time, retention time.Duration) model.Doc {
	at := f.Stop
	if at.IsZero() {
		at = now
	}
	start := f.Start
	if start.IsZero() {
		start = seen
	}
	at = at.UTC()

	tx, rx, txp, rxp := f.OrigBytes, f.ReplyBytes, f.OrigPkts, f.ReplyPkts
	if dir == DirIn {
		tx, rx, txp, rxp = rx, tx, rxp, txp
	}

	peer := f.Orig.Dst.Addr
	if dir == DirIn {
		peer = f.Orig.Src.Addr
	}

	doc := model.Doc{
		"at":       at,
		"server":   server,
		"dir":      dir,
		"proto":    ProtoName(f.Proto),
		"src":      f.Orig.Src.Addr.Unmap().String(),
		"dst":      f.Orig.Dst.Addr.Unmap().String(),
		"peer":     peer.Unmap().String(),
		"tx_bytes": int64(tx),
		"rx_bytes": int64(rx),
		"tx_pkts":  int64(txp),
		"rx_pkts":  int64(rxp),
		"replied":  f.SeenReply,
	}
	if hasPorts(f.Proto) {
		doc["sport"] = int(f.Orig.Src.Port)
		doc["dport"] = int(f.Orig.Dst.Port)
		doc["port"] = int(f.Orig.Dst.Port) // the service port, whichever side is local
	} else {
		doc["port"] = nil
	}
	if f.ICMPType >= 0 {
		doc["icmp_type"] = f.ICMPType
		doc["icmp_code"] = f.ICMPCode
	}
	if !start.IsZero() {
		start = start.UTC()
		doc["start"] = start
		doc["dur_ms"] = at.Sub(start).Milliseconds()
	}
	if f.TCPState >= 0 {
		doc["tcp_state"] = TCPStateName(f.TCPState)
	}
	if natted(f) {
		doc["nat"] = true
	}
	if proc != nil {
		p := model.Doc{"pid": proc.PID, "comm": proc.Comm, "uid": proc.UID}
		if proc.Exe != "" {
			p["exe"] = proc.Exe
		}
		if proc.Unit != "" {
			p["unit"] = proc.Unit
		}
		doc["proc"] = p
	}
	if retention > 0 {
		doc["expireAt"] = at.Add(retention)
	}
	return doc
}

// natted reports whether the reply tuple is not the mirror of the
// original (SNAT/DNAT/masquerade happened).
func natted(f Info) bool {
	return f.Reply.Src != f.Orig.Dst || f.Reply.Dst != f.Orig.Src
}

func hasPorts(p uint8) bool { return p == 6 || p == 17 || p == 132 || p == 33 || p == 136 }

// ProtoName names common IP protocols.
func ProtoName(p uint8) string {
	switch p {
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 58:
		return "icmpv6"
	case 132:
		return "sctp"
	case 136:
		return "udplite"
	case 47:
		return "gre"
	case 50:
		return "esp"
	}
	return strconv.Itoa(int(p))
}

var tcpStates = [...]string{"NONE", "SYN_SENT", "SYN_RECV", "ESTABLISHED", "FIN_WAIT", "CLOSE_WAIT",
	"LAST_ACK", "TIME_WAIT", "CLOSE", "SYN_SENT2"}

// TCPStateName names a conntrack TCP state.
func TCPStateName(s int) string {
	if s >= 0 && s < len(tcpStates) {
		return tcpStates[s]
	}
	return "STATE" + strconv.Itoa(s)
}
