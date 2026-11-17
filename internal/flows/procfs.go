package flows

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// ProcFS reads process ownership from a /proc tree. Root is "/proc" in
// production and a fake tree in tests. Reading other users' fd tables
// needs CAP_SYS_PTRACE (and CAP_DAC_READ_SEARCH).
type ProcFS struct{ Root string }

// Scan walks /proc/<pid>/fd and maps every socket inode to its pid.
func (p ProcFS) Scan() (map[uint64]int, error) {
	ents, err := os.ReadDir(p.Root)
	if err != nil {
		return nil, err
	}
	m := map[uint64]int{}
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		fdDir := filepath.Join(p.Root, e.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue // exited, or not permitted
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			if ino, ok := socketInode(link); ok {
				// a socket shared after fork: keep the lowest pid (usually the parent)
				if prev, dup := m[ino]; !dup || pid < prev {
					m[ino] = pid
				}
			}
		}
	}
	return m, nil
}

// Info reads comm, exe and the systemd unit of pid.
func (p ProcFS) Info(pid int) (*Proc, bool) {
	dir := filepath.Join(p.Root, strconv.Itoa(pid))
	comm, err := os.ReadFile(filepath.Join(dir, "comm"))
	if err != nil {
		return nil, false
	}
	info := &Proc{PID: pid, Comm: strings.TrimSpace(string(comm))}
	if exe, err := os.Readlink(filepath.Join(dir, "exe")); err == nil {
		info.Exe = strings.TrimSuffix(exe, " (deleted)")
	}
	if cg, err := os.ReadFile(filepath.Join(dir, "cgroup")); err == nil {
		info.Unit = UnitFromCgroup(string(cg))
	}
	return info, true
}

func socketInode(link string) (uint64, bool) {
	s, ok := strings.CutPrefix(link, "socket:[")
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseUint(strings.TrimSuffix(s, "]"), 10, 64)
	return n, err == nil
}

// UnitFromCgroup picks the systemd unit (the innermost *.service or
// *.scope component) from /proc/<pid>/cgroup content.
func UnitFromCgroup(content string) string {
	unit := ""
	for _, line := range strings.Split(content, "\n") {
		// cgroup v2: "0::/system.slice/ssh.service"; v1 lines use the name=systemd hierarchy
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 || (parts[0] != "0" && parts[1] != "name=systemd") {
			continue
		}
		for _, c := range strings.Split(parts[2], "/") {
			if strings.HasSuffix(c, ".service") || strings.HasSuffix(c, ".scope") {
				unit = c
			}
		}
		if parts[0] == "0" {
			break
		}
	}
	return unit
}

// NetlinkSockets dumps sockets through sock_diag (NETLINK_INET_DIAG).
type NetlinkSockets struct{}

// Dump returns IPv4 and IPv6 sockets for proto.
func (NetlinkSockets) Dump(proto uint8) ([]Sock, error) {
	var out []Sock
	var firstErr error
	for _, fam := range []uint8{unix.AF_INET, unix.AF_INET6} {
		var socks []*netlink.Socket
		var err error
		switch proto {
		case 6:
			socks, err = netlink.SocketDiagTCP(fam)
		case 17:
			socks, err = netlink.SocketDiagUDP(fam)
		default:
			return nil, nil
		}
		if err != nil && firstErr == nil {
			firstErr = err // ErrDumpInterrupted still returns usable sockets
		}
		for _, s := range socks {
			out = append(out, Sock{
				Local:  Endpoint{ipAddr(s.ID.Source), s.ID.SourcePort},
				Remote: Endpoint{ipAddr(s.ID.Destination), s.ID.DestinationPort},
				Inode:  uint64(s.INode),
				UID:    int(s.UID),
			})
		}
	}
	return out, firstErr
}

func ipAddr(ip net.IP) netip.Addr {
	a, _ := netip.AddrFromSlice(ip)
	return a.Unmap()
}
