package packages

import (
	"bufio"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"mongo-journald/internal/model"
)

// Host facts are read from these files; none needs privileges.
const (
	bootTimeFile     = "/proc/stat"
	rebootFile       = "/run/reboot-required"
	rebootPkgsFile   = "/run/reboot-required.pkgs"
	osReleaseFile    = "/etc/os-release"
	osReleaseFileAlt = "/usr/lib/os-release"
)

// HostDoc describes the host itself as of the scan at time at: the OS
// release (os-release), the running kernel (uname -r), when it booted and
// whether a package has asked for a reboot. Comparing kernel with the
// installed linux-image packages shows a host that has not rebooted into
// its newest kernel. There is one such document per server.
func HostDoc(host string, at time.Time, retention time.Duration) model.Doc {
	d := model.Doc{"server": host, "at": at}
	if retention > 0 {
		d["expireAt"] = at.Add(retention)
	}

	f, err := os.Open(osReleaseFile)
	if err != nil {
		f, err = os.Open(osReleaseFileAlt)
	}
	if err == nil {
		if osd := osDoc(parseOSRelease(f)); len(osd) > 0 {
			d["os"] = osd
		}
		f.Close()
	}

	var u unix.Utsname
	if unix.Uname(&u) == nil {
		d["kernel"] = unix.ByteSliceToString(u.Release[:])
		d["arch"] = unix.ByteSliceToString(u.Machine[:])
	}

	if f, err := os.Open(bootTimeFile); err == nil {
		if t, ok := parseBootTime(f); ok {
			d["boot"] = t
		}
		f.Close()
	}

	// Ubuntu's packages touch this file when an upgrade (kernel, libc,
	// …) only takes effect after a reboot, and list themselves in .pkgs.
	_, err = os.Stat(rebootFile)
	d["reboot_required"] = err == nil
	if err == nil {
		if b, err := os.ReadFile(rebootPkgsFile); err == nil {
			if pkgs := uniqueLines(string(b)); len(pkgs) > 0 {
				d["reboot_pkgs"] = pkgs
			}
		}
	}
	return d
}

// parseOSRelease reads os-release(5): KEY=value lines, the value
// optionally quoted.
func parseOSRelease(r io.Reader) map[string]string {
	kv := map[string]string{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		k, v, ok := strings.Cut(line, "=")
		if !ok || strings.HasPrefix(line, "#") {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
			if v != "" && strings.Contains(v, `\`) {
				v = strings.NewReplacer(`\"`, `"`, `\$`, `$`, "\\`", "`", `\\`, `\`).Replace(v)
			}
		}
		kv[strings.TrimSpace(k)] = v
	}
	return kv
}

// osDoc keeps the os-release fields worth querying on.
func osDoc(kv map[string]string) model.Doc {
	d := model.Doc{}
	for field, key := range map[string]string{
		"id":       "ID",               // ubuntu
		"version":  "VERSION_ID",       // 24.04
		"codename": "VERSION_CODENAME", // noble
		"name":     "PRETTY_NAME",      // Ubuntu 24.04.3 LTS
	} {
		if v := kv[key]; v != "" {
			d[field] = v
		}
	}
	return d
}

// parseBootTime finds the "btime <unix seconds>" line of /proc/stat.
func parseBootTime(r io.Reader) (time.Time, bool) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		if rest, ok := strings.CutPrefix(sc.Text(), "btime "); ok {
			n, err := strconv.ParseInt(strings.TrimSpace(rest), 10, 64)
			if err != nil || n <= 0 {
				return time.Time{}, false
			}
			return time.Unix(n, 0).UTC(), true
		}
	}
	return time.Time{}, false
}

func uniqueLines(s string) []string {
	var out []string
	seen := map[string]bool{}
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" && !seen[l] {
			seen[l] = true
			out = append(out, l)
		}
	}
	return out
}
