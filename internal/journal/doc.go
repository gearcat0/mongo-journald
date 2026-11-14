// Package journal turns systemd-journald JSON entries into Mongo
// documents shaped like the mover's events collection, and streams them
// off the local journal.
package journal

import (
	"strconv"
	"time"

	"mongo-journald/internal/model"
	"mongo-journald/internal/redact"
)

// severity maps a syslog PRIORITY (0..7) to its RFC 5424 name.
var severity = [...]string{"emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"}

// SeverityName returns the syslog severity name for a priority, or
// "pri<N>" when out of range.
func SeverityName(p int) string {
	if p >= 0 && p < len(severity) {
		return severity[p]
	}
	return "pri" + strconv.Itoa(p)
}

// Build maps one journald JSON entry to a Mongo document. hostname is the
// fallback when the entry has no _HOSTNAME; now is the fallback when it
// has no timestamp. retention > 0 stamps expireAt (at + retention) so the
// TTL index can drop it; 0 keeps it forever. doRedact scrubs likely
// secrets from the message. raw attaches every journald field under
// "fields" (off by default, to control document size; raw fields are not
// redacted).
func Build(entry map[string]any, hostname string, now time.Time, retention time.Duration, doRedact, raw bool) model.Doc {
	at := now
	if t, ok := microTime(entry["__REALTIME_TIMESTAMP"]); ok {
		at = t
	}
	at = at.UTC()

	server := str(entry, "_HOSTNAME")
	if server == "" {
		server = hostname
	}

	prio := 6
	if p, ok := atoi(str(entry, "PRIORITY")); ok {
		prio = p
	}

	msg := str(entry, "MESSAGE")
	if doRedact {
		msg = redact.Message(msg)
	}

	doc := model.Doc{
		"at":       at,
		"server":   server,
		"level":    SeverityName(prio),
		"priority": prio,
		"source":   firstNonEmpty(str(entry, "_SYSTEMD_UNIT"), str(entry, "SYSLOG_IDENTIFIER"), str(entry, "_COMM")),
		"msg":      msg,
	}
	if u := str(entry, "_SYSTEMD_UNIT"); u != "" {
		doc["unit"] = u
	}
	if id := str(entry, "SYSLOG_IDENTIFIER"); id != "" {
		doc["ident"] = id
	}
	if pid, ok := atoi(str(entry, "_PID")); ok {
		doc["pid"] = pid
	}
	if f := str(entry, "SYSLOG_FACILITY"); f != "" {
		doc["facility"] = f
	}
	if b := str(entry, "_BOOT_ID"); b != "" {
		doc["boot"] = b
	}
	if retention > 0 {
		doc["expireAt"] = at.Add(retention)
	}
	if raw {
		doc["fields"] = entry
	}
	return doc
}

// str coerces a journald JSON field to a string. Fields are usually
// strings; a non-UTF8/binary field arrives as a JSON array of byte
// values, which we render as those bytes. Missing → "".
func str(entry map[string]any, key string) string {
	switch v := entry[key].(type) {
	case string:
		return v
	case []any:
		b := make([]byte, 0, len(v))
		for _, x := range v {
			if f, ok := x.(float64); ok {
				b = append(b, byte(int(f)))
			}
		}
		return string(b)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	default:
		return ""
	}
}

func atoi(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, false
	}
	return n, true
}

// microTime parses a __REALTIME_TIMESTAMP (microseconds since the Unix
// epoch, as a string) into a time.Time.
func microTime(v any) (time.Time, bool) {
	s, ok := v.(string)
	if !ok {
		return time.Time{}, false
	}
	us, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	return time.UnixMicro(us), true
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
