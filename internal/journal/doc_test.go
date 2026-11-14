package journal

import (
	"testing"
	"time"
)

func TestBuildMapsCoreFields(t *testing.T) {
	entry := map[string]any{
		"__REALTIME_TIMESTAMP": "1700000000000000",
		"__CURSOR":             "s=abc;i=1",
		"_HOSTNAME":            "web01",
		"PRIORITY":             "3",
		"_SYSTEMD_UNIT":        "nginx.service",
		"SYSLOG_IDENTIFIER":    "nginx",
		"_PID":                 "1234",
		"SYSLOG_FACILITY":      "3",
		"MESSAGE":              "connection refused",
	}
	ret := 60 * 24 * time.Hour
	d := Build(entry, "fallback", time.Unix(0, 0), ret, true, false)

	if d["server"] != "web01" {
		t.Errorf("server = %v, want web01", d["server"])
	}
	if d["level"] != "err" {
		t.Errorf("level = %v, want err", d["level"])
	}
	if d["priority"] != 3 {
		t.Errorf("priority = %v, want 3", d["priority"])
	}
	if d["source"] != "nginx.service" {
		t.Errorf("source = %v, want nginx.service", d["source"])
	}
	if d["unit"] != "nginx.service" || d["ident"] != "nginx" {
		t.Errorf("unit/ident = %v/%v", d["unit"], d["ident"])
	}
	if d["msg"] != "connection refused" {
		t.Errorf("msg = %v", d["msg"])
	}
	if d["pid"] != 1234 {
		t.Errorf("pid = %v, want 1234", d["pid"])
	}

	at, ok := d["at"].(time.Time)
	if !ok {
		t.Fatalf("at is %T, want time.Time", d["at"])
	}
	if want := time.UnixMicro(1700000000000000).UTC(); !at.Equal(want) {
		t.Errorf("at = %v, want %v", at, want)
	}
	exp, ok := d["expireAt"].(time.Time)
	if !ok {
		t.Fatalf("expireAt is %T, want time.Time", d["expireAt"])
	}
	if exp.Sub(at) != ret {
		t.Errorf("expireAt-at = %v, want %v", exp.Sub(at), ret)
	}
}

func TestBuildFallbacksAndBinaryMessage(t *testing.T) {
	entry := map[string]any{
		"PRIORITY": "6",
		// non-UTF8/binary fields arrive as a JSON array of byte values
		"MESSAGE": []any{float64('h'), float64('i')},
	}
	d := Build(entry, "fallback-host", time.Unix(100, 0), 0, true, false)

	if d["server"] != "fallback-host" {
		t.Errorf("server = %v, want fallback-host (no _HOSTNAME)", d["server"])
	}
	if d["msg"] != "hi" {
		t.Errorf("msg = %v, want hi (decoded byte array)", d["msg"])
	}
	if d["level"] != "info" {
		t.Errorf("level = %v, want info", d["level"])
	}
	if _, ok := d["expireAt"]; ok {
		t.Error("expireAt should be absent when retention == 0")
	}
	if _, ok := d["unit"]; ok {
		t.Error("unit should be absent when _SYSTEMD_UNIT missing")
	}
}

func TestBuildRedactsMessage(t *testing.T) {
	entry := map[string]any{
		"PRIORITY": "6",
		"MESSAGE":  "auth attempt password=hunter2 for bob",
	}
	on := Build(entry, "h", time.Unix(0, 0), 0, true, false)
	if on["msg"] != "auth attempt password=REDACTED for bob" {
		t.Errorf("redacted msg = %v", on["msg"])
	}
	off := Build(entry, "h", time.Unix(0, 0), 0, false, false)
	if off["msg"] != "auth attempt password=hunter2 for bob" {
		t.Errorf("unredacted msg = %v", off["msg"])
	}
}

func TestSeverityName(t *testing.T) {
	cases := map[int]string{0: "emerg", 3: "err", 6: "info", 7: "debug", 9: "pri9"}
	for p, want := range cases {
		if got := SeverityName(p); got != want {
			t.Errorf("SeverityName(%d) = %q, want %q", p, got, want)
		}
	}
}
