package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func loadJSON(t *testing.T, js string) (*Config, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(p, []byte(js), 0o644); err != nil {
		t.Fatal(err)
	}
	return LoadConfig(p)
}

func TestStreamDefaults(t *testing.T) {
	c, err := loadJSON(t, `{}`)
	if err != nil {
		t.Fatal(err)
	}
	if c.DNS.Collection != "dns" || c.DNS.RollupCollection != "dns_hourly" ||
		c.Flows.Collection != "flows" || c.Flows.RollupCollection != "flows_hourly" {
		t.Errorf("collections: %+v %+v", c.DNS.StreamConfig, c.Flows.StreamConfig)
	}
	if c.DNS.retention != 3*day || c.DNS.rollupRetention != 60*day || c.Flows.retention != 3*day {
		t.Errorf("retention: %v %v %v", c.DNS.retention, c.DNS.rollupRetention, c.Flows.retention)
	}
	if !c.Flows.proc || c.Flows.IncludeLoopback {
		t.Error("flows defaults")
	}
}

func TestStreamOverrides(t *testing.T) {
	c, err := loadJSON(t, `{"dns":{"collection":"d","retention":"12h","rollupRetention":"forever","ignore":["ts.net"]},
		"flows":{"proc":false,"ignore":{"cidrs":["100.64.0.0/10","10.1.2.3"],"ports":[41641]}}}`)
	if err != nil {
		t.Fatal(err)
	}
	if c.DNS.Collection != "d" || c.DNS.retention != 12*time.Hour || c.DNS.rollupRetention != 0 {
		t.Errorf("dns: %+v", c.DNS)
	}
	if c.Flows.proc || len(c.Flows.ignoreNets) != 2 || c.Flows.ignoreNets[1].Bits() != 32 || !c.Flows.ignorePorts[41641] {
		t.Errorf("flows: %+v", c.Flows)
	}
	for _, bad := range []string{`{"flows":{"ignore":{"cidrs":["nope"]}}}`, `{"flows":{"ignore":{"ports":[70000]}}}`, `{"dns":{"retention":"x"}}`} {
		if _, err := loadJSON(t, bad); err == nil {
			t.Errorf("want error for %s", bad)
		}
	}
}

func TestPackagesConfig(t *testing.T) {
	c, err := loadJSON(t, `{}`)
	if err != nil {
		t.Fatal(err)
	}
	if p := c.Packages; !p.enabled || p.Collection != "packages" || p.HostCollection != "hosts" || p.interval != time.Hour || p.retention != 14*day {
		t.Errorf("defaults: %+v", p)
	}
	c, err = loadJSON(t, `{"packages":{"enabled":false,"collection":"pkgs","interval":"6h","retention":"forever"}}`)
	if err != nil {
		t.Fatal(err)
	}
	if p := c.Packages; p.enabled || p.Collection != "pkgs" || p.interval != 6*time.Hour || p.retention != 0 {
		t.Errorf("overrides: %+v", p)
	}
	for _, bad := range []string{`{"packages":{"interval":"10s"}}`, `{"packages":{"interval":"x"}}`, `{"packages":{"interval":"12h","retention":"12h"}}`} {
		if _, err := loadJSON(t, bad); err == nil {
			t.Errorf("want error for %s", bad)
		}
	}
}

func TestMetricsConfig(t *testing.T) {
	c, err := loadJSON(t, `{}`)
	if err != nil {
		t.Fatal(err)
	}
	m := c.Metrics
	if !m.enabled || m.Collection != "metrics" || m.interval != time.Minute || m.retention != 30*day {
		t.Errorf("defaults: %+v", m)
	}
	if u := m.Units; !u.enabled || u.Collection != "unit_metrics" || u.RollupCollection != "unit_metrics_hourly" ||
		u.retention != 3*day || u.rollupRetention != 60*day || u.minCPUPct != 1 || u.minMem != 100<<20 {
		t.Errorf("unit defaults: %+v", u)
	}
	c, err = loadJSON(t, `{"metrics":{"enabled":false,"interval":"15s","retention":"7d",
		"units":{"enabled":false,"collection":"u","retention":"1d","minCpuPct":0.5,"minMemMB":0}}}`)
	if err != nil {
		t.Fatal(err)
	}
	m = c.Metrics
	if m.enabled || m.interval != 15*time.Second || m.retention != 7*day || m.Units.enabled || m.Units.Collection != "u" ||
		m.Units.retention != day || m.Units.minCPUPct != 0.5 || m.Units.minMem != 0 {
		t.Errorf("overrides: %+v", m)
	}
	for _, bad := range []string{`{"metrics":{"interval":"10ms"}}`, `{"metrics":{"interval":"2h"}}`, `{"metrics":{"retention":"x"}}`,
		`{"metrics":{"units":{"minCpuPct":-1}}}`, `{"metrics":{"units":{"rollupRetention":"x"}}}`} {
		if _, err := loadJSON(t, bad); err == nil {
			t.Errorf("want error for %s", bad)
		}
	}
}
