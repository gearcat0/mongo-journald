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
	if p := c.Packages; !p.enabled || p.Collection != "packages" || p.interval != time.Hour || p.retention != 14*day {
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
