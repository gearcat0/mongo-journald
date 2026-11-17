package main

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

const day = 24 * time.Hour

// Config is the on-disk config plus derived values. The Mongo URI is kept
// out of the file and supplied via MONGO_JOURNALD_URI so credentials
// don't live in config.json.
type Config struct {
	Mongo      MongoConfig `json:"mongo"`
	Retention  string      `json:"retention"` // "60d", "48h", "forever"
	Priority   *int        `json:"priority"`  // syslog floor 0..7 (default 6: info and above)
	Redact     *bool       `json:"redact"`    // scrub secrets from messages (default true)
	CursorFile string      `json:"cursorFile"`
	Hostname   string      `json:"hostname"` // override; default os.Hostname()
	Units      UnitFilter  `json:"units"`
	Batch      BatchConfig `json:"batch"`
	RawFields  bool        `json:"rawFields"`
	DNS        DNSConfig   `json:"dns"`   // --mode dns
	Flows      FlowsConfig `json:"flows"` // --mode flows

	// derived
	priority   int
	redact     bool
	retention  time.Duration
	batchFlush time.Duration
	denySet    map[string]bool
	allowSet   map[string]bool
}

type MongoConfig struct {
	URI        string `json:"uri"`
	Database   string `json:"database"`
	Collection string `json:"collection"`
}

// StreamConfig is shared by the dns and flows modes: a raw collection
// with short retention plus an hourly rollup collection kept longer.
type StreamConfig struct {
	Collection       string `json:"collection"`
	RollupCollection string `json:"rollupCollection"`
	Retention        string `json:"retention"`       // raw docs; default "3d"
	RollupRetention  string `json:"rollupRetention"` // hourly rollups; default "60d"

	retention, rollupRetention time.Duration
}

// DNSConfig configures --mode dns (systemd-resolved lookups).
type DNSConfig struct {
	StreamConfig
	Ignore []string `json:"ignore"` // qname suffixes to drop, e.g. "ts.net"
}

// FlowsConfig configures --mode flows (conntrack flows).
type FlowsConfig struct {
	StreamConfig
	Proc            *bool `json:"proc"`            // attribute flows to processes (default true)
	IncludeLoopback bool  `json:"includeLoopback"` // default false
	Ignore          struct {
		CIDRs []string `json:"cidrs"` // drop flows with either endpoint inside
		Ports []int    `json:"ports"` // drop flows to these service ports
	} `json:"ignore"`

	proc        bool
	ignoreNets  []netip.Prefix
	ignorePorts map[uint16]bool
}

type UnitFilter struct {
	Deny  []string `json:"deny"`
	Allow []string `json:"allow"`
}

type BatchConfig struct {
	Size   int    `json:"size"`
	Buffer int    `json:"buffer"`
	Flush  string `json:"flush"` // Go duration, e.g. "1s"
}

// LoadConfig reads the JSON config (a missing file is allowed — defaults
// plus the env override still apply), fills defaults and derives values.
func LoadConfig(path string) (*Config, error) {
	c := &Config{}
	if b, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(b, c); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	if v := os.Getenv("MONGO_JOURNALD_URI"); v != "" {
		c.Mongo.URI = v
	}
	if c.Mongo.Database == "" {
		c.Mongo.Database = "syslog"
	}
	if c.Mongo.Collection == "" {
		c.Mongo.Collection = "events"
	}
	if c.CursorFile == "" {
		c.CursorFile = "/var/lib/mongo-journald/cursor"
	}

	c.priority = 6
	if c.Priority != nil {
		if *c.Priority < 0 || *c.Priority > 7 {
			return nil, fmt.Errorf("priority must be 0..7, got %d", *c.Priority)
		}
		c.priority = *c.Priority
	}

	c.redact = true
	if c.Redact != nil {
		c.redact = *c.Redact
	}

	c.retention = 60 * day
	if s := strings.TrimSpace(c.Retention); s != "" {
		d, err := ParseRetention(s)
		if err != nil {
			return nil, err
		}
		c.retention = d
	}

	c.batchFlush = time.Second
	if s := strings.TrimSpace(c.Batch.Flush); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil {
			return nil, fmt.Errorf("batch.flush: %w", err)
		}
		c.batchFlush = d
	}

	c.denySet = toSet(c.Units.Deny)
	c.allowSet = toSet(c.Units.Allow)

	if err := c.DNS.fill("dns", "dns", "dns_hourly"); err != nil {
		return nil, err
	}
	if err := c.Flows.fill("flows", "flows", "flows_hourly"); err != nil {
		return nil, err
	}
	c.Flows.proc = true
	if c.Flows.Proc != nil {
		c.Flows.proc = *c.Flows.Proc
	}
	for _, s := range c.Flows.Ignore.CIDRs {
		p, err := netip.ParsePrefix(strings.TrimSpace(s))
		if err != nil {
			if a, aerr := netip.ParseAddr(strings.TrimSpace(s)); aerr == nil {
				p = netip.PrefixFrom(a, a.BitLen())
			} else {
				return nil, fmt.Errorf("flows.ignore.cidrs: %w", err)
			}
		}
		c.Flows.ignoreNets = append(c.Flows.ignoreNets, p.Masked())
	}
	if len(c.Flows.Ignore.Ports) > 0 {
		c.Flows.ignorePorts = map[uint16]bool{}
		for _, p := range c.Flows.Ignore.Ports {
			if p < 1 || p > 65535 {
				return nil, fmt.Errorf("flows.ignore.ports: %d out of range", p)
			}
			c.Flows.ignorePorts[uint16(p)] = true
		}
	}
	return c, nil
}

func (s *StreamConfig) fill(name, coll, rollup string) error {
	if s.Collection == "" {
		s.Collection = coll
	}
	if s.RollupCollection == "" {
		s.RollupCollection = rollup
	}
	var err error
	if s.retention, err = retentionOr(s.Retention, 3*day); err != nil {
		return fmt.Errorf("%s.retention: %w", name, err)
	}
	if s.rollupRetention, err = retentionOr(s.RollupRetention, 60*day); err != nil {
		return fmt.Errorf("%s.rollupRetention: %w", name, err)
	}
	return nil
}

func retentionOr(s string, def time.Duration) (time.Duration, error) {
	if strings.TrimSpace(s) == "" {
		return def, nil
	}
	return ParseRetention(s)
}

// ParseRetention parses "48h", "90m", "60d" or "forever"/"0" (keep
// forever). Mirrors the mover's obs retention syntax.
func ParseRetention(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "forever" || s == "0" {
		return 0, nil
	}
	if n, ok := strings.CutSuffix(s, "d"); ok {
		days, err := strconv.Atoi(strings.TrimSpace(n))
		if err != nil {
			return 0, fmt.Errorf("retention %q: %w", s, err)
		}
		return time.Duration(days) * day, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("retention %q: %w", s, err)
	}
	return d, nil
}

func toSet(xs []string) map[string]bool {
	if len(xs) == 0 {
		return nil
	}
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		if x = strings.TrimSpace(x); x != "" {
			m[x] = true
		}
	}
	return m
}
