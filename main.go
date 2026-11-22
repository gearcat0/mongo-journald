// Command mongo-journald ships systemd-journald logs from the local host
// into MongoDB, mirroring the mover's events schema and TTL retention so
// the same mongosh sweeps work against system logs.
//
// --mode dns and --mode flows instead ship systemd-resolved lookups and
// conntrack network flows (each run as its own systemd unit) into their
// own collections, plus hourly rollups.
//
// The journal service also keeps an inventory of installed packages
// (dpkg) in its own collection; --mode packages runs one such scan.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"mongo-journald/internal/journal"
	"mongo-journald/internal/model"
	"mongo-journald/internal/packages"
	"mongo-journald/internal/store"
)

// version is the build version. It defaults to a dev value and is
// overridden at build time via -ldflags "-X main.version=<v>".
var version = "0.2.1"

func main() {
	cfgPath := flag.String("config", "/etc/mongo-journald/config.json", "path to config JSON")
	mode := flag.String("mode", "journal", "what to ship: journal (journald logs, plus the package inventory), dns (resolved lookups), flows (conntrack flows), packages (one package scan, then exit)")
	dryRun := flag.Bool("dry-run", false, "map and print docs as JSON to stdout; do not connect to Mongo")
	stdin := flag.Bool("stdin", false, "read journald JSON (one object per line) from stdin instead of journalctl")
	showVer := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVer {
		fmt.Println("mongo-journald", version)
		return
	}

	logf := func(f string, a ...any) {
		fmt.Fprintf(os.Stderr, time.Now().UTC().Format("2006-01-02T15:04:05Z")+" "+f+"\n", a...)
	}

	cfg, err := LoadConfig(*cfgPath)
	if err != nil {
		logf("config: %v", err)
		os.Exit(2)
	}

	host := cfg.Hostname
	if host == "" {
		host, _ = os.Hostname()
	}

	switch *mode {
	case "journal":
	case "dns", "flows":
		os.Exit(runStream(*mode, cfg, host, *dryRun, *stdin, logf))
	case "packages":
		os.Exit(runPackages(cfg, host, *dryRun, logf))
	default:
		logf("unknown --mode %q (want journal, dns, flows or packages)", *mode)
		os.Exit(2)
	}

	ropt := journal.Options{
		Hostname:  host,
		Priority:  cfg.priority,
		Retention: cfg.retention,
		Redact:    cfg.redact,
		Raw:       cfg.RawFields,
		Deny:      cfg.denySet,
		Allow:     cfg.allowSet,
		Notify:    logf,
	}

	var reader *journal.Reader
	if *stdin {
		reader = journal.NewStream(ropt, os.Stdin)
	} else {
		reader = journal.NewJournalctl(ropt)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	out := make(chan model.Record, 4096)

	var consume func(model.Record)
	loadCursor := func() string { return "" }
	closeConsumer := func() {}

	if *dryRun {
		enc := json.NewEncoder(os.Stdout)
		consume = func(rec model.Record) { _ = enc.Encode(rec.Doc) }
	} else {
		if cfg.Mongo.URI == "" {
			logf("mongo.uri is required (set MONGO_JOURNALD_URI or mongo.uri in the config)")
			os.Exit(2)
		}
		db, err := store.Open(cfg.Mongo.URI, cfg.Mongo.Database)
		if err != nil {
			logf("mongo open: %v", err)
			os.Exit(1)
		}
		ictx, icancel := context.WithTimeout(context.Background(), time.Minute)
		if err := store.EnsureIndexes(ictx, db, cfg.Mongo.Collection, store.EventIndexes...); err != nil {
			logf("ensure indexes on %s.%s: %v (continuing)", cfg.Mongo.Database, cfg.Mongo.Collection, err)
		}
		icancel()

		cur := &cursorStore{path: cfg.CursorFile}
		sink := store.NewSink(db, store.SinkConfig{
			Collection: cfg.Mongo.Collection,
			BatchSize:  cfg.Batch.Size,
			Buffer:     cfg.Batch.Buffer,
			Flush:      cfg.batchFlush,
			Notify:     logf,
			Checkpoint: cur.Save,
		})
		consume = sink.Write
		loadCursor = cur.Load
		closeConsumer = func() {
			cctx, ccancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer ccancel()
			sink.Close(cctx)
		}
		logf("mongo-journald %s: host=%q → %s.%s, priority<=%d, retention=%s",
			version, host, cfg.Mongo.Database, cfg.Mongo.Collection, cfg.priority, cfg.retention)

		// Package inventory: independent of the log stream, and never
		// allowed to hold it up, so it runs on its own goroutine.
		if cfg.Packages.enabled && !*stdin {
			go packages.NewSyncer(db, pkgOptions(cfg, host, logf)).Run(ctx)
		}
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for rec := range out {
			consume(rec)
		}
	}()

	runErr := reader.Run(ctx, out, loadCursor)
	close(out)
	wg.Wait()
	closeConsumer()

	if runErr != nil {
		logf("reader stopped: %v", runErr)
		os.Exit(1)
	}
	logf("shutdown complete")
}

func pkgOptions(cfg *Config, host string, logf func(string, ...any)) packages.Options {
	return packages.Options{
		Collection: cfg.Packages.Collection,
		Hostname:   host,
		Interval:   cfg.Packages.interval,
		Retention:  cfg.Packages.retention,
		Notify:     logf,
	}
}

// runPackages runs --mode packages: one package scan, printed with
// --dry-run or written to Mongo, and returns the exit code. It runs even
// when packages.enabled is false, since it was asked for explicitly.
func runPackages(cfg *Config, host string, dryRun bool, logf func(string, ...any)) int {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if dryRun {
		pkgs, err := packages.List(ctx)
		if err != nil {
			logf("packages: %v", err)
			return 1
		}
		enc := json.NewEncoder(os.Stdout)
		at := time.Now().UTC().Truncate(time.Millisecond)
		for _, p := range pkgs {
			_ = enc.Encode(packages.Doc(p, host, at, cfg.Packages.retention))
		}
		return 0
	}

	if cfg.Mongo.URI == "" {
		logf("mongo.uri is required (set MONGO_JOURNALD_URI or mongo.uri in the config)")
		return 2
	}
	db, err := store.Open(cfg.Mongo.URI, cfg.Mongo.Database)
	if err != nil {
		logf("mongo open: %v", err)
		return 1
	}
	s := packages.NewSyncer(db, pkgOptions(cfg, host, logf))
	if err := s.EnsureIndexes(ctx); err != nil {
		logf("packages: ensure indexes on %s.%s: %v (continuing)", cfg.Mongo.Database, cfg.Packages.Collection, err)
	}
	if err := s.Sync(ctx); err != nil {
		logf("packages: %v", err)
		return 1
	}
	return 0
}

// cursorStore persists the last durably-written journald cursor so a
// restart resumes where shipping left off.
type cursorStore struct {
	path string
	mu   sync.Mutex
}

func (c *cursorStore) Load() string {
	b, err := os.ReadFile(c.path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func (c *cursorStore) Save(cursor string) {
	if cursor == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, []byte(cursor+"\n"), 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, c.path)
}
