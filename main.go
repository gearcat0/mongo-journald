// Command mongo-journald ships systemd-journald logs from the local host
// into MongoDB, mirroring the mover's events schema and TTL retention so
// the same mongosh sweeps work against system logs.
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
	"mongo-journald/internal/store"
)

// version is the build version. It defaults to a dev value and is
// overridden at build time via -ldflags "-X main.version=<v>".
var version = "0.1.0"

func main() {
	cfgPath := flag.String("config", "/etc/mongo-journald/config.json", "path to config JSON")
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
		if err := store.EnsureIndexes(ictx, db, cfg.Mongo.Collection); err != nil {
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
