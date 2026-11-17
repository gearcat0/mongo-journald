package main

import (
	"context"
	"encoding/json"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"mongo-journald/internal/dns"
	"mongo-journald/internal/flows"
	"mongo-journald/internal/model"
	"mongo-journald/internal/rollup"
	"mongo-journald/internal/store"
)

// streamMode describes one of the live (cursorless) sources.
type streamMode struct {
	sc           StreamConfig
	indexes      []bson.D
	rollupFields []string
	rollupKey    func(model.Doc) ([]any, map[string]int64)
	run          func(ctx context.Context, out chan<- model.Record) error
}

// runStream runs --mode dns or --mode flows and returns the exit code.
// These sources have no resume cursor: what happens while the unit is
// down is not recorded.
func runStream(mode string, cfg *Config, host string, dryRun, stdin bool, logf func(string, ...any)) int {
	var m streamMode
	switch mode {
	case "dns":
		opt := dns.Options{Hostname: host, Retention: cfg.DNS.retention, Ignore: cfg.DNS.Ignore, Notify: logf}
		r := dns.NewMonitor(opt)
		if stdin {
			r = dns.NewStream(opt, os.Stdin)
		}
		m = streamMode{cfg.DNS.StreamConfig, dns.Indexes, dns.RollupFields, dns.RollupKey, r.Run}
	case "flows":
		if stdin {
			logf("--stdin is not supported with --mode flows")
			return 2
		}
		r := flows.NewReader(flows.Options{
			Hostname:  host,
			Retention: cfg.Flows.retention,
			Filter: flows.Filter{
				IncludeLoopback: cfg.Flows.IncludeLoopback,
				IgnoreNets:      cfg.Flows.ignoreNets,
				IgnorePorts:     cfg.Flows.ignorePorts,
			},
			Proc:   cfg.Flows.proc,
			Notify: logf,
		})
		m = streamMode{cfg.Flows.StreamConfig, flows.Indexes, flows.RollupFields, flows.RollupKey, r.Run}
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var consume func(model.Record)
	closeConsumer := func() {}
	if dryRun {
		enc := json.NewEncoder(os.Stdout)
		consume = func(rec model.Record) { _ = enc.Encode(rec.Doc) }
	} else {
		if cfg.Mongo.URI == "" {
			logf("mongo.uri is required (set MONGO_JOURNALD_URI or mongo.uri in the config)")
			return 2
		}
		db, err := store.Open(cfg.Mongo.URI, cfg.Mongo.Database)
		if err != nil {
			logf("mongo open: %v", err)
			return 1
		}
		ictx, icancel := context.WithTimeout(context.Background(), time.Minute)
		if err := store.EnsureIndexes(ictx, db, m.sc.Collection, m.indexes...); err != nil {
			logf("ensure indexes on %s.%s: %v (continuing)", cfg.Mongo.Database, m.sc.Collection, err)
		}
		if err := store.EnsureUnique(ictx, db, m.sc.RollupCollection, rollup.IndexKeys(m.rollupFields)); err != nil {
			logf("ensure indexes on %s.%s: %v (continuing)", cfg.Mongo.Database, m.sc.RollupCollection, err)
		}
		icancel()

		sink := store.NewSink(db, store.SinkConfig{
			Collection: m.sc.Collection,
			BatchSize:  cfg.Batch.Size,
			Buffer:     cfg.Batch.Buffer,
			Flush:      cfg.batchFlush,
			Notify:     logf,
		})
		roll := rollup.New(db, rollup.Config{
			Collection: m.sc.RollupCollection,
			Server:     host,
			KeyFields:  m.rollupFields,
			Retention:  m.sc.rollupRetention,
			Notify:     logf,
		})
		consume = func(rec model.Record) {
			sink.Write(rec)
			key, inc := m.rollupKey(rec.Doc)
			roll.Add(rec.Doc["at"].(time.Time), key, inc)
		}
		closeConsumer = func() {
			cctx, ccancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer ccancel()
			sink.Close(cctx)
			roll.Close(cctx)
		}
		logf("mongo-journald %s --mode %s: host=%q → %s.%s (retention %s) + %s (retention %s)",
			version, mode, host, cfg.Mongo.Database, m.sc.Collection, m.sc.retention, m.sc.RollupCollection, m.sc.rollupRetention)
	}

	out := make(chan model.Record, 4096)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for rec := range out {
			consume(rec)
		}
	}()

	runErr := m.run(ctx, out)
	close(out)
	wg.Wait()
	closeConsumer()

	if runErr != nil {
		logf("%s reader stopped: %v", mode, runErr)
		return 1
	}
	logf("shutdown complete")
	return 0
}
