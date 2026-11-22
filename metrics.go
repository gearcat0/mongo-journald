package main

import (
	"context"
	"encoding/json"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.mongodb.org/mongo-driver/v2/mongo"

	"mongo-journald/internal/metrics"
	"mongo-journald/internal/model"
	"mongo-journald/internal/rollup"
	"mongo-journald/internal/store"
)

func newSampler(cfg *Config, host string) *metrics.Sampler {
	return metrics.NewSampler(metrics.Options{
		Hostname:      host,
		Retention:     cfg.Metrics.retention,
		UnitRetention: cfg.Metrics.Units.retention,
		Units:         cfg.Metrics.Units.enabled,
		MinCPUPct:     cfg.Metrics.Units.minCPUPct,
		MinMem:        cfg.Metrics.Units.minMem,
	})
}

// sampleLoop takes a baseline, then samples every interval until ctx is
// done. Ticks are aligned to the wall clock (with a 1m interval, on the
// minute) so hosts' samples line up with each other.
func sampleLoop(ctx context.Context, s *metrics.Sampler, interval time.Duration,
	host func(model.Doc), unit func(metrics.UnitSample, time.Time)) {
	s.Sample(time.Now())
	for {
		now := time.Now()
		next := now.Truncate(interval).Add(interval)
		if next.Sub(now) < interval/2 {
			next = next.Add(interval) // don't emit a sliver of an interval
		}
		t := time.NewTimer(next.Sub(now))
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		at := time.Now()
		h, units := s.Sample(at)
		if h == nil {
			continue
		}
		host(h)
		for _, u := range units {
			unit(u, h["at"].(time.Time))
		}
	}
}

// startMetrics starts sampling into Mongo on its own goroutine and
// returns a function that stops it and flushes what is buffered.
func startMetrics(db *mongo.Database, cfg *Config, host string, logf func(string, ...any)) (stop func()) {
	mc, uc := cfg.Metrics, cfg.Metrics.Units

	ictx, icancel := context.WithTimeout(context.Background(), time.Minute)
	if err := store.EnsureIndexes(ictx, db, mc.Collection, metrics.HostIndexes...); err != nil {
		logf("metrics: ensure indexes on %s: %v (continuing)", mc.Collection, err)
	}
	if uc.enabled {
		if err := store.EnsureIndexes(ictx, db, uc.Collection, metrics.UnitIndexes...); err != nil {
			logf("metrics: ensure indexes on %s: %v (continuing)", uc.Collection, err)
		}
		if err := store.EnsureUnique(ictx, db, uc.RollupCollection, rollup.IndexKeys(metrics.UnitRollupFields)); err != nil {
			logf("metrics: ensure indexes on %s: %v (continuing)", uc.RollupCollection, err)
		}
	}
	icancel()

	sinkCfg := store.SinkConfig{BatchSize: cfg.Batch.Size, Buffer: cfg.Batch.Buffer, Flush: cfg.batchFlush, Notify: logf}
	sinkCfg.Collection = mc.Collection
	hostSink := store.NewSink(db, sinkCfg)
	sinkCfg.Collection = uc.Collection
	unitSink := store.NewSink(db, sinkCfg)
	roll := rollup.New(db, rollup.Config{
		Collection: uc.RollupCollection,
		Server:     host,
		KeyFields:  metrics.UnitRollupFields,
		Retention:  uc.rollupRetention,
		Notify:     logf,
	})

	s := newSampler(cfg, host)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		sampleLoop(ctx, s, mc.interval,
			func(d model.Doc) { hostSink.Write(model.Record{Doc: d}) },
			func(u metrics.UnitSample, at time.Time) {
				if s.Busy(u) {
					unitSink.Write(model.Record{Doc: s.Doc(u, at)})
				}
				key, inc, max := metrics.Rollup(u)
				roll.AddMax(at, key, inc, max)
			})
	}()

	if uc.enabled {
		logf("metrics: every %s → %s (retention %s); units → %s (retention %s) + %s (retention %s)",
			mc.interval, mc.Collection, mc.retention, uc.Collection, uc.retention, uc.RollupCollection, uc.rollupRetention)
	} else {
		logf("metrics: every %s → %s (retention %s); per-unit samples off", mc.interval, mc.Collection, mc.retention)
	}

	return func() {
		cancel()
		<-done
		cctx, ccancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer ccancel()
		hostSink.Close(cctx)
		unitSink.Close(cctx)
		roll.Close(cctx)
	}
}

// runMetrics runs --mode metrics: only the sampler, until interrupted.
// With --dry-run it prints the documents it would write (the host sample,
// then the units that clear the raw thresholds). It runs even when
// metrics.enabled is false, since it was asked for explicitly.
func runMetrics(cfg *Config, host string, dryRun bool, logf func(string, ...any)) int {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if dryRun {
		enc := json.NewEncoder(os.Stdout)
		s := newSampler(cfg, host)
		sampleLoop(ctx, s, cfg.Metrics.interval,
			func(d model.Doc) { _ = enc.Encode(d) },
			func(u metrics.UnitSample, at time.Time) {
				if s.Busy(u) {
					_ = enc.Encode(s.Doc(u, at))
				}
			})
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
	closeMetrics := startMetrics(db, cfg, host, logf)
	<-ctx.Done()
	closeMetrics()
	logf("shutdown complete")
	return 0
}
