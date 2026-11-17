// Package rollup keeps hourly per-host counters in memory and periodically
// upserts them into a Mongo collection with $inc, so long-lived summaries
// (top domains, top talkers) outlive the short raw-data retention.
//
// Each rollup document is keyed by {server, hour, <key fields>} — a unique
// index on those fields makes the upsert idempotent per key — and carries
// expireAt = hour + retention for the TTL index.
package rollup

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// Config tunes a Rollup.
type Config struct {
	Collection string
	Server     string
	KeyFields  []string      // names of the key fields, in index order
	Retention  time.Duration // stamped as expireAt = hour + Retention; 0 = forever
	Flush      time.Duration // default 60s
	MaxKeys    int           // flush early past this many pending keys; default 50000
	Notify     func(string, ...any)
}

// Rollup aggregates counters per (hour, key).
type Rollup struct {
	db   *mongo.Database
	cfg  Config
	mu   sync.Mutex
	acc  map[string]*entry
	kick chan struct{}
	done chan struct{}
	wg   sync.WaitGroup
}

type entry struct {
	hour time.Time
	key  []any
	inc  map[string]int64
}

// New starts the flusher goroutine. With a nil db nothing is flushed
// (tests inspect the pending entries directly).
func New(db *mongo.Database, cfg Config) *Rollup {
	if cfg.Flush <= 0 {
		cfg.Flush = time.Minute
	}
	if cfg.MaxKeys <= 0 {
		cfg.MaxKeys = 50000
	}
	r := &Rollup{db: db, cfg: cfg, acc: map[string]*entry{}, kick: make(chan struct{}, 1), done: make(chan struct{})}
	if db != nil {
		r.wg.Add(1)
		go r.loop()
	}
	return r
}

// Add increments counters for the key (values in KeyFields order) in the
// hour containing at.
func (r *Rollup) Add(at time.Time, key []any, inc map[string]int64) {
	hour := at.UTC().Truncate(time.Hour)
	id := mapKey(hour, key)
	r.mu.Lock()
	e := r.acc[id]
	if e == nil {
		e = &entry{hour: hour, key: key, inc: make(map[string]int64, len(inc))}
		r.acc[id] = e
	}
	for k, v := range inc {
		e.inc[k] += v
	}
	full := len(r.acc) >= r.cfg.MaxKeys
	r.mu.Unlock()
	if full && r.db != nil {
		select {
		case r.kick <- struct{}{}:
		default:
		}
	}
}

// Close flushes what is pending, bounded by ctx.
func (r *Rollup) Close(ctx context.Context) {
	if r.db == nil {
		return
	}
	close(r.done)
	finished := make(chan struct{})
	go func() { r.wg.Wait(); close(finished) }()
	select {
	case <-finished:
	case <-ctx.Done():
		r.notify("rollup %s: close timed out; pending counters lost", r.cfg.Collection)
	}
}

func (r *Rollup) notify(f string, a ...any) {
	if r.cfg.Notify != nil {
		r.cfg.Notify(f, a...)
	}
}

func (r *Rollup) loop() {
	defer r.wg.Done()
	t := time.NewTicker(r.cfg.Flush)
	defer t.Stop()
	for {
		select {
		case <-t.C:
		case <-r.kick:
		case <-r.done:
			r.flush()
			return
		}
		r.flush()
	}
}

func (r *Rollup) take() map[string]*entry {
	r.mu.Lock()
	defer r.mu.Unlock()
	acc := r.acc
	r.acc = map[string]*entry{}
	return acc
}

func (r *Rollup) flush() {
	acc := r.take()
	if len(acc) == 0 {
		return
	}
	ids := make([]string, 0, len(acc))
	for id := range acc {
		ids = append(ids, id)
	}
	slices.Sort(ids) // deterministic order; also groups by hour
	const chunk = 1000
	for i := 0; i < len(ids); i += chunk {
		var models []mongo.WriteModel
		for _, id := range ids[i:min(i+chunk, len(ids))] {
			models = append(models, r.Model(acc[id]))
		}
		if err := r.write(models); err != nil {
			r.notify("rollup %s: upsert of %d keys failed, dropping: %v", r.cfg.Collection, len(models), err)
		}
	}
}

// Model builds the upsert for one entry: filter on the key, $inc the
// counters, $setOnInsert the expiry.
func (r *Rollup) Model(e *entry) mongo.WriteModel {
	return mongo.NewUpdateOneModel().SetFilter(r.filter(e)).SetUpdate(r.update(e)).SetUpsert(true)
}

func (r *Rollup) filter(e *entry) bson.D {
	f := bson.D{{Key: "server", Value: r.cfg.Server}, {Key: "hour", Value: e.hour}}
	for i, name := range r.cfg.KeyFields {
		var v any
		if i < len(e.key) {
			v = e.key[i]
		}
		f = append(f, bson.E{Key: name, Value: v})
	}
	return f
}

func (r *Rollup) update(e *entry) bson.D {
	inc := bson.D{}
	names := make([]string, 0, len(e.inc))
	for k := range e.inc {
		names = append(names, k)
	}
	slices.Sort(names)
	for _, k := range names {
		inc = append(inc, bson.E{Key: k, Value: e.inc[k]})
	}
	u := bson.D{{Key: "$inc", Value: inc}}
	if r.cfg.Retention > 0 {
		u = append(u, bson.E{Key: "$setOnInsert", Value: bson.D{{Key: "expireAt", Value: e.hour.Add(r.cfg.Retention)}}})
	}
	return u
}

func (r *Rollup) write(models []mongo.WriteModel) error {
	backoff := time.Second
	var err error
	for attempt := 0; attempt < 4; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		_, err = r.db.Collection(r.cfg.Collection).BulkWrite(ctx, models, options.BulkWrite().SetOrdered(false))
		cancel()
		if err == nil {
			return nil
		}
		time.Sleep(backoff)
		backoff *= 2
	}
	return err
}

// IndexKeys is the unique key for the rollup collection.
func IndexKeys(keyFields []string) bson.D {
	k := bson.D{{Key: "server", Value: 1}, {Key: "hour", Value: -1}}
	for _, f := range keyFields {
		k = append(k, bson.E{Key: f, Value: 1})
	}
	return k
}

func mapKey(hour time.Time, key []any) string {
	var b strings.Builder
	b.WriteString(hour.Format(time.RFC3339))
	for _, v := range key {
		b.WriteByte(0)
		b.WriteString(toString(v))
	}
	return b.String()
}

func toString(v any) string {
	switch x := v.(type) {
	case nil:
		return "\x01nil"
	case string:
		return x
	default:
		return fmt.Sprintf("%T:%v", x, x)
	}
}
