package store

import (
	"context"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"mongo-journald/internal/model"
)

// SinkConfig tunes batching, backpressure and checkpointing.
type SinkConfig struct {
	Collection string
	BatchSize  int           // default 500
	Buffer     int           // default 10000
	Flush      time.Duration // default 1s
	Notify     func(string, ...any)
	Checkpoint func(cursor string) // called with a batch's last cursor after it is durably written
}

// Sink batches records and writes them to Mongo from a single goroutine.
type Sink struct {
	db      *mongo.Database
	cfg     SinkConfig
	ch      chan model.Record
	wg      sync.WaitGroup
	mu      sync.Mutex
	dropped int
}

// NewSink starts the writer goroutine.
func NewSink(db *mongo.Database, cfg SinkConfig) *Sink {
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 500
	}
	if cfg.Buffer <= 0 {
		cfg.Buffer = 10000
	}
	if cfg.Flush <= 0 {
		cfg.Flush = time.Second
	}
	s := &Sink{db: db, cfg: cfg, ch: make(chan model.Record, cfg.Buffer)}
	s.wg.Add(1)
	go s.loop()
	return s
}

// Write queues a record without blocking. When the buffer is full the
// record is dropped and counted: logs are lossy under sustained
// backpressure by design — the shipper must never block or back up the
// host it runs on.
func (s *Sink) Write(rec model.Record) {
	select {
	case s.ch <- rec:
	default:
		s.mu.Lock()
		s.dropped++
		n := s.dropped
		s.mu.Unlock()
		if n == 1 || n%1000 == 0 {
			s.notify("buffer full; dropped %d log docs so far", n)
		}
	}
}

// Close stops accepting records and flushes what is queued, bounded by
// ctx.
func (s *Sink) Close(ctx context.Context) {
	close(s.ch)
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		s.notify("close timed out; some buffered docs may be unflushed")
	}
}

func (s *Sink) notify(f string, a ...any) {
	if s.cfg.Notify != nil {
		s.cfg.Notify(f, a...)
	}
}

func (s *Sink) loop() {
	defer s.wg.Done()
	t := time.NewTicker(s.cfg.Flush)
	defer t.Stop()

	batch := make([]any, 0, s.cfg.BatchSize)
	cursor := ""
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := s.insert(batch); err != nil {
			s.notify("insert of %d docs failed, dropping batch: %v", len(batch), err)
		} else if s.cfg.Checkpoint != nil && cursor != "" {
			s.cfg.Checkpoint(cursor)
		}
		batch = batch[:0]
		cursor = ""
	}

	for {
		select {
		case rec, ok := <-s.ch:
			if !ok {
				flush()
				return
			}
			batch = append(batch, rec.Doc)
			if rec.Cursor != "" {
				cursor = rec.Cursor
			}
			if len(batch) >= s.cfg.BatchSize {
				flush()
			}
		case <-t.C:
			flush()
		}
	}
}

// insert writes a batch with bounded retries. SetOrdered(false) lets Mongo
// insert the rest past a bad doc; a retry after a partial write may
// duplicate, which is acceptable (at-least-once).
func (s *Sink) insert(docs []any) error {
	backoff := time.Second
	var err error
	for attempt := 0; attempt < 5; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		_, err = s.db.Collection(s.cfg.Collection).InsertMany(ctx, docs, options.InsertMany().SetOrdered(false))
		cancel()
		if err == nil {
			return nil
		}
		time.Sleep(backoff)
		if backoff < 30*time.Second {
			if backoff *= 2; backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
		}
	}
	return err
}
