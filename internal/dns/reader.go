package dns

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"mongo-journald/internal/model"
)

// Indexes are the lookup indexes for the raw dns collection.
var Indexes = []bson.D{
	{{Key: "server", Value: 1}, {Key: "at", Value: -1}},
	{{Key: "qname", Value: 1}, {Key: "at", Value: -1}},
}

// RollupFields are the key fields of the dns_hourly collection.
var RollupFields = []string{"qname", "qtype", "rcode"}

// RollupKey returns the hourly rollup key and counters for a dns doc.
func RollupKey(doc model.Doc) ([]any, map[string]int64) {
	rc, _ := doc["rcode"].(string)
	if rc == "" {
		rc, _ = doc["state"].(string)
	}
	return []any{doc["qname"], doc["qtype"], rc}, map[string]int64{"n": 1}
}

// Options configure the reader.
type Options struct {
	Hostname  string
	Retention time.Duration
	Ignore    []string // qname suffixes to drop (e.g. "ts.net"); matched on label boundaries
	Notify    func(string, ...any)
}

// Reader streams lookups as Records. With a nil stream it spawns and
// supervises `resolvectl monitor --json=short` (root only: the monitor
// varlink socket requires privileges); with a stream it reads that once.
type Reader struct {
	opt    Options
	stream io.Reader
}

// NewMonitor builds a Reader backed by `resolvectl monitor`.
func NewMonitor(opt Options) *Reader { return &Reader{opt: opt} }

// NewStream builds a Reader over a line stream of monitor JSON.
func NewStream(opt Options, r io.Reader) *Reader { return &Reader{opt: opt, stream: r} }

func (r *Reader) notify(f string, a ...any) {
	if r.opt.Notify != nil {
		r.opt.Notify(f, a...)
	}
}

// Run streams records to out until ctx is cancelled (monitor mode) or the
// stream ends. There is no resume cursor: lookups made while the reader is
// down are not recorded.
func (r *Reader) Run(ctx context.Context, out chan<- model.Record) error {
	if r.stream != nil {
		return r.pump(ctx, r.stream, out)
	}
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return nil
		}
		cmd := exec.CommandContext(ctx, "resolvectl", "monitor", "--json=short", "--no-pager")
		cmd.Stderr = os.Stderr
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return err
		}
		if err := cmd.Start(); err != nil {
			return err
		}
		started := time.Now()
		perr := r.pump(ctx, stdout, out)
		werr := cmd.Wait()
		if ctx.Err() != nil {
			return nil
		}
		if time.Since(started) > time.Minute {
			backoff = time.Second // it ran fine for a while; restart promptly
		}
		why := werr // the exit status (resolvectl prints its reason to stderr)
		if why == nil {
			why = perr
		}
		if why == nil {
			why = errors.New("exited cleanly")
		}
		r.notify("resolvectl monitor stopped (%v); restarting in %s", why, backoff)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > 30*time.Second {
			backoff = 30 * time.Second
		}
	}
}

func (r *Reader) pump(ctx context.Context, src io.Reader, out chan<- model.Record) error {
	br := bufio.NewReaderSize(src, 1<<18)
	for {
		if ctx.Err() != nil {
			return nil
		}
		line, err := br.ReadBytes('\n')
		if len(line) > 0 {
			if rec, ok := r.record(line, time.Now()); ok {
				select {
				case out <- rec:
				case <-ctx.Done():
					return nil
				}
			}
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

func (r *Reader) record(line []byte, now time.Time) (model.Record, bool) {
	if len(strings.TrimSpace(string(line))) == 0 {
		return model.Record{}, false
	}
	var msg map[string]any
	if err := json.Unmarshal(line, &msg); err != nil {
		r.notify("skip unparseable monitor line: %v", err)
		return model.Record{}, false
	}
	doc, ok := Build(msg, r.opt.Hostname, now, r.opt.Retention)
	if !ok {
		return model.Record{}, false
	}
	if Ignored(doc["qname"].(string), r.opt.Ignore) {
		return model.Record{}, false
	}
	return model.Record{Doc: doc}, true
}

// Ignored reports whether name equals or is a subdomain of one of the
// suffixes.
func Ignored(name string, suffixes []string) bool {
	for _, s := range suffixes {
		s = NormName(s)
		if s == "" {
			continue
		}
		if name == s || strings.HasSuffix(name, "."+s) {
			return true
		}
	}
	return false
}
