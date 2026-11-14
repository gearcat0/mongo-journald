package journal

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"mongo-journald/internal/model"
)

// Options configure the reader.
type Options struct {
	Hostname  string          // fallback host tag; default os.Hostname()
	Priority  int             // syslog floor 0..7; entries with a higher number are dropped
	Retention time.Duration   // stamped as expireAt; 0 = keep forever
	Redact    bool            // scrub likely secrets from the message
	Raw       bool            // keep every journald field under "fields"
	Deny      map[string]bool // units/idents to drop
	Allow     map[string]bool // if non-empty, keep only these units/idents
	Notify    func(string, ...any)
}

// Reader streams journald entries as Records. With a nil stream it spawns
// and supervises `journalctl --follow`; with a stream it reads that once
// (used for --stdin and tests).
type Reader struct {
	opt    Options
	stream io.Reader
}

// NewJournalctl builds a Reader backed by `journalctl --follow`.
func NewJournalctl(opt Options) *Reader { return &Reader{opt: opt} }

// NewStream builds a Reader over a line stream of journald JSON (one
// object per line).
func NewStream(opt Options, r io.Reader) *Reader { return &Reader{opt: opt, stream: r} }

func (r *Reader) notify(f string, a ...any) {
	if r.opt.Notify != nil {
		r.opt.Notify(f, a...)
	}
}

// Run streams records to out until ctx is cancelled (journalctl mode) or
// the stream ends (stream mode). loadCursor returns the last durably
// stored journald cursor, used to resume journalctl across restarts;
// resuming from the stored (acked) cursor is what makes delivery
// at-least-once — a crash re-ships at most one batch, never drops.
func (r *Reader) Run(ctx context.Context, out chan<- model.Record, loadCursor func() string) error {
	if r.stream != nil {
		return r.pump(ctx, r.stream, out)
	}
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return nil
		}
		cursor := ""
		if loadCursor != nil {
			cursor = loadCursor()
		}
		cmd := exec.CommandContext(ctx, "journalctl", r.args(cursor)...)
		cmd.Stderr = os.Stderr
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return err
		}
		if err := cmd.Start(); err != nil {
			return err
		}
		perr := r.pump(ctx, stdout, out)
		_ = cmd.Wait()
		if ctx.Err() != nil {
			return nil
		}
		r.notify("journalctl exited (%v); restarting in %s", perr, backoff)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			if backoff *= 2; backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
		}
	}
}

func (r *Reader) args(cursor string) []string {
	a := []string{"--output=json", "--no-pager", "--follow", "--priority=" + strconv.Itoa(r.opt.Priority)}
	if cursor != "" {
		a = append(a, "--after-cursor="+cursor)
	} else {
		a = append(a, "--lines=0") // first run: start at "now", no history backfill
	}
	return a
}

func (r *Reader) pump(ctx context.Context, src io.Reader, out chan<- model.Record) error {
	br := bufio.NewReaderSize(src, 1<<18)
	for {
		if ctx.Err() != nil {
			return nil
		}
		line, err := br.ReadBytes('\n')
		if len(line) > 0 {
			if rec, ok := r.record(line); ok {
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

func (r *Reader) record(line []byte) (model.Record, bool) {
	if len(strings.TrimSpace(string(line))) == 0 {
		return model.Record{}, false
	}
	var entry map[string]any
	if err := json.Unmarshal(line, &entry); err != nil {
		r.notify("skip unparseable journald line: %v", err)
		return model.Record{}, false
	}
	// Priority floor. journalctl already filters, but a stream (stdin) may not.
	if p, ok := atoi(str(entry, "PRIORITY")); ok && p > r.opt.Priority {
		return model.Record{}, false
	}
	key := firstNonEmpty(str(entry, "_SYSTEMD_UNIT"), str(entry, "SYSLOG_IDENTIFIER"), str(entry, "_COMM"))
	if len(r.opt.Allow) > 0 && !r.opt.Allow[key] {
		return model.Record{}, false
	}
	if r.opt.Deny[key] {
		return model.Record{}, false
	}
	doc := Build(entry, r.opt.Hostname, time.Now(), r.opt.Retention, r.opt.Redact, r.opt.Raw)
	return model.Record{Doc: doc, Cursor: str(entry, "__CURSOR")}, true
}
