// Package packages ships the host's installed Debian packages to Mongo so
// patch levels can be compared across the fleet.
//
// Unlike the log collections this one holds current state, not a stream:
// one document per {server, name, arch, version}. Each scan upserts what
// is installed and deletes this host's documents that the scan no longer
// saw, so a version change replaces the old document. expireAt is
// refreshed on every scan, so a host that stops reporting ages out.
//
// Each scan also writes one document about the host itself (OS release,
// running kernel, boot time, reboot-required) to a second collection.
package packages

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"mongo-journald/internal/model"
	"mongo-journald/internal/store"
)

// queryFormat is the machine-readable equivalent of `dpkg -l`: one
// package per line, tab-separated. dpkg-query expands the \t and \n
// escapes itself. Reading the dpkg database needs no privileges.
const queryFormat = `${Package}\t${Architecture}\t${Version}\t${source:Package}\t${db:Status-Want}\t${db:Status-Status}\n`

// statusFile changes whenever dpkg installs, upgrades or removes
// something; its mtime triggers a rescan.
const statusFile = "/var/lib/dpkg/status"

// keyFields identify a document. version is part of the key so that an
// upgrade inserts a new document, whose since is when it was first seen.
var keyFields = bson.D{{Key: "server", Value: 1}, {Key: "name", Value: 1}, {Key: "arch", Value: 1}, {Key: "version", Value: 1}}

// Package is one row of the dpkg database.
type Package struct {
	Name    string
	Arch    string
	Version string
	Source  string // source package (what security notices are filed against)
	Status  string // installed, config-files, half-installed, unpacked, …
	Hold    bool   // held back from upgrades (apt-mark hold)
}

// List runs dpkg-query and returns every package dpkg knows about.
func List(ctx context.Context) ([]Package, error) {
	cmd := exec.CommandContext(ctx, "dpkg-query", "-W", "-f="+queryFormat)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("dpkg-query: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return Parse(bytes.NewReader(out))
}

// Parse reads dpkg-query output in queryFormat. Packages that are known
// but not installed (purged, or only ever seen as available) are skipped.
func Parse(r io.Reader) ([]Package, error) {
	var pkgs []Package
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 6 || f[0] == "" {
			return nil, fmt.Errorf("unexpected dpkg-query line %q", line)
		}
		if f[5] == "not-installed" {
			continue
		}
		pkgs = append(pkgs, Package{Name: f[0], Arch: f[1], Version: f[2], Source: f[3], Status: f[5], Hold: f[4] == "hold"})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(pkgs) == 0 {
		return nil, errors.New("dpkg-query listed no packages")
	}
	return pkgs, nil
}

// Doc is the document for one package as of the scan at time at. It does
// not carry since, which is set only when the document is first inserted.
func Doc(p Package, host string, at time.Time, retention time.Duration) model.Doc {
	d := model.Doc{
		"server":  host,
		"name":    p.Name,
		"arch":    p.Arch,
		"version": p.Version,
		"source":  p.Source,
		"status":  p.Status,
		"hold":    p.Hold,
		"at":      at,
	}
	if retention > 0 {
		d["expireAt"] = at.Add(retention)
	}
	return d
}

// Options configures a Syncer.
type Options struct {
	Collection string
	HostColl   string // one doc per server with OS release and kernel; "" = don't write it
	Hostname   string
	Interval   time.Duration // rescan at least this often, even if nothing changed
	Retention  time.Duration // a host's docs expire this long after its last scan; 0 = never
	Notify     func(string, ...any)
}

// Syncer keeps one host's documents in the packages collection current.
type Syncer struct {
	db     *mongo.Database
	opt    Options
	first  bool
	noDpkg bool // no dpkg-query here: only the host document is written
}

func NewSyncer(db *mongo.Database, opt Options) *Syncer {
	return &Syncer{db: db, opt: opt, first: true}
}

func (s *Syncer) notify(f string, a ...any) {
	if s.opt.Notify != nil {
		s.opt.Notify(f, a...)
	}
}

// EnsureIndexes creates the TTL index, the unique key and a by-name
// lookup index, plus the TTL index and unique server key of the host
// collection. Idempotent.
func (s *Syncer) EnsureIndexes(ctx context.Context) error {
	if s.opt.HostColl != "" {
		if err := store.EnsureIndexes(ctx, s.db, s.opt.HostColl); err != nil {
			return err
		}
		if _, err := s.db.Collection(s.opt.HostColl).Indexes().CreateOne(ctx, mongo.IndexModel{
			Keys: bson.D{{Key: "server", Value: 1}}, Options: options.Index().SetUnique(true).SetName("host_key"),
		}); err != nil {
			return fmt.Errorf("%s: %w", s.opt.HostColl, err)
		}
	}
	if err := store.EnsureIndexes(ctx, s.db, s.opt.Collection, bson.D{{Key: "name", Value: 1}, {Key: "version", Value: 1}}); err != nil {
		return err
	}
	_, err := s.db.Collection(s.opt.Collection).Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: keyFields, Options: options.Index().SetUnique(true).SetName("package_key"),
	})
	return err
}

// Run scans at startup, then whenever the dpkg status file changes
// (checked once a minute) or Interval has passed, until ctx is done. A
// failed scan is retried on the next check.
func (s *Syncer) Run(ctx context.Context) {
	if _, err := exec.LookPath("dpkg-query"); err != nil {
		s.notify("packages: dpkg-query not found; package inventory is off")
		s.noDpkg = true
		if s.opt.HostColl == "" {
			return
		}
	}
	ictx, cancel := context.WithTimeout(ctx, time.Minute)
	if err := s.EnsureIndexes(ictx); err != nil {
		s.notify("packages: ensure indexes on %s: %v (continuing)", s.opt.Collection, err)
	}
	cancel()

	t := time.NewTicker(time.Minute)
	defer t.Stop()
	var lastOK, lastMod time.Time
	failures := 0
	for {
		// Read the mtime before scanning: a change during the scan then
		// differs from lastMod and triggers another one.
		mod := statusMtime()
		if lastOK.IsZero() || time.Since(lastOK) >= s.opt.Interval || !mod.Equal(lastMod) {
			if err := s.Sync(ctx); err == nil {
				lastOK, lastMod, failures = time.Now(), mod, 0
			} else if ctx.Err() == nil {
				// retried every minute; don't log every attempt of a long outage
				if failures++; failures == 1 || failures%60 == 0 {
					s.notify("packages: scan failed (attempt %d, retrying each minute): %v", failures, err)
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func statusMtime() time.Time {
	fi, err := os.Stat(statusFile)
	if err != nil {
		return time.Time{}
	}
	return fi.ModTime()
}

// Sync does one scan: replace the host document, upsert every package,
// then delete this host's package documents the scan did not touch
// (removed packages and old versions).
func (s *Syncer) Sync(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	// Mongo dates have millisecond precision; truncate so the stale
	// filter below compares against exactly what was stored.
	at := time.Now().UTC().Truncate(time.Millisecond)

	if s.opt.HostColl != "" {
		_, err := s.db.Collection(s.opt.HostColl).ReplaceOne(ctx,
			bson.D{{Key: "server", Value: s.opt.Hostname}},
			HostDoc(s.opt.Hostname, at, s.opt.Retention),
			options.Replace().SetUpsert(true))
		if err != nil {
			return fmt.Errorf("write host doc to %s: %w", s.opt.HostColl, err)
		}
	}
	if s.noDpkg {
		return nil
	}

	pkgs, err := List(ctx)
	if err != nil {
		return err
	}

	ops := make([]mongo.WriteModel, 0, len(pkgs))
	for _, p := range pkgs {
		set := Doc(p, s.opt.Hostname, at, s.opt.Retention)
		filter := bson.D{}
		for _, k := range keyFields {
			filter = append(filter, bson.E{Key: k.Key, Value: set[k.Key]})
			delete(set, k.Key)
		}
		update := bson.D{{Key: "$set", Value: set}, {Key: "$setOnInsert", Value: bson.D{{Key: "since", Value: at}}}}
		if s.opt.Retention <= 0 {
			update = append(update, bson.E{Key: "$unset", Value: bson.D{{Key: "expireAt", Value: ""}}})
		}
		ops = append(ops, mongo.NewUpdateOneModel().SetFilter(filter).SetUpdate(update).SetUpsert(true))
	}

	coll := s.db.Collection(s.opt.Collection)
	res, err := coll.BulkWrite(ctx, ops, options.BulkWrite().SetOrdered(false))
	if err != nil {
		// Leave the stale documents alone: they are still the best
		// record of this host until a scan fully succeeds.
		return fmt.Errorf("upsert %d packages: %w", len(pkgs), err)
	}
	del, err := coll.DeleteMany(ctx, bson.D{
		{Key: "server", Value: s.opt.Hostname},
		{Key: "at", Value: bson.D{{Key: "$lt", Value: at}}},
	})
	if err != nil {
		return fmt.Errorf("delete stale packages: %w", err)
	}

	if s.first || res.UpsertedCount > 0 || del.DeletedCount > 0 {
		s.notify("packages: %d listed → %s; %d new or changed, %d dropped (removed or superseded)",
			len(pkgs), s.opt.Collection, res.UpsertedCount, del.DeletedCount)
	}
	s.first = false
	return nil
}
