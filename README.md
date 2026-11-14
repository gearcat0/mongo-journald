# mongo-journald

Ships `systemd-journald` logs from an Ubuntu host into MongoDB, using the same schema and TTL
retention as the `mover` daemon's `events` collection — so the same `mongosh` log-sweep flow works
against system logs.

Each journald entry becomes one document:

| field | from | notes |
|---|---|---|
| `at` | `__REALTIME_TIMESTAMP` | UTC `Date` |
| `server` | `_HOSTNAME` (fallback `os.Hostname()`) | tags the originating host |
| `level` | `PRIORITY` → syslog name | emerg, alert, crit, err, warning, notice, info |
| `priority` | `PRIORITY` | numeric 0–7 |
| `source` | `_SYSTEMD_UNIT` → `SYSLOG_IDENTIFIER` → `_COMM` | the emitter |
| `msg` | `MESSAGE` | binary messages are byte-decoded |
| `unit`,`ident`,`pid`,`facility`,`boot` | journald | present when available |
| `expireAt` | `at + retention` | TTL index drops the doc at this time |

Retention is the mover's technique: a `{expireAt:1}` index with `expireAfterSeconds:0`, and the
daemon stamps `expireAt = at + retention` (default **60d**). Change `retention` and only *new* docs
are affected; existing docs keep the `expireAt` they were written with.

## Build

```sh
go build -o mongo-journald .          # on the target box, or cross-compile:
GOOS=linux GOARCH=amd64 go build -o mongo-journald .
```

Pure Go (no cgo), Go 1.27. `journalctl` must be on `PATH` at runtime.

## Configure

`/etc/mongo-journald/config.json` (see `config_sample.json`). The Mongo **URI is not** in this file —
it comes from `MONGO_JOURNALD_URI` so credentials stay out of config:

```
MONGO_JOURNALD_URI=mongodb://w_syslog:PASS@blue/syslog?authSource=syslog
```

Key options: `priority` (syslog floor, default `6` = info and above, drops debug), `retention`
(`60d`/`48h`/`forever`), `redact` (scrub secrets from messages, default `true`),
`units.deny`/`units.allow`, `batch.{size,buffer,flush}`, `rawFields` (keep every journald field under
`fields`; off by default), `hostname` (override the host tag).

### Redaction

With `redact` on (the default), each `MESSAGE` is scrubbed before it leaves the host. It is
conservative — it rewrites only recognised secrets and leaves ordinary log text alone:

- `key=value` / `key: value` where the key is a credential name (`password`, `token`, `api_key`,
  `secret`, `authorization`, `passphrase`, `signature`, `session`, `cookie`, …) → value becomes `REDACTED`
- URL credentials: `scheme://user:pass@host` → `scheme://REDACTED@host`
- `Bearer`/`Basic <token>` → `Bearer REDACTED`
- a whole-line JSON object has its secret keys redacted structurally

Note: `rawFields` keeps the full journald field set unredacted, so leave `redact` on if you enable it,
and prefer not enabling `rawFields` on hosts with sensitive logs.

## Run / deploy

Per box, as root:

```sh
sudo MONGO_JOURNALD_URI='mongodb://w_syslog:PASS@blue/syslog?authSource=syslog' ./install.sh
```

`install.sh` creates the `mongo-journald` service user (in group `systemd-journal` for journal read),
installs the binary to `/usr/bin`, drops the config and a root-only `env` file, installs
`mongo-journald.service` (`Restart=always`, hardened), and `enable --now`s it. First run starts at
"now" (no history backfill); restarts resume from the saved cursor (`/var/lib/mongo-journald/cursor`)
for at-least-once delivery.

To roll out across hosts, run `install.sh` on each (e.g. from a root loop in the house
`check_nvm_bun.sh` style), or build a `.deb` and install that (below).

## Packaging (`.deb`)

For fleet rollout, build Debian packages instead of running `install.sh` per host.
[GoReleaser](https://goreleaser.com) (`.goreleaser.yaml`) is the single source of truth for packaging:
it cross-compiles static binaries for **amd64 + arm64** and wraps each in a `.deb` (plus a raw-binary
`.tar.gz` and a `checksums.txt`).

**Releases are tag-driven.** Push a semver tag and GitHub Actions (`.github/workflows/release.yml`)
runs GoReleaser and attaches the artifacts to a GitHub Release — no copying from a build box:

```sh
git tag v0.2.0 && git push origin v0.2.0
```

**Local build** (same config, snapshot version) needs only GoReleaser
(`go install github.com/goreleaser/goreleaser/v2@latest`):

```sh
make deb     # -> dist/*.deb  (amd64 + arm64)   [goreleaser release --snapshot]
make check   # validate .goreleaser.yaml
make test    # vet, gofmt, unit tests
```

The package installs the binary to `/usr/bin`, the unit to `/lib/systemd/system`, and `config.json`
to `/etc/mongo-journald` (a dpkg **conffile** — local edits survive upgrades). The Mongo URI is **not**
in the package: `postinst` writes a root-only `0600` `/etc/mongo-journald/env` placeholder (only if
absent), creates the service user and state dir, and **enables but does not start** the unit. So the
per-host flow is install → set URI → start:

```sh
sudo apt install ./mongo-journald_0.2.0_linux_amd64.deb   # or: sudo dpkg -i …
sudoedit /etc/mongo-journald/env                         # set MONGO_JOURNALD_URI=…
sudo systemctl start mongo-journald
```

Upgrades (install a newer `.deb`) keep the existing `env` and config and restart the service in place
only if it was already running. `apt purge` removes the env, state dir, and service user; `apt remove`
leaves config for a later purge.

Packaging files: `.goreleaser.yaml` (build + package metadata), `debian/{postinst,prerm,postrm}` (the
install steps, mirroring `install.sh` minus the secret), `.github/workflows/{ci,release}.yml` (CI runs
tests + a snapshot package on every push/PR; release fires on a `v*` tag). A signed apt repo for
`apt update && apt install mongo-journald` is the natural follow-on.

## One-time MongoDB setup on `blue`

Create the DB and a least-privilege writer (auth source = the app DB, mirroring `r_mover`):

```js
use syslog
db.createUser({ user: "w_syslog", pwd: "PASS", roles: [{ role: "readWrite", db: "syslog" }] })
// optional read-only analyst account:
db.createUser({ user: "r_syslog", pwd: "PASS2", roles: [{ role: "read", db: "syslog" }] })
```

Indexes (TTL + lookups) are created by the daemon at startup — no provisioning step needed.

**Security:** system logs can contain usernames, IPs, command lines and occasional secrets, and they
plus the Mongo credentials cross the network to `blue`. Enable TLS on `mongod`, require auth, and
firewall it to the tailnet. Consider shortening `retention` for auth-heavy hosts.

## Verify

```sh
# 1. field mapping, no Mongo needed:
journalctl -o json -n 50 | ./mongo-journald --dry-run --stdin

# 2. one host → blue, then in mongosh:
mongosh "mongodb://r_syslog:PASS2@blue/syslog?authSource=syslog" --eval '
  printjson(db.events.getIndexes());                 // expect expireAt_ttl (expireAfterSeconds:0)
  printjson(db.events.find().sort({at:-1}).limit(1).toArray());
'

# 3. resume / no-dup:
sudo systemctl stop mongo-journald
logger "mongo-journald-test $RANDOM"
sudo systemctl start mongo-journald
# the line should appear exactly once

# 4. multi-host sweep (like the mover flow):
# db.events.aggregate([{$match:{level:{$in:["err","crit","alert","emerg"]}}},
#                      {$group:{_id:"$server", n:{$sum:1}}}, {$sort:{n:-1}}])
```

## Layout

```
main.go            flags, wiring, graceful shutdown, cursor persistence
config.go          config + ParseRetention (60d/forever syntax)
internal/journal/  reader.go (journalctl --follow + resume), doc.go (journald→doc), doc_test.go
internal/store/    store.go (Open + ensure TTL/lookup indexes), sink.go (batch/backpressure/retry)
internal/redact/   redact.go (scrub secrets from messages), redact_test.go
internal/model/    Doc + Record
mongo-journald.service, install.sh, config_sample.json
.goreleaser.yaml, debian/{postinst,prerm,postrm}, Makefile, .github/workflows/  (.deb packaging + CI)
```
