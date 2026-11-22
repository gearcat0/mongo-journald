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
MONGO_JOURNALD_URI=mongodb://w_syslog:PASS@MONGO_HOST/syslog?authSource=syslog
```

Key options (journal mode): `priority` (syslog floor, default `6` = info and above, drops debug), `retention`
(`60d`/`48h`/`forever`), `redact` (scrub secrets from messages, default `true`),
`units.deny`/`units.allow`, `batch.{size,buffer,flush}`, `rawFields` (keep every journald field under
`fields`; off by default), `hostname` (override the host tag). The `dns` and `flows` sections configure
the optional modes ([below](#dns-lookups-and-network-flows-optional)).

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

## Installed packages (on by default)

The journal service also keeps an inventory of the host's installed packages in the `packages`
collection, for checking patch levels across the fleet. It needs no extra privileges or unit, and it
is **on unless the config says otherwise**, so existing hosts start reporting as soon as they run a
version that has it.

Source: `dpkg-query -W -f=…`, the tab-separated form of `dpkg -l`. Unlike the log collections,
`packages` holds current state: one document per installed package per host. The service scans at
startup, within a minute of any change to `/var/lib/dpkg/status` (so right after an `apt upgrade`),
and at least every `interval`. Each scan upserts what is installed and deletes that host's documents
for packages that are gone or were superseded by a new version.

| field | notes |
|---|---|
| `server`, `name`, `arch`, `version` | the document key (unique index) |
| `source` | source package name, which is what USNs and CVE trackers are filed against |
| `status` | `installed`, or `config-files` (removed, not purged), `half-installed`, `unpacked`, … |
| `hold` | `true` when the package is held back (`apt-mark hold`) |
| `since` | when this host was first seen with this version (first scan, or the upgrade) |
| `at` | the host's last successful scan |
| `expireAt` | `at + retention`; a host that stops reporting ages out |

Config, all optional:

```json
"packages": { "enabled": true, "collection": "packages", "interval": "1h", "retention": "14d" }
```

`retention` must be at least twice `interval`. Hosts without `dpkg-query` log one line and skip the
inventory. `mongo-journald --mode packages` runs a single scan and exits; add `--dry-run` to print the
documents instead of writing them.

```js
// versions of one package across the fleet
db.packages.find({name: "openssl", status: "installed"}, {_id: 0, server: 1, version: 1, since: 1})
// packages whose version differs between hosts
db.packages.aggregate([{$match: {status: "installed"}},
  {$group: {_id: {n: "$name", a: "$arch"}, versions: {$addToSet: "$version"}, hosts: {$push: {s: "$server", v: "$version"}}}},
  {$match: {"versions.1": {$exists: true}}}])
// what changed in the last day (upgrades and new installs)
db.packages.find({since: {$gte: new Date(Date.now() - 864e5)}}, {_id: 0, server: 1, name: 1, version: 1, since: 1})
// held packages, and hosts whose inventory is stale
db.packages.find({hold: true}, {_id: 0, server: 1, name: 1, version: 1})
db.packages.aggregate([{$group: {_id: "$server", at: {$max: "$at"}, n: {$sum: 1}}}, {$sort: {at: 1}}])
```

## DNS lookups and network flows (optional)

Two more modes of the same binary ship network telemetry into their own collections in the same
database. Each runs as its own systemd unit, installed **disabled** because both need privileges and
produce far more data than syslog:

```sh
sudo systemctl enable --now mongo-journald-dns mongo-journald-flows   # uses the same env file
```

Each mode writes **raw** documents (default retention `3d`) and **hourly rollups** (default `60d`).
The rollups are per-host `$inc` counters that the daemon upserts every minute, so summaries outlive the
raw data. Neither mode has a resume cursor: whatever happens while a unit is stopped is not recorded.

### `--mode dns` → `dns`, `dns_hourly`

Source: `resolvectl monitor --json=short`, systemd-resolved's stream of every lookup it answers,
cache hits included. Needs systemd ≥ 254 (the fleet runs 255/259). The unit runs as **root, keeping
only `CAP_DAC_OVERRIDE`**: resolved's monitor only answers root, and its socket is owned by
`systemd-resolve`.

| field | notes |
|---|---|
| `at`, `server`, `expireAt` | as for events |
| `qname`, `qtype` | lowercased, no trailing dot; `A`, `AAAA`, `MX`, … |
| `state` | resolved's result: `success`, `rcode-failure`, `timeout`, `no-servers`, … |
| `rcode` | `NOERROR` on success, else the server's rcode (`NXDOMAIN`, `SERVFAIL`, …) |
| `answers` | `[{name, type, data, ttl}]` (decoded from the wire-format RR) |
| `cname` | first CNAME target, when there is one |

`dns_hourly`: `{server, hour, qname, qtype, rcode, n}`. Failed lookups other than rcode failures use
the `state` as the `rcode`.

Gaps: resolved doesn't record *which process* asked. Programs that query a DNS server directly
(bypassing `127.0.0.53`) are not seen here, but their port-53 traffic shows up in `flows`. Config:
`dns.ignore` lists name suffixes to drop (e.g. `"ts.net"`).

### `--mode flows` → `flows`, `flows_hourly`

Source: the kernel's conntrack NEW/DESTROY netlink events. Each document is one **finished**
connection (TCP, UDP or ICMP), written when conntrack destroys the entry. A connection that stays open
for days is only written once it closes. The unit runs as root with
`CAP_NET_ADMIN CAP_SYS_PTRACE CAP_DAC_READ_SEARCH`. Before starting it loads `nf_conntrack` and sets
`net.netfilter.nf_conntrack_acct=1` (byte/packet counters) and `nf_conntrack_timestamp=1` (start/stop
times), but only on hosts that run this unit.

| field | notes |
|---|---|
| `at`, `start`, `dur_ms` | end time, start time, duration |
| `dir` | `out` (this host initiated), `in` (to a local socket), `fwd` (routed/NATed, e.g. containers) |
| `proto`, `src`, `sport`, `dst`, `dport` | the original (initiator → responder) tuple |
| `peer`, `port` | the remote IP and the service port (`dport`), for easy querying |
| `tx_bytes`, `rx_bytes`, `tx_pkts`, `rx_pkts` | from this host's side (`fwd`: tx = initiator → responder) |
| `replied`, `tcp_state`, `nat`, `icmp_type`/`icmp_code` | final TCP state (`SYN_SENT` = never answered), etc. |
| `proc` | `{pid, comm, exe, uid, unit}` of the local process that owns the socket — best effort |

**Process attribution.** Conntrack does not know which process owns a connection, so the daemon finds
out when the flow is NEW. Every 100 ms it matches pending flows to sockets via `sock_diag`: first the
exact 4-tuple, then a listener or unbound UDP socket on the local port. It then maps the socket inode
to a pid using a cache built from `/proc/*/fd`, rescanned on a miss at most every 500 ms, and reads
`comm`, `exe` and the systemd unit from `/proc/<pid>`. Connections that close before the next round,
forwarded traffic and ICMP get no `proc`. Inbound flows are attributed to the accepted socket's owner,
or to the listener (the server's main process) if the socket hasn't been accepted yet. Every 10 minutes
the daemon logs what share of local flows got a process. Set `flows.proc: false` to turn this off.

`flows_hourly`: `{server, hour, dir, proto, peer, port, comm, unit, flows, tx_bytes, rx_bytes}`.

Config: `flows.ignore.cidrs` (drop flows with either endpoint inside), `flows.ignore.ports` (drop
flows to these service ports), and `flows.includeLoopback` (default `false`).

Volume: expect far more documents than `events`. Busy hosts make thousands of short connections an
hour, and Tailscale keeps many UDP flows alive. Check the rate on one host before rolling out, and use
`ignore` for noise you will never query.

### Queries

```js
// who resolved a name, and when
db.dns.find({qname: /(^|\.)example\.com$/}).sort({at: -1}).limit(20)
// top domains per host, last 7 days (rollups)
db.dns_hourly.aggregate([{$match: {hour: {$gte: new Date(Date.now() - 7*864e5)}}},
  {$group: {_id: {s: "$server", q: "$qname"}, n: {$sum: "$n"}}}, {$sort: {n: -1}}, {$limit: 20}])
// which process talked to an IP
db.flows.find({peer: "203.0.113.9"}, {at: 1, server: 1, dir: 1, port: 1, proc: 1})
// top talkers by bytes out, per process, last 24h
db.flows_hourly.aggregate([{$match: {hour: {$gte: new Date(Date.now() - 864e5)}, dir: "out"}},
  {$group: {_id: {s: "$server", comm: "$comm", peer: "$peer"}, tx: {$sum: "$tx_bytes"}}}, {$sort: {tx: -1}}, {$limit: 20}])
// outbound DNS that bypassed resolved
db.flows.find({port: 53, dir: "out", "proc.comm": {$ne: "systemd-resolve"}})
```

## Run / deploy

Per box, as root:

```sh
sudo MONGO_JOURNALD_URI='mongodb://w_syslog:PASS@MONGO_HOST/syslog?authSource=syslog' ./install.sh
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
tests + a snapshot package on every push/PR; release fires on a `v*` tag).

### apt repo (recommended for fleets)

A public signed apt repo at **https://apt.satoshi.in.th** (static files on Cloudflare R2, rebuilt and
signed by CI on every release) gives hosts the simplest path — `apt install` + `apt upgrade`. The
steps below assume nothing on the host but a working `apt`: no checked-out repo, and no `gnupg` (the
signing key is stored armored and apt reads it directly).

```sh
# 1. prerequisites (usually already present on Ubuntu; a no-op if so)
sudo apt-get update
sudo apt-get install -y ca-certificates curl

# 2. install the repo signing key (armored .asc — apt reads it directly, no gnupg)
sudo install -d -m 0755 /etc/apt/keyrings
sudo curl -fsSL https://apt.satoshi.in.th/pubkey.asc -o /etc/apt/keyrings/mongo-journald.asc

# 3. register the repo (one printf, no heredoc — pastes cleanly over SSH)
printf '%s\n' 'Types: deb' 'URIs: https://apt.satoshi.in.th' 'Suites: stable' 'Components: main' 'Architectures: amd64 arm64' 'Signed-By: /etc/apt/keyrings/mongo-journald.asc' | sudo tee /etc/apt/sources.list.d/mongo-journald.sources >/dev/null

# 4. install
sudo apt-get update
sudo apt-get install -y mongo-journald
```

Then set the Mongo URI and start it (the package installs enabled-but-stopped):

```sh
sudoedit /etc/mongo-journald/env       # set MONGO_JOURNALD_URI=…
sudo systemctl start mongo-journald
```

Upgrades ride along with the host's normal `apt upgrade`. Repo setup, signing, and the publish
pipeline are documented in [`aptrepo/README.md`](aptrepo/README.md).

## One-time MongoDB setup (on the Mongo host)

Create the DB and a least-privilege writer (auth source = the app DB, mirroring `r_mover`):

```js
use syslog
db.createUser({ user: "w_syslog", pwd: "PASS", roles: [{ role: "readWrite", db: "syslog" }] })
// optional read-only analyst account:
db.createUser({ user: "r_syslog", pwd: "PASS2", roles: [{ role: "read", db: "syslog" }] })
```

Indexes (TTL + lookups) are created by the daemon at startup — no provisioning step needed.

**Security:** system logs can contain usernames, IPs, command lines and occasional secrets, and they
plus the Mongo credentials cross the network to the Mongo host. Enable TLS on `mongod`, require auth, and
firewall it to the tailnet. Consider shortening `retention` for auth-heavy hosts. The `dns` and `flows` collections are a
browsing and connection history of every host (names looked up, peers, owning processes), so treat
read access to them, including `r_syslog`, as sensitive.

## Verify

```sh
# 1. field mapping, no Mongo needed:
journalctl -o json -n 50 | ./mongo-journald --dry-run --stdin

# 2. one host → the Mongo host, then in mongosh:
mongosh "mongodb://r_syslog:PASS2@MONGO_HOST/syslog?authSource=syslog" --eval '
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
main.go            flags (--mode), wiring, graceful shutdown, cursor persistence, --mode packages
stream.go          --mode dns|flows wiring: sink + hourly rollup
config.go          config (+ dns/flows sections) + ParseRetention (60d/forever syntax)
internal/journal/  reader.go (journalctl --follow + resume), doc.go (journald→doc), doc_test.go
internal/dns/      reader.go (resolvectl monitor), doc.go (monitor JSON→doc), testdata/
internal/flows/    conntrack.go (netlink events, filter), doc.go (flow→doc), attrib.go + procfs.go (process attribution)
internal/packages/ packages.go (dpkg-query → upsert current packages, drop stale ones)
internal/rollup/   rollup.go (hourly $inc upserts)
internal/store/    store.go (Open + ensure TTL/lookup indexes), sink.go (batch/backpressure/retry)
internal/redact/   redact.go (scrub secrets from messages), redact_test.go
internal/model/    Doc + Record
mongo-journald.service, mongo-journald-{dns,flows}.service, install.sh, config_sample.json
.goreleaser.yaml, debian/{postinst,prerm,postrm}, Makefile, .github/workflows/  (.deb packaging + CI)
```
