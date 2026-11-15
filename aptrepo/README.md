# Public apt repo (Cloudflare R2)

A signed Debian repository for `mongo-journald`, served publicly at
**https://apt.satoshi.in.th** so any host can `apt install mongo-journald` and
`apt upgrade` it. The repo is **static files on Cloudflare R2**; GitHub Actions
rebuilds and GPG-signs it on every release and syncs it to R2. There is no
server to maintain, and the **signing private key lives only in Actions
secrets** — never on an internet-facing host.

Security model: trust comes from the **GPG signature** on the repo index, not
from TLS. apt verifies the signed `InRelease` against the public key each host
holds, so even plain HTTP would be safe for integrity; HTTPS (free via
Cloudflare) is just polish.

```
apt.satoshi.in.th/
  pubkey.asc                      public signing key (clients fetch this)
  dists/stable/
    InRelease, Release, Release.gpg
    main/binary-amd64/Packages{,.gz}
    main/binary-arm64/Packages{,.gz}
  pool/main/m/mongo-journald/*.deb
```

## One-time setup

### 1. Signing key

```sh
aptrepo/gen-signing-key.sh          # run locally, once
```

It prints the **fingerprint** (record it below), writes `aptrepo/pubkey.asc`,
and prints the armored **private** key. The key has no passphrase so CI can
sign unattended.

> Fingerprint: `____________________`  ← fill in after generating

### 2. Cloudflare R2 bucket + custom domain

In the Cloudflare dashboard (the `satoshi.in.th` zone is already there):

1. **R2 → Create bucket**, e.g. `apt-satoshi`.
2. Bucket → **Settings → Custom Domains → Connect Domain** → `apt.satoshi.in.th`.
   Cloudflare adds the DNS record and provisions the TLS cert automatically.
3. **R2 → Manage R2 API Tokens → Create** an **Object Read & Write** token
   scoped to this bucket. Note the **Access Key ID**, **Secret Access Key**,
   and your **Account ID** (shown in the R2 endpoint
   `https://<ACCOUNT_ID>.r2.cloudflarestorage.com`).

### 3. GitHub Actions secrets (in an Environment)

These are **environment** secrets, not repository secrets, so the signing key
can only be used from release refs. On `gearcat0/mongo-journald` → Settings →
**Environments → New environment** → name it **`release`**, then:

- **Deployment branches and tags → Selected** → add `v*` and `master`. This is
  the point of using an environment: the `apt-publish` job declares
  `environment: release` (see `release.yml`), so the signing key is reachable
  only from a `v*` tag push or a `master` `workflow_dispatch`, never from an
  arbitrary branch or PR.
- *(optional)* **Required reviewers** → adds a manual approval gate before each
  publish. Leave off for hands-free tag releases; turn on if you want to click
  to approve every push to the public repo.
- Add the secrets under this environment (Environment secrets → Add secret):

| secret | value |
|---|---|
| `APT_GPG_PRIVATE_KEY` | the armored private key block from step 1 |
| `APT_GPG_PASSPHRASE` | leave empty (the key has none) |
| `R2_ACCOUNT_ID` | Cloudflare account id |
| `R2_BUCKET` | the bucket name, e.g. `apt-satoshi` |
| `R2_ACCESS_KEY_ID` | R2 token access key id |
| `R2_SECRET_ACCESS_KEY` | R2 token secret access key |

`R2_ACCOUNT_ID` and `R2_BUCKET` aren't truly secret (the account id is in the
public R2 endpoint, the bucket is just a name) — fine to keep here, or make them
environment *variables* instead. The four that matter are the GPG key, its
passphrase, and the two R2 keys.

### 4. First publish

The repo is published by the `apt-publish` job in
`.github/workflows/release.yml`. It runs after every tagged release, and can be
run on its own from the **Actions → release → Run workflow** button
(`workflow_dispatch`) to back-fill from existing releases. Since `v0.1.0` was
tagged before this job existed, trigger one manual run now to populate the repo
with it. Thereafter `git tag vX.Y.Z && git push` publishes automatically.

The job: imports the key → downloads every release's `.deb` → `build-repo.sh`
rebuilds and signs the index → `aws s3 sync` pushes `pool/` (cached immutably)
and `dists/` + `pubkey.asc` (no-cache, so new releases appear at once) to R2.

## Install on a host

```sh
curl -fsSL https://apt.satoshi.in.th/aptrepo/install-client.sh | sudo bash   # if you mirror this script, or:
sudo REPO_URL=https://apt.satoshi.in.th aptrepo/install-client.sh
```

Or by hand:

```sh
sudo install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://apt.satoshi.in.th/pubkey.asc | sudo gpg --dearmor -o /etc/apt/keyrings/mongo-journald-apt.gpg
sudo tee /etc/apt/sources.list.d/mongo-journald.sources >/dev/null <<'EOF'
Types: deb
URIs: https://apt.satoshi.in.th
Suites: stable
Components: main
Architectures: amd64 arm64
Signed-By: /etc/apt/keyrings/mongo-journald-apt.gpg
EOF
sudo apt-get update
sudo apt-get install mongo-journald
```

Then set the URI and start it (the package installs enabled-but-stopped):

```sh
sudoedit /etc/mongo-journald/env      # MONGO_JOURNALD_URI=…
sudo systemctl start mongo-journald
```

Upgrades come with the host's normal `apt upgrade`. Verify the key out-of-band
against the fingerprint above if you want to be strict.

## Local build / debugging

`build-repo.sh` is the same tool CI uses, so you can build the exact repo tree
locally (needs `apt-utils` + `dpkg-dev`):

```sh
mkdir incoming && gh release download v0.1.0 --pattern '*.deb' --dir incoming
GPG_KEY_ID=<fpr> aptrepo/build-repo.sh out incoming
# then serve ./out over any static server and point a test host at it
```

## Notes / follow-ons

- **Cache:** `dists/` and `pubkey.asc` are uploaded `no-cache` so clients always
  see the newest signed index; `.deb`s in `pool/` are immutable and cached hard.
  If an update ever looks stale, purge the Cloudflare cache for `/dists/*`.
- **Multiple versions** are kept (`dpkg-scanpackages -m`), so `apt install
  mongo-journald=0.1.0` still works after newer releases ship.
- This repo currently hosts one package; the same layout takes more packages
  later (drop their `.deb`s into the `incoming` set).
