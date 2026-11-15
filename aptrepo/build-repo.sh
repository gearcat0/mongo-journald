#!/usr/bin/env bash
# build-repo.sh — build and GPG-sign a flat apt repository from .deb files.
#
#   aptrepo/build-repo.sh <outdir> <deb-dir> [more-deb-dirs...]
#
# Stateless: the whole dists/ index is regenerated from the pooled .debs on
# every run, so it is safe to run in CI with no persisted database. The
# output tree (pool/ + dists/) is what gets synced to Cloudflare R2.
#
# Metadata + signing via env:
#   ORIGIN, LABEL, SUITE, COMPONENT, ARCHES, DESCRIPTION
#   GPG_KEY_ID      key to sign with (default: gpg's first secret key)
#   GPG_PASSPHRASE  optional; enables loopback signing for a protected key
set -euo pipefail

OUT=${1:?usage: build-repo.sh <outdir> <deb-dir>...}
shift
[ "$#" -ge 1 ] || { echo "need at least one deb dir" >&2; exit 1; }

ORIGIN=${ORIGIN:-satoshi.in.th}
LABEL=${LABEL:-mongo-journald}
SUITE=${SUITE:-stable}
COMPONENT=${COMPONENT:-main}
ARCHES=${ARCHES:-amd64 arm64}
DESCRIPTION=${DESCRIPTION:-mongo-journald apt repository}

rm -rf "$OUT"
mkdir -p "$OUT/pool/$COMPONENT"

# Pool the .debs at pool/<component>/<first-letter>/<pkg>/<file>.deb
shopt -s nullglob
found=0
for d in "$@"; do
	for deb in "$d"/*.deb; do
		pkg=$(dpkg-deb -f "$deb" Package)
		first=$(printf '%s' "$pkg" | cut -c1)
		dest="$OUT/pool/$COMPONENT/$first/$pkg"
		mkdir -p "$dest"
		cp -f "$deb" "$dest/"
		found=$((found + 1))
	done
done
[ "$found" -gt 0 ] || {
	echo "no .deb files found in: $*" >&2
	exit 1
}
echo "pooled $found package file(s)"

cd "$OUT"

# Per-arch Packages indexes (-m keeps every version so apt install pkg=ver works)
for arch in $ARCHES; do
	dir="dists/$SUITE/$COMPONENT/binary-$arch"
	mkdir -p "$dir"
	dpkg-scanpackages -a "$arch" -m pool /dev/null >"$dir/Packages" 2>/dev/null
	gzip -9kf "$dir/Packages"
	cat >"$dir/Release" <<EOF
Archive: $SUITE
Component: $COMPONENT
Origin: $ORIGIN
Label: $LABEL
Architecture: $arch
EOF
done

# Top-level Release with checksums over the indexes. No Valid-Until, so an
# infrequently-updated repo never shows up as "expired".
apt-ftparchive \
	-o "APT::FTPArchive::Release::Origin=$ORIGIN" \
	-o "APT::FTPArchive::Release::Label=$LABEL" \
	-o "APT::FTPArchive::Release::Suite=$SUITE" \
	-o "APT::FTPArchive::Release::Codename=$SUITE" \
	-o "APT::FTPArchive::Release::Architectures=$ARCHES" \
	-o "APT::FTPArchive::Release::Components=$COMPONENT" \
	-o "APT::FTPArchive::Release::Description=$DESCRIPTION" \
	release "dists/$SUITE" >"dists/$SUITE/Release"

# Sign: clearsigned InRelease + detached Release.gpg
gpgargs=(--batch --yes --armor)
[ -n "${GPG_KEY_ID:-}" ] && gpgargs+=(--local-user "$GPG_KEY_ID")
if [ -n "${GPG_PASSPHRASE:-}" ]; then
	gpgargs+=(--pinentry-mode loopback --passphrase "$GPG_PASSPHRASE")
fi
gpg "${gpgargs[@]}" --clearsign -o "dists/$SUITE/InRelease" "dists/$SUITE/Release"
gpg "${gpgargs[@]}" --detach-sign -o "dists/$SUITE/Release.gpg" "dists/$SUITE/Release"

echo "signed repo built in $OUT (suite=$SUITE, component=$COMPONENT, arches: $ARCHES)"
