#!/usr/bin/env bash
# install-client.sh — point this host at the mongo-journald apt repo.
# Run as root. Afterwards: apt-get install mongo-journald
#
#   sudo ./install-client.sh
#   sudo REPO_URL=https://apt.satoshi.in.th ./install-client.sh   # override
set -euo pipefail

REPO_URL=${REPO_URL:-https://apt.satoshi.in.th}
KEYRING=/etc/apt/keyrings/mongo-journald-apt.gpg
SOURCES=/etc/apt/sources.list.d/mongo-journald.sources

[ "$(id -u)" -eq 0 ] || {
	echo "run as root" >&2
	exit 1
}

install -d -m 0755 /etc/apt/keyrings

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
if command -v curl >/dev/null 2>&1; then
	curl -fsSL "$REPO_URL/pubkey.asc" -o "$tmp"
else
	wget -qO "$tmp" "$REPO_URL/pubkey.asc"
fi
gpg --dearmor <"$tmp" >"$KEYRING"
chmod 0644 "$KEYRING"

cat >"$SOURCES" <<EOF
X-Repolib-Name: mongo-journald
Types: deb
URIs: $REPO_URL
Suites: stable
Components: main
Architectures: amd64 arm64
Signed-By: $KEYRING
EOF

apt-get update
echo
echo "repo configured. install with:  apt-get install mongo-journald"
