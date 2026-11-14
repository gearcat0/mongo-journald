#!/usr/bin/env bash
#
# install.sh — install and start mongo-journald on THIS host. Run as root.
#
#   sudo MONGO_JOURNALD_URI='mongodb://w_syslog:PASS@blue/syslog?authSource=syslog' ./install.sh [path-to-binary]
#
# Idempotent: re-running upgrades the binary + unit and restarts the
# service, and never overwrites an existing /etc/mongo-journald/config.json.
set -euo pipefail

host=$(hostname -s)
here=$(cd "$(dirname "$0")" && pwd)
bin_src=${1:-"$here/mongo-journald"}
uri=${MONGO_JOURNALD_URI:-}

if [[ $EUID -ne 0 ]]; then
	echo "install.sh must run as root" >&2
	exit 1
fi
if [[ ! -x $bin_src ]]; then
	echo "binary not found or not executable: $bin_src (build: go build -o mongo-journald .)" >&2
	exit 1
fi
if [[ -z $uri ]]; then
	echo "set MONGO_JOURNALD_URI to the writer connection string before running" >&2
	exit 1
fi

# dedicated unprivileged service account
if ! id -u mongo-journald >/dev/null 2>&1; then
	useradd --system --no-create-home --shell /usr/sbin/nologin mongo-journald
fi

install -m 0755 "$bin_src" /usr/bin/mongo-journald
install -d -m 0755 /etc/mongo-journald
install -d -o mongo-journald -g mongo-journald -m 0750 /var/lib/mongo-journald

if [[ ! -f /etc/mongo-journald/config.json ]]; then
	install -m 0644 "$here/config_sample.json" /etc/mongo-journald/config.json
fi

# credentials live only here, root-only
umask 077
printf 'MONGO_JOURNALD_URI=%s\n' "$uri" >/etc/mongo-journald/env
chmod 600 /etc/mongo-journald/env

install -m 0644 "$here/mongo-journald.service" /etc/systemd/system/mongo-journald.service
systemctl daemon-reload
systemctl enable --now mongo-journald

echo "[$host] mongo-journald installed; status:"
systemctl --no-pager --lines=0 status mongo-journald || true
