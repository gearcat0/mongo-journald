#!/usr/bin/env bash
# gen-signing-key.sh — generate a dedicated GPG signing key for the apt repo.
#
# Run this LOCALLY, once (not in CI). It prints:
#   - the key fingerprint (record it; clients can verify against it)
#   - the ARMORED PUBLIC key  -> written to aptrepo/pubkey.asc for your records
#                                (CI exports the public key to the repo itself;
#                                 this local copy is not committed)
#   - the ARMORED PRIVATE key -> paste into the GitHub Actions secret
#                                 APT_GPG_PRIVATE_KEY
#
# The key is created WITHOUT a passphrase so CI can sign unattended; its
# protection is that the private half lives only in Actions secrets and is
# never written to an internet-facing host. RSA-4096 for broad apt/gpgv
# compatibility.
set -euo pipefail

NAME=${1:-"mongo-journald apt repo"}
EMAIL=${2:-"sean@foobox.net"}

here=$(cd "$(dirname "$0")" && pwd)
GNUPGHOME=$(mktemp -d)
export GNUPGHOME
chmod 700 "$GNUPGHOME"
trap 'rm -rf "$GNUPGHOME"' EXIT

cat >"$GNUPGHOME/spec" <<EOF
%no-protection
Key-Type: RSA
Key-Length: 4096
Key-Usage: sign
Name-Real: $NAME
Name-Email: $EMAIL
Expire-Date: 0
%commit
EOF

gpg --batch --gen-key "$GNUPGHOME/spec" 2>/dev/null
fpr=$(gpg --list-keys --with-colons | awk -F: '/^fpr:/{print $10; exit}')

gpg --armor --export "$fpr" >"$here/pubkey.asc"

cat <<EOF

================================================================
apt repo signing key generated
================================================================
Fingerprint : $fpr
Public key  : aptrepo/pubkey.asc   (local copy for your records; not committed.
                                    CI exports the public key to the repo, and
                                    clients fetch it from apt.satoshi.in.th)

Next:
  1. Add a GitHub Actions secret named APT_GPG_PRIVATE_KEY with the block
     printed below (everything between the BEGIN/END lines, inclusive).
  2. Keep the fingerprint above in the README so hosts can verify the key.

----- COPY BELOW INTO SECRET: APT_GPG_PRIVATE_KEY -----
EOF
gpg --armor --export-secret-keys "$fpr"
echo "----- END -----"
