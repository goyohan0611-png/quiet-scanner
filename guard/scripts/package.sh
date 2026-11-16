#!/usr/bin/env bash
# Build a release directory and sign it locally. Never upload the private key.
set -euo pipefail
binary=${1:?compiled Linux binary}
destination=${2:?new output directory}
sequence=${3:?positive release sequence}
version=${4:?version}
private_key=${5:?offline Ed25519 private PEM}
test ! -e "$destination"
mkdir -m 700 -- "$destination"
install -m 755 -- "$binary" "$destination/quiet-guard"
install -m 644 -- "$(dirname "$0")/../systemd/quiet-guard.service" "$destination/quiet-guard.service"
"$binary" bundle manifest "$destination" release "$sequence" "$version"
openssl pkeyutl -sign -inkey "$private_key" -rawin -in "$destination/manifest.json" -out "$destination/signature.bin"
echo 'Signed release directory created. Verify using an independently trusted public key.'
