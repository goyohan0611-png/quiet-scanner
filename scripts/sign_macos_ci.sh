#!/bin/bash
# Run only on the temporary macOS CI runner, after unsigned build/tests.
set -euo pipefail
umask 077
for key in APPLE_CERTIFICATE APPLE_CERTIFICATE_PASSWORD APPLE_ID APPLE_PASSWORD RUNNER_TEMP CARGO_BUILD_TARGET; do
  if [[ -z "${!key:-}" ]]; then printf 'Missing signing setting: %s\n' "$key" >&2; exit 1; fi
done

SIGNING_DIR="$(mktemp -d "$RUNNER_TEMP/quiet-signing.XXXXXX")"
KEYCHAIN_PATH="$SIGNING_DIR/build.keychain-db"
KEYCHAIN_PASSWORD="$(openssl rand -base64 32)"
printf '::add-mask::%s\n' "$KEYCHAIN_PASSWORD"
ORIGINAL_KEYCHAINS=()
while IFS= read -r keychain; do ORIGINAL_KEYCHAINS+=("$keychain"); done < <(
  security list-keychains -d user | python3 -c 'import shlex,sys; print("\n".join(shlex.split(sys.stdin.read())))'
)
cleanup() {
  if [[ "${#ORIGINAL_KEYCHAINS[@]}" -gt 0 ]]; then
    security list-keychains -d user -s "${ORIGINAL_KEYCHAINS[@]}" >/dev/null 2>&1 || true
  fi
  security delete-keychain "$KEYCHAIN_PATH" >/dev/null 2>&1 || true
  # This directory is created by mktemp under this runner's private temp path.
  case "$SIGNING_DIR" in "$RUNNER_TEMP"/quiet-signing.*) rm -rf -- "$SIGNING_DIR" ;; esac
}
trap cleanup EXIT

printf '%s' "$APPLE_CERTIFICATE" | base64 --decode > "$SIGNING_DIR/certificate.p12"
security create-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN_PATH"
security set-keychain-settings -lut 7200 "$KEYCHAIN_PATH"
security unlock-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN_PATH"
security import "$SIGNING_DIR/certificate.p12" -k "$KEYCHAIN_PATH" -P "$APPLE_CERTIFICATE_PASSWORD" -T /usr/bin/codesign >/dev/null
# Import the public Apple intermediate, without adding custom trust settings.
curl --fail --silent --show-error --location https://www.apple.com/certificateauthority/DeveloperIDG2CA.cer -o "$SIGNING_DIR/DeveloperIDG2CA.cer"
security import "$SIGNING_DIR/DeveloperIDG2CA.cer" -k "$KEYCHAIN_PATH" >/dev/null
security list-keychains -d user -s "$KEYCHAIN_PATH" "${ORIGINAL_KEYCHAINS[@]}"
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$KEYCHAIN_PASSWORD" "$KEYCHAIN_PATH" >/dev/null

# Select exactly one trusted Developer ID Application identity, never an iOS or
# Apple Development identity. Certificate labels must be single-line values.
IDENTITIES="$(security find-identity -v -p codesigning "$KEYCHAIN_PATH")"
export IDENTITIES
IDENTITY_METADATA="$(python3 - <<'PY'
import os,re,json
matches=re.findall(r'"(Developer ID Application: [^"\r\n]+)"',os.environ['IDENTITIES'])
if len(matches)!=1: raise SystemExit('Expected exactly one valid Developer ID Application identity')
team=re.search(r'\(([A-Z0-9]{10})\)$',matches[0])
if not team: raise SystemExit('Cannot determine Apple Team ID from certificate')
print(json.dumps({'identity':matches[0],'team':team.group(1)}))
PY
)"
export IDENTITY_METADATA
APPLE_SIGNING_IDENTITY="$(python3 -c 'import os,json; print(json.loads(os.environ["IDENTITY_METADATA"])["identity"])')"
APPLE_TEAM_ID="$(python3 -c 'import os,json; print(json.loads(os.environ["IDENTITY_METADATA"])["team"])')"
export APPLE_SIGNING_IDENTITY APPLE_TEAM_ID
unset APPLE_CERTIFICATE APPLE_CERTIFICATE_PASSWORD IDENTITIES IDENTITY_METADATA

# Sign with the imported identity, but keep notarization out of the bundler's
# blocking wait. Submit only the final disk image; Apple also checks its app.
env -u APPLE_ID -u APPLE_PASSWORD -u APPLE_API_ISSUER -u APPLE_API_KEY -u APPLE_API_KEY_PATH \
  node node_modules/@tauri-apps/cli/tauri.js bundle --bundles app,dmg --target "$CARGO_BUILD_TARGET" --ci

APP="src-tauri/target/$CARGO_BUILD_TARGET/release/bundle/macos/Quiet Scanner.app"
codesign --verify --deep --strict --verbose=2 "$APP"
shopt -s nullglob
DMGS=("src-tauri/target/$CARGO_BUILD_TARGET/release/bundle/dmg/"*.dmg)
[[ "${#DMGS[@]}" == 1 ]] || { printf 'Expected exactly one signed DMG\n' >&2; exit 1; }
codesign --force --timestamp --sign "$APPLE_SIGNING_IDENTITY" "${DMGS[0]}"
codesign --verify --strict "${DMGS[0]}"
hdiutil verify "${DMGS[0]}"
VERSION="$(python3 -c 'import json; print(json.load(open("src-tauri/tauri.conf.json"))["version"])')"
export NOTARY_TEAM_ID="$APPLE_TEAM_ID"
python3 scripts/macos_notarization.py submit --dmg "${DMGS[0]}" \
  --output "notarization-pending/$CARGO_BUILD_TARGET" --version "$VERSION"
