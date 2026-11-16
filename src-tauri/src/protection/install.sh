# Managed by Quiet Scanner protection v1
#!/usr/bin/env bash
# Embedded in the signed application; never downloaded or assembled from input.
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root LC_ALL=C DEBIAN_FRONTEND=noninteractive
umask 077
DIR=/etc/quiet-scanner/protection
MARKER='# Managed by Quiet Scanner protection v1'
DROPIN=/etc/systemd/system/crowdsec-firewall-bouncer.service.d/quiet-scanner-setup.conf
TEMP=$(mktemp -d)
CURRENT=starting
stage() { CURRENT=$1; printf '{"stage":"%s"}\n' "$CURRENT" > "$DIR/setup-stage.json"; }
cleanup_default() {
  if [[ -f "$DROPIN" ]] && [[ "$(head -n 1 "$DROPIN")" == "$MARKER" ]]; then
    # This drop-in is created only for a newly installed default bouncer.
    # Keep it in place if disabling fails: it prevents unrequested activation.
    systemctl disable crowdsec-firewall-bouncer.service
    rm -- "$DROPIN"
    systemctl daemon-reload
  fi
}
failed() {
  local code=$?
  trap - ERR
  printf '{"stage":"failed","step":"%s","line":%s}\n' "$CURRENT" "${BASH_LINENO[0]}" > "$DIR/setup-stage.json"
  cleanup_default || true
  echo "Quiet Scanner setup failed at $CURRENT (exit $code). Existing packages/configurations are retained."
  exit "$code"
}
trap failed ERR

stage repository
apt-get -o DPkg::Lock::Timeout=120 update -qq
apt-get -o DPkg::Lock::Timeout=120 install -y --no-install-recommends curl ca-certificates gnupg nftables python3-yaml
python3 - <<'PY'
import json, os
p='/etc/quiet-scanner/protection/setup-owner.json'
if not os.path.exists(p):
    with open(p,'x') as f: json.dump({'managedEngine':not os.path.exists('/usr/bin/cscli'),'packageBouncers':[]},f)
PY
LIST=/etc/apt/sources.list.d/quiet-scanner-crowdsec.list
KEY=/etc/apt/keyrings/quiet-scanner-crowdsec.gpg
PREF=/etc/apt/preferences.d/quiet-scanner-crowdsec
for p in "$LIST" "$PREF"; do
  [[ ! -L "$p" ]]
  if [[ -e "$p" ]]; then [[ "$(head -n 1 "$p")" == "$MARKER" ]]; fi
done
[[ ! -L "$KEY" ]]
if [[ -e "$KEY" && ! -e "$LIST" ]]; then echo 'Existing unowned repository key'; exit 1; fi
install -d -m 755 /etc/apt/keyrings
curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error --retry 2 --connect-timeout 15 --max-time 90 https://packagecloud.io/crowdsec/crowdsec/gpgkey -o "$TEMP/key.asc"
gpg --batch --dearmor --output "$TEMP/key.gpg" "$TEMP/key.asc"
install -m 644 "$TEMP/key.gpg" "$KEY"
printf '%s\ndeb [signed-by=%s] https://packagecloud.io/crowdsec/crowdsec/any any main\n' "$MARKER" "$KEY" > "$LIST"
printf '%s\nPackage: crowdsec crowdsec-firewall-bouncer-nftables\nPin: origin packagecloud.io\nPin-Priority: 700\n' "$MARKER" > "$PREF"
chmod 644 "$LIST" "$PREF"

stage packages
apt-get -o DPkg::Lock::Timeout=120 update -qq
if [[ ! -x /usr/bin/cscli ]]; then
  printf 'crowdsec crowdsec/lapi boolean true\ncrowdsec crowdsec/capi boolean false\n' | debconf-set-selections
fi
apt-get -o DPkg::Lock::Timeout=120 install -y --no-install-recommends crowdsec
dpkg --compare-versions "$(dpkg-query -W -f='${Version}' crowdsec)" ge 1.7.0
systemctl start crowdsec.service
if [[ ! -x /usr/bin/crowdsec-firewall-bouncer ]]; then
  # The vendor postinst starts its default service. A temporary condition makes
  # that a no-op, so only Quiet Scanner's explicit ON can add blocking rules.
  [[ -z "$(systemctl show --property=FragmentPath --value crowdsec-firewall-bouncer.service)" ]]
  install -d -m 755 "$(dirname "$DROPIN")"
  [[ ! -L "$DROPIN" ]]
  if [[ -e "$DROPIN" ]]; then
    [[ -f "$DROPIN" && "$(head -n 1 "$DROPIN")" == "$MARKER" ]]
  fi
  printf '%s\n[Unit]\nConditionPathExists=/etc/quiet-scanner/protection/enable-vendor-default\n' "$MARKER" > "$DROPIN"
  chmod 644 "$DROPIN"
  [[ ! -e "$DIR/enable-vendor-default" ]]
  systemctl daemon-reload
  cscli bouncers list -o json > "$TEMP/before-bouncers.json"
  apt-get -o DPkg::Lock::Timeout=120 install -y --no-install-recommends crowdsec-firewall-bouncer-nftables
  ! systemctl is-active --quiet crowdsec-firewall-bouncer.service
  cscli bouncers list -o json > "$TEMP/after-bouncers.json"
  python3 "$DIR/configure.py" remember-bouncers "$TEMP/before-bouncers.json" "$TEMP/after-bouncers.json"
  cleanup_default
fi

stage configure
cscli hub update
cscli setup unattended
python3 "$DIR/configure.py" configure
stage validate
timeout 60 /usr/bin/crowdsec -t -c /etc/crowdsec/config.yaml
systemctl restart crowdsec.service
timeout 60 /usr/bin/cscli lapi status
stage activate
"$DIR/setup-worker" --protection-finalize
if [[ -e "$DIR/cancel-start" ]]; then stage cancelled; else stage done; fi
echo 'Quiet Scanner setup completed. No log content or engine credentials are written to the application UI.'
