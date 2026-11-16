#!/usr/bin/env bash
# Explicit development setup; never runs a downloaded shell script.
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C DEBIAN_FRONTEND=noninteractive
test "$(id -u)" = 0
. /etc/os-release
test "$ID" = ubuntu && test "$VERSION_ID" = 24.04 && test "$(uname -m)" = x86_64
test -x /usr/sbin/sshd || { echo 'Configure the server SSH service first.' >&2; exit 1; }
if [[ -x /usr/bin/cscli ]]; then
  installed=$(dpkg-query -W -f='${Version}' crowdsec)
  [[ "$installed" = 1.8.2 || "$installed" = 1.8.2-* ]] || { echo 'Existing CrowdSec version is preserved; this prototype requires 1.8.2.' >&2; exit 1; }
  apt-get install -y --no-install-recommends curl nftables
  exit 0
fi
dropin=/etc/systemd/system/crowdsec.service.d/quiet-guard-setup.conf
list=/etc/apt/sources.list.d/quiet-guard-crowdsec.list
key=/etc/apt/keyrings/quiet-guard-crowdsec.gpg
for path in "$dropin" "$list" "$key"; do test ! -e "$path" && test ! -L "$path"; done
test ! -e /etc/quiet-guard/allow-vendor-crowdsec
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT
apt-get update -qq
apt-get install -y --no-install-recommends curl ca-certificates gnupg nftables
install -d -m 755 /etc/apt/keyrings "$(dirname "$dropin")"
curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location --connect-timeout 15 --max-time 90 https://packagecloud.io/crowdsec/crowdsec/gpgkey -o "$temporary/key.asc"
gpg --batch --dearmor --output "$temporary/key.gpg" "$temporary/key.asc"
install -m 644 "$temporary/key.gpg" "$key"
printf 'deb [signed-by=%s] https://packagecloud.io/crowdsec/crowdsec/any any main\n' "$key" > "$list"
chmod 644 "$list"
# Postinst may unmask/start the default unit. A condition blocks that first boot,
# before the package can run its engine. Existing instances take the branch above.
printf '# Managed by Quiet Guard dependency setup v1\n[Unit]\nConditionPathExists=/etc/quiet-guard/allow-vendor-crowdsec\n' > "$dropin"
chmod 644 "$dropin"
systemctl daemon-reload
printf 'crowdsec crowdsec/lapi boolean true\ncrowdsec crowdsec/capi boolean false\n' | debconf-set-selections
apt-get update -qq
apt-get install -y --no-install-recommends crowdsec=1.8.2
! systemctl is-active --quiet crowdsec.service
systemctl disable crowdsec.service
rm -- "$dropin"
rmdir -- "$(dirname "$dropin")" 2>/dev/null || true
systemctl daemon-reload
echo 'Dependencies prepared. No Quiet Guard protection is enabled until explicit SSH enable.'
