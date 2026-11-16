#!/usr/bin/env bash
# Explicit development prerequisite installation; does not enable Guard WAF.
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C DEBIAN_FRONTEND=noninteractive
test "$(id -u)" = 0
. /etc/os-release
test "$ID" = ubuntu && test "$VERSION_ID" = 24.04
test -x /usr/bin/cscli || { echo 'Prepare the pinned CrowdSec dependency first; see README.' >&2; exit 1; }
if test -x /usr/sbin/nginx; then
  installed=$(dpkg-query -W -f='${Version}' nginx 2>/dev/null || true)
  [[ "$installed" = 1.24.0 || "$installed" = 1.24.0-* ]] || { echo 'Existing Nginx is outside the validated Ubuntu profile; packages and settings were preserved.' >&2; exit 1; }
fi
apt-get update -qq
# Installing the distribution Lua module may reload Nginx. Run in a maintenance window.
apt-get install -y --no-install-recommends nginx libnginx-mod-http-lua lua-cjson
echo 'Nginx Lua dependencies prepared. WAF is still off until explicit enable.'
