#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Halis Utku Aladağ (TestOps Center, https://testopscenter.com)
# Runs inside debian:12 (see build-deb.sh).
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends python3 python3-venv dpkg-dev ca-certificates >/dev/null

STAGE=/tmp/stage
LIB=$STAGE/usr/lib/testops-gate
rm -rf "$STAGE"
mkdir -p "$STAGE/DEBIAN" "$LIB/vendor" "$STAGE/usr/bin" "$STAGE/lib/systemd/system" "$STAGE/usr/share/doc/testops-gate"

cp -r /src/src/testops_gate "$LIB/"
find "$LIB" -name __pycache__ -type d -prune -exec rm -rf {} +

python3 -m venv /tmp/pip
/tmp/pip/bin/pip install -q --upgrade pip
/tmp/pip/bin/pip install -q --target "$LIB/vendor" \
    --python-version 3.10 --implementation py --abi none --platform any --only-binary=:all: \
    "textual>=3.0,<9"
rm -rf "$LIB/vendor/bin"
find "$LIB/vendor" -name __pycache__ -type d -prune -exec rm -rf {} +

install -m 0755 /src/packaging/bin/testops-gate /src/packaging/bin/testops-gated "$STAGE/usr/bin/"
install -m 0644 /src/packaging/systemd/* "$STAGE/lib/systemd/system/"
install -m 0644 /src/README.md /src/NOTICE /src/TRADEMARKS.md "$STAGE/usr/share/doc/testops-gate/"
# Debian policy: the license goes to /usr/share/doc/<package>/copyright
{ cat /src/NOTICE; echo; echo "----"; echo; cat /src/LICENSE; } > "$STAGE/usr/share/doc/testops-gate/copyright"
for script in postinst prerm postrm; do
    install -m 0755 "/src/packaging/debian/$script" "$STAGE/DEBIAN/"
done
SIZE=$(du -sk "$STAGE" | cut -f1)
MAINTAINER=${DEB_MAINTAINER:-testops-gate maintainers <noreply@github.com>}
sed -e "s/@VERSION@/$VERSION/" -e "s/@SIZE@/$SIZE/" -e "s|@MAINTAINER@|$MAINTAINER|" /src/packaging/debian/control > "$STAGE/DEBIAN/control"

DEB="/out/testops-gate_${VERSION}_all.deb"
dpkg-deb --build --root-owner-group "$STAGE" "$DEB" >/dev/null
chown "$OWNER" "$DEB"
dpkg-deb --info "$DEB" | sed -n '1,20p'
