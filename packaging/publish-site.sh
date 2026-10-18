#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Halis Utku Aladağ (TestOps Center, https://testopscenter.com)
# Upload dist/release/ to the website over SSH (rsync):
#
#   <SITE_ROOT>/install.sh
#   <SITE_ROOT>/testops-gate/v<version>/   VERSION, SHA256SUMS, testops-gate_all.deb, testops-gate_<version>_all.deb
#   <SITE_ROOT>/testops-gate/latest/       same files; VERSION is written last so a server that
#                                         sees a new version can always download its package
#
# Environment: SITE_SSH (user@host), SITE_ROOT (document root on the server),
#              SITE_URL (public URL used for the final check, default https://testopscenter.com),
#              SITE_SSH_PORT (default 22)
set -euo pipefail
cd "$(dirname "$0")/.."
: "${SITE_SSH:?set SITE_SSH, e.g. deploy@testopscenter.com}"
: "${SITE_ROOT:?set SITE_ROOT, e.g. /var/www/testopscenter.com}"
SITE_URL=${SITE_URL:-https://testopscenter.com}
R=dist/release
VERSION=$(cat "$R/VERSION")
SSH="ssh -p ${SITE_SSH_PORT:-22} -o BatchMode=yes -o StrictHostKeyChecking=accept-new"
DEST="$SITE_ROOT/testops-gate"

echo "Publishing testops-gate $VERSION to $SITE_SSH:$DEST"
$SSH "$SITE_SSH" "mkdir -p '$DEST/v$VERSION' '$DEST/latest'"
rsync -a --chmod=F644,D755 -e "$SSH" "$R/testops-gate_${VERSION}_all.deb" "$R/testops-gate_all.deb" \
    "$R/SHA256SUMS" "$R/VERSION" "$SITE_SSH:$DEST/v$VERSION/"
rsync -a --chmod=F644 -e "$SSH" "$R/testops-gate_${VERSION}_all.deb" "$R/testops-gate_all.deb" "$R/SHA256SUMS" \
    "$SITE_SSH:$DEST/latest/"
rsync -a --chmod=F644 -e "$SSH" "$R/VERSION" "$SITE_SSH:$DEST/latest/"
rsync -a --chmod=F644 -e "$SSH" "$R/install.sh" "$SITE_SSH:$SITE_ROOT/install.sh"

published=$(curl -fsS "$SITE_URL/testops-gate/latest/VERSION" || true)
if [ "$published" != "$VERSION" ]; then
    echo "warning: $SITE_URL/testops-gate/latest/VERSION returns '$published', expected $VERSION" >&2
    exit 1
fi
curl -fsS "$SITE_URL/testops-gate/latest/SHA256SUMS" | grep -q " testops-gate_all.deb$"
echo "OK: curl -fsSL $SITE_URL/install.sh | sudo sh"
