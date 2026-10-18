#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Halis Utku Aladağ (TestOps Center, https://testopscenter.com)
# Upload dist/release/ to testopscenter.com through its release API and publish it:
#
#   PUT  <SITE_URL>/api/releases/testops-gate/<version>/files/<file>   every release file
#   POST <SITE_URL>/api/releases/testops-gate/<version>/publish        the site checks SHA256SUMS
#
# The site then serves the files under /testops-gate/v<version>/ and, when it is the newest
# version, under /testops-gate/latest/ and /install.sh; NOTES.md appears on /releases.
#
# Environment: SITE_TOKEN (release upload token of the site),
#              SITE_URL (default https://testopscenter.com)
set -euo pipefail
cd "$(dirname "$0")/.."
: "${SITE_TOKEN:?set SITE_TOKEN, the release upload token of the site}"
SITE_URL=${SITE_URL:-https://testopscenter.com}
R=dist/release
VERSION=$(cat "$R/VERSION")
API="$SITE_URL/api/releases/testops-gate/$VERSION"
# The token must never travel in clear text (plain http is allowed only for a local test site)
case "$SITE_URL" in
    https://*|http://127.0.0.1[:/]*|http://127.0.0.1|http://localhost[:/]*|http://localhost) ;;
    *) echo "SITE_URL must use https: $SITE_URL" >&2; exit 1 ;;
esac

# Pass the token in a header file so it does not show up in the process list
HEADER=$(mktemp)
trap 'rm -f "$HEADER"' EXIT
printf 'Authorization: Bearer %s\n' "$SITE_TOKEN" > "$HEADER"
api() { curl -sS --fail-with-body --retry 3 -H @"$HEADER" "$@"; }

echo "Publishing testops-gate $VERSION to $SITE_URL"
for file in "testops-gate_${VERSION}_all.deb" testops-gate_all.deb SHA256SUMS VERSION install.sh NOTES.md; do
    echo "  uploading $file"
    api -T "$R/$file" "$API/files/$file" >/dev/null
done
api -X POST "$API/publish" >/dev/null

curl -fsS "$SITE_URL/testops-gate/v$VERSION/VERSION" | grep -qx "$VERSION"
latest=$(curl -fsS "$SITE_URL/testops-gate/latest/VERSION")
curl -fsS "$SITE_URL/testops-gate/latest/SHA256SUMS" | grep -q " testops-gate_all.deb$"
echo "OK: testops-gate $VERSION published, latest is $latest"
echo "    curl -fsSL $SITE_URL/install.sh | sudo sh"
