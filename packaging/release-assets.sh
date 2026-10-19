#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Halis Utku Aladağ (TestOps Center, https://testopscenter.com)
# Collect the release files in dist/release/:
#   testops-gate_<version>_all.deb, testops-gate_all.deb (stable name), SHA256SUMS, VERSION, install.sh,
#   NOTES.md (the version's section of CHANGELOG.md)
# When building a tag (TAG_NAME=vX.Y.Z) the tag must match the version in pyproject.toml.
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' pyproject.toml | head -1)
if [ -n "${TAG_NAME:-}" ] && [ "$TAG_NAME" != "v$VERSION" ]; then
    echo "tag $TAG_NAME does not match pyproject version $VERSION" >&2
    exit 1
fi
DEB="dist/testops-gate_${VERSION}_all.deb"
NODE_DEB="dist/testops-gate-node_${VERSION}_all.deb"
for f in "$DEB" "$NODE_DEB"; do
    [ -f "$f" ] || { echo "$f not found: run packaging/build-deb.sh first" >&2; exit 1; }
done

R=dist/release
rm -rf "$R" && mkdir -p "$R"
cp "$DEB" "$R/"
cp "$DEB" "$R/testops-gate_all.deb"
cp "$NODE_DEB" "$R/"
cp "$NODE_DEB" "$R/testops-gate-node_all.deb"
cp install.sh "$R/"
echo "$VERSION" > "$R/VERSION"
# Body of the "## <version> — <date>" section, without leading/trailing blank lines
awk -v v="$VERSION" '
    /^## / { if (found) exit; found = ($2 == v); next }
    found { line[++n] = $0 }
    END {
        s = 1; while (s <= n && line[s] ~ /^[[:space:]]*$/) s++
        e = n; while (e >= s && line[e] ~ /^[[:space:]]*$/) e--
        for (i = s; i <= e; i++) print line[i]
    }' CHANGELOG.md > "$R/NOTES.md"
[ -s "$R/NOTES.md" ] || { echo "CHANGELOG.md has no section for $VERSION" >&2; exit 1; }
# Every published file except SHA256SUMS itself (the site rejects a release with an unlisted file)
(cd "$R" && sha256sum "testops-gate_${VERSION}_all.deb" testops-gate_all.deb "testops-gate-node_${VERSION}_all.deb" \
    testops-gate-node_all.deb install.sh VERSION NOTES.md > SHA256SUMS)
ls -l "$R"
