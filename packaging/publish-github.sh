#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Halis Utku Aladağ (TestOps Center, https://testopscenter.com)
# Create (or reuse) the GitHub release v<version> and upload dist/release/ as assets.
# Environment: GITHUB_TOKEN (contents: write), GITHUB_REPO (owner/repo), GIT_COMMIT (optional)
set -euo pipefail
cd "$(dirname "$0")/.."
: "${GITHUB_TOKEN:?}" "${GITHUB_REPO:?set GITHUB_REPO, e.g. testopscenter/testops-gate}"
R=dist/release
VERSION=$(cat "$R/VERSION")
TAG="v$VERSION"
API="https://api.github.com/repos/$GITHUB_REPO"
api() { curl -fsS -H "Authorization: Bearer $GITHUB_TOKEN" -H "Accept: application/vnd.github+json" "$@"; }
json_id() { python3 -c 'import json, sys; print(json.load(sys.stdin)["id"])'; }

if ! id=$(api "$API/releases/tags/$TAG" 2>/dev/null | json_id); then
    body=$(python3 -c 'import json, sys; print(json.dumps({"tag_name": sys.argv[1], "name": f"testops-gate {sys.argv[2]}",
        "target_commitish": sys.argv[3], "generate_release_notes": True}))' "$TAG" "$VERSION" "${GIT_COMMIT:-main}")
    id=$(api -X POST "$API/releases" -d "$body" | json_id)
fi
for file in "testops-gate_${VERSION}_all.deb" testops-gate_all.deb SHA256SUMS VERSION install.sh; do
    echo "uploading $file"
    api -X POST -H "Content-Type: application/octet-stream" --data-binary "@$R/$file" \
        "https://uploads.github.com/repos/$GITHUB_REPO/releases/$id/assets?name=$file" >/dev/null
done
echo "https://github.com/$GITHUB_REPO/releases/tag/$TAG"
