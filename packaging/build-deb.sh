#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Halis Utku Aladağ (TestOps Center, https://testopscenter.com)
# Build dist/testops-gate_<version>_all.deb in a Debian container.
#
# The package is architecture independent: testops-gate and its pure-Python
# dependencies (Textual, Rich, ...) are vendored under /usr/lib/testops-gate and
# resolved for Python 3.10, the oldest interpreter of the supported releases
# (Ubuntu 22.04); PyYAML comes from the distribution (python3-yaml).
set -euo pipefail

cd "$(dirname "$0")/.."
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' pyproject.toml | head -1)
mkdir -p dist
docker run --rm \
    -v "$PWD":/src:ro \
    -v "$PWD/dist":/out \
    -e VERSION="$VERSION" -e OWNER="$(id -u):$(id -g)" -e DEB_MAINTAINER="${DEB_MAINTAINER:-}" \
    debian:12 bash /src/packaging/build-inside.sh
echo "dist/testops-gate_${VERSION}_all.deb"
echo "dist/testops-gate-node_${VERSION}_all.deb"
