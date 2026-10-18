# Releasing TestOps Gate

Releases are built, tested and published by a Jenkins job that lives in a private CI
repository (the pipeline and the tests are not part of this repository). The job clones
this repository at a branch or tag, runs the tests and uses the scripts in `packaging/`.
Servers download from **testopscenter.com**:

```
https://testopscenter.com/install.sh
https://testopscenter.com/testops-gate/latest/   VERSION · SHA256SUMS · testops-gate_all.deb · testops-gate_<version>_all.deb
https://testopscenter.com/testops-gate/v0.2.0/   the same files for every version (TESTOPS_GATE_VERSION=0.2.0)
```

`install.sh` and `testops-gate update` read `latest/`; installed servers notice a new
`latest/VERSION` within a day.

## Publishing a version

1. Set `version` in `pyproject.toml` and `__version__` in `src/testops_gate/__init__.py`.
2. Commit, then `git tag v0.2.0 && git push && git push --tags`.
3. Run the release job with `REF=v0.2.0`: lint + unit tests → `.deb` → end-to-end tests on
   Debian 12/13 and Ubuntu 22.04/24.04 → release files → upload to testopscenter.com →
   (optional) GitHub release. Nothing is published when a test fails.

## Release scripts

| Script | Does |
|---|---|
| `packaging/build-deb.sh` | Builds `dist/testops-gate_<version>_all.deb` in a Debian container |
| `packaging/release-assets.sh` | Collects the release files in `dist/release/` (checks that a tag matches the version) |
| `packaging/publish-site.sh` | Uploads them with rsync over SSH; `VERSION` last, so servers never see a version without its package |
| `packaging/publish-github.sh` | Optional GitHub release with the same files |

The web server needs no server-side code: any static file server works. A `deploy` user
that can write to the document root is enough. Recommended: serve
`testops-gate/latest/VERSION` with `Cache-Control: no-cache`.

## By hand

```bash
./packaging/build-deb.sh
./packaging/release-assets.sh
SITE_SSH=deploy@testopscenter.com SITE_ROOT=/var/www/testopscenter.com ./packaging/publish-site.sh
GITHUB_TOKEN=… GITHUB_REPO=owner/repo ./packaging/publish-github.sh   # optional
```
