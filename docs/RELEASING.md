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
`latest/VERSION` within a day. Release notes appear on https://testopscenter.com/releases.

## Publishing a version

1. Set `version` in `pyproject.toml` and `__version__` in `src/testops_gate/__init__.py`.
2. Add a `## 0.2.0 — YYYY-MM-DD` section to `CHANGELOG.md`; it becomes the release notes.
3. Commit, then `git tag v0.2.0 && git push && git push --tags`.
4. Run the release job with `REF=v0.2.0`: lint + unit tests → `.deb` → end-to-end tests on
   Debian 12/13 and Ubuntu 22.04/24.04/26.04 → release files → upload to testopscenter.com →
   (optional) GitHub release. Nothing is published when a test fails.

## Release scripts

| Script | Does |
|---|---|
| `packaging/build-deb.sh` | Builds `dist/testops-gate_<version>_all.deb` in a Debian container |
| `packaging/release-assets.sh` | Collects the release files and `NOTES.md` (from `CHANGELOG.md`) in `dist/release/`; checks that a tag matches the version |
| `packaging/publish-site.sh` | Uploads them to the site's release API with a token, then publishes the version |
| `packaging/publish-github.sh` | Optional GitHub release with the same files and notes |

The site stores uploads in a volume and only serves a version after checking it against
`SHA256SUMS`. `latest/` only moves forward (publishing 0.1.1 after 0.2.0 keeps 0.2.0 as latest);
to roll back, make an older published version the latest:

```bash
curl -X POST -H "Authorization: Bearer $SITE_TOKEN" https://testopscenter.com/api/releases/testops-gate/0.1.0/latest
```

## By hand

```bash
./packaging/build-deb.sh
./packaging/release-assets.sh
SITE_TOKEN=… ./packaging/publish-site.sh
GITHUB_TOKEN=… GITHUB_REPO=owner/repo ./packaging/publish-github.sh   # optional
```
