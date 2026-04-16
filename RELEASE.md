# How to release a new version

1. Ensure `main` is green.
1. Bump `version` in `pyproject.toml`.
1. `make all` (lint + format check + tests at 100% coverage).
1. `export VERSION=<new version>`
1. `git ci -am "release $VERSION"`
1. Open a PR, merge to `main`.
1. From updated `main`: `git tag $VERSION && git push origin $VERSION`

The `publish.yml` workflow verifies that the tag matches the version in
`pyproject.toml`, builds sdist + wheel, publishes to PyPI via Trusted
Publishing (OIDC), and creates a GitHub Release with auto-generated notes.

Tag format must exactly match `project.version` — `1.0.0` (no `v` prefix).
