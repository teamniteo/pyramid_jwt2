# Releasing

1. `nix-shell -p uv`
1. `git pull origin main`
1. Bump `version` in `pyproject.toml`.
1. `uv sync`
1. `make tests`
1. `export VERSION=<new version>`
1. `git ci -am "release $VERSION"`
1. `git push origin main` and wait for CI to pass.
1. `git tag $VERSION && git push origin $VERSION`

`publish.yml` verifies the tag matches `pyproject.toml`, builds sdist + wheel, publishes to PyPI via Trusted Publishing (OIDC), and creates a GitHub Release with auto-generated notes.

Tag format must exactly match `project.version` — `1.0.0`, no `v` prefix.
