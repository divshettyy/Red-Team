# Changelog

All notable changes to this project are documented here.

## 2026-11-20

### Added
- `CHANGELOG.md` to track changes over time.
- Continuous integration workflow (`.github/workflows/ci.yml`) that byte-compiles every Python module on each push and pull request, so syntax regressions are caught automatically.
- Dependabot configuration (`.github/dependabot.yml`) to keep Python dependencies and GitHub Actions current.
- `.editorconfig` to keep indentation and line endings consistent across editors.

### Verified
- All 33 Python modules compile without syntax errors.

## Earlier

- Overhauled the README with badges, a table of contents, an architecture diagram, and a competitive comparison.
- Added `LICENSE` (MIT) and `SECURITY.md`.
- Set the repository description and topics for discoverability.
