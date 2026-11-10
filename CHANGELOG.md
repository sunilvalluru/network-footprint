# Changelog

## 1.1.0

### Fixed
- **Skill now loads.** The skill file is renamed to `skills/network-footprint/SKILL.md`
  with a valid `name: network-footprint` and `allowed-tools` frontmatter. Previously
  only the `/network-footprint:scan` command worked.
- **Credentials no longer leak into findings or reports.** URL userinfo is masked
  (`postgres://user:***@host`, `https://***@o0.ingest.sentry.io`), as are values of
  `password` / `token` / `api_key` / `secret`-style keys, `?api_key=` query
  parameters and `Bearer` / `Basic` header values. Unquoted `KEY=value` pairs are
  masked in config and `.env` files.
- **Fewer bare-domain false positives.** In programming-language source a bare
  hostname must sit inside a string literal (so `data.in` is no longer an endpoint);
  names that are files in the scanned repo (`deploy.sh`) and two-label
  `name.ext` matches on file-extension TLDs are dropped.
- **Placeholder hosts are skipped.** `https://{HOST}/path` and `https://$BASE/x` are
  no longer reported as an endpoint named `{host`. They are counted in
  `summary.templated_urls_skipped`.
- **Full paths with template variables.** `/v1/users/${id}` and `/${pkg}/latest` are
  captured whole instead of being cut at `}`; balanced `(...)` in paths is kept too.

### Changed
- The command and the skill locate the bundled scripts with `${CLAUDE_PLUGIN_ROOT}` /
  `${CLAUDE_SKILL_DIR}` instead of globbing the disk for `plugin.json`.
- `/network-footprint:scan` accepts the target as an argument
  (`/network-footprint:scan ./repo`) and is now a thin wrapper around the skill, so the
  workflow is defined in one place.
- The HTML report step now requires HTML-escaping every value taken from scanned code.
- Docs use `python3`.
- Scanner version reported in findings now matches the plugin version (was `2.0.0`).

### Added
- `LICENSE` (MIT), `CHANGELOG.md`, `homepage` / `repository` in the plugin manifest.
- Regression tests: `python3 -m unittest discover tests`, run on Linux, macOS and
  Windows in CI.

## 1.0.0
- Initial release.
