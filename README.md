# Network Footprint

A Claude Code / Cowork plugin that maps **how data moves in and out of a codebase**.

Point it at a repository and it produces an inventory of every external network
reference **of any protocol** — HTTP/HTTPS, WebSocket (ws/wss), databases
(postgres, mysql, mongodb, redis), message queues (amqp, mqtt, kafka), gRPC, SSH,
FTP, `git@` remotes — plus bare public domains and IP addresses. For each one it
tells you the **direction data flows** (outbound, inbound,
bidirectional, or none), whether it is **actively used** in code or only defined in
configuration, and **where** in the source it appears.

It reports facts, not verdicts. There is no risk scoring, no severity, and no
compliance classification — just a clear picture of what your application connects to
and which way data travels. If you want to judge risk, the report gives you the
groundwork to do so yourself.

## What it detects

- **Outbound (OUT)** — where the app *sends* data (uploads, posts, pushes).
- **Inbound (IN)** — where the app *receives* data (fetches, downloads, pulls).
- **Bidirectional (BOTH)** — send-and-receive endpoints (upload-then-read, websockets, DB connections).
- **Config-only** — endpoints defined in configuration but never exercised in code.
- **Endpoint type** — a neutral label (cloud storage, code repository, package registry, database, monitoring, auth provider, CDN, internal/localhost, third-party).
- **Public IP addresses** used in network operations.
- **Code identifiers excluded** — package/namespace names that look like domains but aren't network references.

## Install

The plugin is distributed through a Claude Code marketplace.

```bash
# 1. Add the marketplace
/plugin marketplace add sunilvalluru/network-footprint

# 2. Install the plugin
/plugin install network-footprint@sunil-plugins
```

Or clone the repo and add it as a local marketplace:

```bash
git clone https://github.com/sunilvalluru/network-footprint.git
/plugin marketplace add ./network-footprint
/plugin install network-footprint@sunil-plugins
```

Requires **Python 3.6+** only — the scanner uses the standard library, no pip installs.

## Usage

Run the command with the directory to analyze (or leave it off and you'll be asked):

```
/network-footprint:scan ./path/to/repo
```

The skill also loads automatically when you ask things like "what external services
does this repo talk to?" or "where does this app send data?".

The agent locates the bundled scanner, runs it, reads the results, works out the
direction and usage of every endpoint, and writes two reports into a `findings/`
directory inside the target:

- `NetworkFootprint_Report.md` — descriptive markdown report
- `NetworkFootprint_Report_<project>_<date>.html` — formatted HTML report (direction-colored, print-friendly)

### Run the scanner directly

You can also run just the scanner (it produces the JSON the agent analyzes):

```bash
python3 skills/network-footprint/scripts/footprint_scan.py /absolute/path/to/target
```

The scan writes findings in two layers, each split one-file-per-finding so
every chunk stays small enough for an LLM to read and reason about on its own:

- `target/findings/footprint_raw.json` + `target/findings/occurrences/*.json` —
  the scanner's raw, pre-grouping occurrences, mechanical and unenriched.
- `target/findings/footprint.json` (an index: summary plus one row per endpoint)
  + `target/findings/endpoints/*.json` — the analyzer's grouped, enriched
  output: each endpoint's full occurrences and context, and, for a URL found
  only in a config file, the config key it's bound to and every place in code
  that reads that key.

## Try it on the sample

The repo ships with a small polyglot test app that exercises every detection path:

```bash
python3 skills/network-footprint/scripts/footprint_scan.py "$(pwd)/samples/sample-app"
```

`samples/EXPECTATIONS.md` is the answer key — it lists every endpoint the sample
contains and how it should be classified, so you can confirm the analyzer is working.

## How it works

Two layers:

1. **Scanner (mechanical).** `footprint_scan.py` runs a network-reference scanner and a
   configuration analyzer. The scanner locates every URL, DNS name, and IP with
   surrounding code context. The analyzer groups those by host and, for any URL found
   only in a config file, traces it to the config key it's bound to and searches the
   codebase for every place that key is actually read, noting any HTTP operation
   detected nearby. Both write structured JSON. Neither judges anything — they locate
   and connect facts, they don't decide what those facts mean.
2. **Agent (analysis).** The `/network-footprint:scan` command / skill reads that JSON and
   reasons about each endpoint — direction, usage status, endpoint type — then writes
   the reports. This reasoning depends on how each project actually uses each endpoint,
   which is why it is done by the model rather than hardcoded.

## Known limitations

By design, the scanner:

- **Does not scan `.md` files** or URLs inside code comments (treated as documentation).
- **Skips placeholder hosts** such as `https://{HOST}/path` or `https://$BASE/x`
  (counted in `summary.templated_urls_skipped`), and bare names that are really
  files (`deploy.sh`) or attribute access (`data.in`, `logger.info`).
- **Keeps only globally-routable IPs** — private (10/8, 172.16/12, 192.168/16),
  loopback, and reserved/documentation ranges are filtered out as non-external.
- Uses pattern matching, so exotic or heavily obfuscated code can produce false
  positives/negatives — the report is a starting point, not a guarantee.
- Attaches a best-effort **direction** and **usage** hint to each endpoint from a small
  keyword window; the agent (and you) refine these from the context stored with every
  occurrence.
- Config-key usage search is also pattern-based per language (quoted key access,
  `config.get()`, environment-variable lookups, dotted property access, a handful of
  framework-specific forms like Spring's `@Value`) — it will miss unconventional or
  deeply indirected config access (e.g. keys built dynamically at runtime).

This plugin maps data flow only. It does not scan for secrets or hardcoded
credentials. It does **mask** any it comes across: URL credentials become
`user:***@host`, and values of keys like `password`, `token`, `api_key` and
`Bearer` headers become `***` in every file written to `findings/`. Masking is
pattern-based, so skim a report before sharing it widely. Inventorying secrets
is still a separate job, better served by dedicated tools (gitleaks,
trufflehog, detect-secrets).

## Repository layout

```
.claude-plugin/
  plugin.json          # plugin manifest
  marketplace.json     # marketplace manifest
commands/
  scan.md               # /network-footprint:scan - thin wrapper around the skill
skills/network-footprint/
  SKILL.md                         # the skill (full workflow)
  scripts/                         # Python stdlib only
    footprint_scan.py               # entry point (scan -> findings/footprint_raw.json + occurrences/, footprint.json + endpoints/)
    footprint_network_scanner.py    # extracts references of any protocol, writes one file per raw occurrence
    footprint_config_analyzer.py    # groups by host, infers direction/usage, traces config-bound URLs to their readers in code
    footprint_config.json           # single config file
    footprint_report_template.html  # HTML report template
samples/
  sample-app/          # test fixture covering every detection path
  EXPECTATIONS.md      # answer key for the sample
tests/
  test_scanner.py      # regression tests (python3 -m unittest discover tests)
```

## Development

```bash
python3 -m unittest discover tests
```

See `CHANGELOG.md` for release notes.

## License

MIT
