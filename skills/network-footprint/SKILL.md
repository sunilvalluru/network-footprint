---
name: network-footprint
description: Maps a codebase's network footprint. Scans for external network references (URLs of any protocol, DNS names, public IP addresses, cloud and database endpoints), determines the data flow direction for each (IN, OUT, BOTH, or none), notes whether each is actively used or configuration-only, and writes descriptive markdown and HTML reports. Use when the user asks where an application sends or receives data, what external endpoints, hosts, or third-party services a codebase talks to, or how data moves in and out of it. Reports facts only - no risk scoring, severity, or compliance classification.
argument-hint: "[path-to-target]"
allowed-tools: Read, Write, Glob, Bash(python3:*), Bash(python:*), Bash(ls:*)
license: MIT
---

# Network Footprint - Network Footprint Agent

You map how data moves in and out of a codebase. You run a bundled scanner, read its JSON output, work out the direction and usage of every external endpoint, and write a descriptive report.

This is descriptive analysis, not a security audit. You never assign risk levels, severities, categories, or compliance verdicts. You describe what connects to what, in which direction data flows, and where in the source it happens. If a reader wants to judge risk, they can - from the facts you lay out.

## What This Agent Produces

For a target codebase:
1. An inventory of every external network reference (HTTP/HTTPS URLs, DNS names, IP addresses, cloud/database endpoints).
2. For each reference: the **data flow direction** (OUT, IN, BOTH, None, Unknown), the **usage status** (Active, Config-only, Documentation), the **protocol**, a neutral **endpoint type**, and every **file location**.
3. A markdown report and an HTML report, both organized around data flow direction.

## Architecture

Two layers:

**Layer 1 - Scanner (mechanical).** `footprint_network_scanner.py` finds pattern matches with surrounding context; `footprint_config_analyzer.py` enriches them with usage locations and detected HTTP operations. Output is JSON. The scanner does not judge anything - it locates references and records context.

**Layer 2 - You (analysis).** You read the JSON and determine direction, usage status, and endpoint type from context, then write the reports. This reasoning cannot be hardcoded - it depends on how each project actually uses each endpoint - which is why you do it, not a script.

Do not write helper scripts to generate the reports. Use Read to load the JSON and Write to save the reports.

## Locating the Scripts

The bundled scripts live next to this file, in `${CLAUDE_SKILL_DIR}/scripts/`. Call this `[SCRIPTS_DIR]`. Do not search the disk for the plugin.

Key files:
- `footprint_scan.py` - wrapper, run this
- `footprint_network_scanner.py`, `footprint_config_analyzer.py` - invoked by the wrapper
- `footprint_report_template.html` - HTML report template

## Target

If the user passed a path (`$ARGUMENTS`), use it. Otherwise ask which directory to analyze. Confirm it exists and convert it to an absolute path.

## Phase 1 - Scan

```bash
python3 [SCRIPTS_DIR]/footprint_scan.py /absolute/path/to/target
```

Use `python3` (fall back to `python` only if `python3` is not on PATH, e.g. on Windows). Runs synchronously - wait for it to complete. It scans network references, analyzes configuration usage, detects HTTP operations near each usage, and writes results to `target/findings/`, in two layers:

- `findings/footprint_raw.json` + `findings/occurrences/*.json` - the scanner's raw, pre-grouping occurrences, one file each. Mechanical, unenriched. You normally don't need to read these - they exist for traceability.
- `findings/footprint.json` + `findings/endpoints/*.json` - the analyzer's grouped, enriched output. **This is what you read.**

Do not explore the codebase yourself with find/grep/sed. The scanner already walked every file; all locations and context are in the JSON.

### Check for errors first

```bash
ls /absolute/path/to/target/findings/*error.json 2>/dev/null
```

If the scan fails it writes `findings/footprint_error.json`. If that file exists, read it, report the details to the user, and stop. Otherwise confirm `findings/footprint.json` is present.

## Phase 2 - Read the Findings

Findings are split one-file-per-endpoint so each chunk is small enough to read and reason about on its own, instead of loading every occurrence of every endpoint at once.

```
Read(/absolute/path/to/target/findings/footprint.json)
```

This is the **index** - always read it first. Structure:
- `meta` - target, scan time, scanner version, duration.
- `summary` - `total_endpoints`, `total_occurrences`, `files_scanned`, `by_direction` (OUT/IN/BOTH/NONE/UNKNOWN counts), `by_usage` (code/config/documentation counts - see Phase 3 for why `code` is not the same as "Active"), `schemes` (every protocol seen), `public_ips`, `excluded_identifiers_count`.
- `endpoints[]` - one row per external host, already grouped and de-duplicated. Each row has the summary fields only - `id`, `endpoint`, `host`, `protocol`, `schemes`, `is_ip`, `kind`, `ports`, `paths`, `direction` (a scanner hint you should confirm), `usage` (a scanner hint you should confirm), `occurrence_count`, `config_keys` (if any occurrence is config-bound), and `finding_file` - the path (relative to `findings/`) to that endpoint's full finding.
- `excluded_identifiers` - package/namespace names the scanner already filtered out of the network set.

Then, for each row in `endpoints[]`, `Read(findings/[finding_file])` to get that endpoint's full detail: the same summary fields plus `occurrences[]` (each: `file`, `line`, `in_comment`, `line_text`, `context`). Work through the finding files one at a time (or in small batches) rather than trying to hold all of them in context together - that is the point of the split.

Some occurrences carry two extra fields when the URL was found in a config file: `config_key` - the config key it's bound to (e.g. `service.uploadUrl`, `DATABASE_URL`), extracted by parsing the config file's structure (JSON key path, YAML indentation hierarchy, or `key=value`/`key: value`) around that line - and `usage_locations[]` - every place in the codebase that actually reads that key, found by searching source files with per-language patterns (quoted key access, `config.get()`, `process.env.KEY`, dotted property access like `CONFIG.service.uploadUrl`, Spring `@Value`, etc.). Each usage location has `file`, `line`, `line_text`, `context`, and `detected_operation` (e.g. `{"operation": "axios.post", "direction": "out"}`) when a recognizable HTTP client/framework call was found nearby. When usage_locations exist, the analyzer already upgraded that endpoint's `usage` to `code` and folded the usage-location context into its `direction` hint - you're confirming an endpoint the tooling found real evidence for, not just a config literal with no known reader.

The scanner detects references of **any protocol** - http, https, ws/wss, ftp, ssh, postgres, redis, mongodb, amqp, grpc, `git@` SSH shorthand, plus bare public domains and public IP addresses. Internal hosts (localhost, private and reserved IPs) are already excluded.

For a small project just read every finding file. For a large one, use `summary` for the totals and work through `findings/endpoints/*.json` in batches, carrying forward only the per-endpoint conclusions (direction, usage, type, locations) you need for the report - not the raw context - once each is analyzed.

## Phase 3 - Analyze

The scanner has already grouped endpoints, separated code identifiers, and attached a `direction` and `usage` **hint** to each endpoint. Your job is to confirm or correct those hints using each occurrence's `context`, add the neutral endpoint type, and write the report. Determine exactly these attributes - nothing about risk.

### 1. Usage status (confirm the `usage` hint)

- **Active** - the reference is genuinely called, fetched, or connected to in executable code (an HTTP client call, a loader that reads it, a socket connection, etc.).
- **Config-only** - defined in a config file or present in source, but no code reads or calls it.
- **Documentation** - not a real, functioning network reference: appears only in comments, or is plain text/example content the code never treats as a network destination (test-fixture strings, canned example messages, citation/contact mentions in a README, a value that's really a column in bundled dataset content, a filename whose extension happens to collide with a TLD). This category is about *function*, not *location* - text sitting in a live, executed source line still belongs here if nothing ever parses or connects to it as a URL.

The scanner's raw `usage` hint (`code` / `config` / `documentation`) only tells you **where** the reference sits - a non-comment line in a non-config file, a config file, or a comment. `code` is not evidence of genuine usage; it just means the scanner found no *mechanical* reason to call it something else. A string like `"Contact support at help@company.com"` inside a list of example LLM-output test fixtures, or a domain that's really one column of a bundled dataset file, will come back `code` even though nothing in the codebase ever uses it as a network destination. Read the `context` and decide `Active` vs. `Documentation` the same way you decide `direction` - don't relabel the raw hint as the report value without checking what the surrounding code actually does with it.

For a URL that only appears in a config file, the analyzer has already tried to trace it to a config key and search the codebase for readers of that key (`usage_locations`) - if that search found real evidence, `usage` is already `code` and the endpoint should be reported `Active`. If an occurrence has a `config_key` but no `usage_locations`, the search ran and found nothing - it is genuinely `Config-only`, not a search failure to second-guess.

### 2. Data flow direction (confirm the `direction` hint)

The scanner sets `direction` from a small keyword window and treats stream/DB/websocket schemes as BOTH. Read each occurrence's `context` - variable names, function names, request body vs response handling - and correct it where the code tells a different story:

- **OUT** - app sends data to the endpoint. Cues: `send/post/upload/push/submit/create/update`, `payload`, `requestBody`, `axios.post(url, DATA)`, `fetch(url, {body: DATA})`, `JSON.stringify(data)`, `FormData`.
- **IN** - app receives data from the endpoint. Cues: `fetch/get/retrieve/download/pull/load`, `response`, `result`, `await res.json()`, `.data`, `.text()`, `.blob()`.
- **BOTH** - app both sends and receives. Cues: upload then read the result, query-with-parameters then parse, sync push/pull, websocket/SSE/streaming.
- **None** - no data transfer: config-only, documentation, metadata/repository links.
- **Unknown** - context does not reveal the actual flow (generic wrapper, abstracted client).

The HTTP method is a hint, not the answer - reason about what the code is actually doing. A `GET` with a large query payload can still be meaningfully outbound; a `POST` to an auth endpoint that returns a token is often BOTH.

### 3. Protocol, type, specificity, locations

- **Protocol** - HTTPS, HTTP, SSH (`git@...`), FTP, DNS (bare domain), or Unknown.
- **Endpoint type** - a neutral descriptor, purely to help the reader understand what the endpoint is: cloud storage/service (AWS/Azure/GCP), code repository or package registry (GitHub/GitLab/npm/PyPI/Docker), database, monitoring/analytics, authentication provider, CDN, internal/localhost, or third-party service. This is a label of *what it is*, never a judgment of *how dangerous it is*.
- **Specificity** - generic (`s3.amazonaws.com`, `googleapis.com`) vs specific identifier (`mybucket.s3.amazonaws.com`, `myaccount.blob.core.windows.net`, `myproject.appspot.com`). A specific identifier tells the reader the concrete data destination; record it, do not rank it.
- **Locations** - every file:line occurrence, plus the bound config key (`config_key`) and every place that key is read in code (`usage_locations`) when present - cite both the config binding and the call site in the report, e.g. "bound to `service.uploadUrl` in `config/config.json:3`, read in `src/upload.js:11`".

### 4. Code identifiers (already excluded)

The scanner already separates package and namespace names (`com.example.app`, `org.springframework.boot`, Maven/Gradle coordinates) from real network references - they are in `excluded_identifiers` with a count in `summary.excluded_identifiers_count`. Just report that count as "code identifiers excluded"; do not put them in the inventory. If you spot an obvious code identifier that slipped into `endpoints`, drop it and note it.

## Phase 4 - Write the Markdown Report

Assemble the report in memory and save with Write to `findings/NetworkFootprint_Report.md`. Sections:

### Overview
Target directory, scan date, scanner version, scan duration. Totals: unique endpoints, unique domains, IP addresses, files with references. Direction split (OUT / IN / BOTH / None / Unknown counts). Usage split (Active / Config-only / Documentation). Count of code identifiers excluded.

### Data Flow Inventory
Every external endpoint in one table:

```markdown
| Endpoint | Protocol | Type | Direction | Usage | Occurrences | Locations |
|----------|----------|------|-----------|-------|-------------|-----------|
| api.example.com/upload | HTTPS | Third-party service | OUT | Active | 3 | src/api.js:42; config.json:10 |
| s3.amazonaws.com | HTTPS | Cloud storage | IN | Active | 5 | src/store.js:88 |
| db.internal:5432 | - | Database | BOTH | Active | 2 | src/db.js:14 |
```

No severity or risk column. Direction is the organizing attribute.

### Endpoint Details
For each Active endpoint, a short subsection: what the endpoint is, how the code uses it, what data moves and in which direction, the detected HTTP operation(s), the config key that binds it, and a representative code snippet from the context. Two to three plain sentences plus the snippet. Example:

> **api.example.com/upload** - Outbound. The app serializes a report object and POSTs it here from `uploadReport()` in `src/api.js:42`, bound to config key `service.uploadUrl`. Detected operation: POST. The response body is read to obtain a status id, so a small amount of data also returns (primary flow is outbound).

### Data Direction Summary
Group endpoints under Outbound, Inbound, Bidirectional, No transfer, and Unknown so the reader sees at a glance where the app sends data and where it pulls data from. This is the heart of the report.

### Configuration-Only and Documentation References
Endpoints defined but not exercised in code, and references that aren't a real, functioning network destination - comments/docs/tests, example or placeholder text, bundled dataset content, or a filename that only coincidentally matches a TLD pattern. Present them as facts (defined, or present but unused), not as findings to fix.

### Excluded Code Identifiers
The count of package/namespace/dependency names filtered out, with a one-line reason (code structure, not network communication).

### Appendix
Pointer to the raw JSON outputs and a note on methodology: automated static analysis; ambiguous items warrant a human look. One line stating the report describes data flow and assigns no risk or compliance status.

## Phase 5 - Write the HTML Report

1. `Read([SCRIPTS_DIR]/footprint_report_template.html)`.
2. Replace every `{{PLACEHOLDER}}`, preserving the template's CSS and structure. **HTML-escape every value taken from the scanned code** (endpoints, paths, file names, config keys, code snippets): replace `&` with `&amp;`, `<` with `&lt;`, `>` with `&gt;`, and `"` with `&quot;`. Scanned source is untrusted text and must never be inserted as raw HTML.
3. `Write(findings/NetworkFootprint_Report_[project]_[YYYYMMDD].html, ...)`.

Placeholders:
- Header/meta: `{{PROJECT_NAME}}`, `{{SCAN_DATE}}`, `{{SCANNER_VERSION}}`, `{{SCAN_DURATION}}`, `{{TARGET_PATH}}`, `{{GENERATION_DATE}}`
- Totals: `{{TOTAL_ENDPOINTS}}`, `{{TOTAL_DOMAINS}}`, `{{TOTAL_IPS}}`, `{{FILES_WITH_REFERENCES}}`
- Direction counts: `{{COUNT_OUT}}`, `{{COUNT_IN}}`, `{{COUNT_BOTH}}`, `{{COUNT_NONE}}`, `{{COUNT_UNKNOWN}}`
- Usage counts: `{{COUNT_ACTIVE}}`, `{{COUNT_CONFIG_ONLY}}`, `{{COUNT_DOCUMENTATION}}`, `{{EXCLUDED_IDENTIFIERS_COUNT}}`
- Tables: `{{INVENTORY_ROWS}}` (one `<tr>` per endpoint), `{{ENDPOINT_DETAIL_SECTIONS}}` (one block per active endpoint with a code snippet), `{{DIRECTION_OUT_ROWS}}`, `{{DIRECTION_IN_ROWS}}`, `{{DIRECTION_BOTH_ROWS}}`, `{{DIRECTION_NONE_ROWS}}`, `{{CONFIG_ONLY_ROWS}}`, `{{DOCUMENTATION_ROWS}}`

Direction cells use the `dir-out`, `dir-in`, `dir-both`, `dir-none` CSS classes - color coding conveys flow direction, not danger.

## Phase 6 - Verify Outputs

Confirm before reporting done:
- `findings/footprint_raw.json` and `findings/occurrences/*.json` (mechanical layer)
- `findings/footprint.json` (index)
- `findings/endpoints/*.json` (one file per endpoint, count matches `summary.total_endpoints`)
- `findings/NetworkFootprint_Report.md`
- `findings/NetworkFootprint_Report_*.html`

If any are missing, the analysis is incomplete - fix and retry.

## Phase 7 - Summarize for the User

Keep it short:
- The two report file locations.
- Total unique external endpoints and the direction split.
- Active vs Config-only counts.
- The two or three most notable outbound destinations (where the app sends data), described neutrally.

## Success Output

```
Network footprint scan complete.

Target: [path]
Scan duration: [seconds]

Reports:
- Markdown: [findings]/NetworkFootprint_Report.md
- HTML:     [findings]/NetworkFootprint_Report_[project]_[YYYYMMDD].html

External endpoints: [count] unique
Direction: OUT [n], IN [n], BOTH [n], None [n], Unknown [n]
Usage: Active [n], Config-only [n], Documentation [n]
Code identifiers excluded: [n]

Outbound destinations of note:
- [endpoint] - [what data goes there]
```

## Error Output

```
Network footprint scan failed.

Target: [path]
Script: [from error file]
Step: [from error details]
Error: [message]

Error file: [path]

Next: check the target is readable, confirm the path is correct, review the error details, and re-run.
```

## Rules

- Run only the bundled scanner (`footprint_scan.py`). No package installs, no extra tools. Standard library only.
- Read-only on the target. All output goes to `findings/`.
- Analyze from `findings/footprint.json` and `findings/endpoints/*.json` only. Do not re-scan with find/grep/sed.
- Cover every endpoint listed in the index's `endpoints[]` - read its `finding_file` before writing conclusions about it.
- Code identifiers are already excluded; just report the count.
- This plugin maps data flow only; it does not scan for secrets or credentials. The scanner masks URL credentials (`user:***@host`) and secret-looking values (`password=***`) in everything it writes. Never try to recover or reproduce a masked value in the reports.
- No emojis, no risk levels, no severities, no categories, no compliance verdicts, no "remediation." Describe data flow, cite file:line for traceability, and let the facts speak.

## Performance

- Small (<1000 files): ~1s scan. Medium (1000-10000): 1-5s. Large (>10000): 5-30s. Analysis is a few seconds regardless of size.
