# Network Footprint

Map how data moves in and out of a codebase. This command scans a target directory for every external network reference (URLs, DNS names, IP addresses, cloud and database endpoints), determines the direction data flows for each one (IN, OUT, BOTH, or none), notes whether the reference is actively used in code or configuration-only, and produces a descriptive network footprint report.

This is a factual inventory, not a security audit. Do not assign risk levels, severities, or compliance verdicts. Report what connects to what, in which direction, and where in the source it happens.

## Ground Rules

- **You are the agent.** You run the bundled scanner, read its JSON output, analyze it, and write the reports yourself using the Read and Write tools. Do not create helper Python scripts to generate reports.
- **Only run the bundled scanner** (`footprint_scan.py`). Do not install packages or add tools. The scanner uses the Python standard library only and runs on Windows, Linux, and macOS.
- **Do not modify the target codebase.** All output goes into a `findings/` directory inside the target.
- **No emojis** in generated reports. Use plain, professional text.
- **No risk framing.** Never label a finding critical/high/medium/low, never rank endpoints by danger, never recommend "remediation." Describe the data flow.

## Step 1 - Confirm the Target

Ask the user which directory to analyze if they have not said. Confirm the path exists and is readable, then convert it to an absolute path.

## Step 2 - Locate the Bundled Scripts

1. Use Glob to find the plugin: `**/.claude-plugin/plugin.json`, and identify the `network-footprint` plugin directory.
2. The scripts live in `[plugin-dir]/skills/network-footprint/scripts/`. Confirm these exist:
   - `footprint_scan.py` (wrapper - run this)
   - `footprint_network_scanner.py`
   - `footprint_config_analyzer.py`
   - `footprint_report_template.html`

Call this directory `[SCRIPTS_DIR]` for the rest of the workflow.

## Step 3 - Run the Scan

```bash
python [SCRIPTS_DIR]/footprint_scan.py /absolute/path/to/target
```

The wrapper runs synchronously. Wait for it to finish before continuing. It performs:

- Network reference scanning (HTTP/HTTPS URLs, DNS names, IP addresses)
- Configuration analysis (endpoints defined in config files, and where code reads them)
- Usage detection (is each reference actually exercised in code, or config-only)
- HTTP operation detection (GET/POST/PUT/DELETE near each usage) to support direction analysis

The scan writes findings in two layers, each split one-file-per-finding so every chunk stays small enough to analyze on its own:

- `target/findings/footprint_raw.json` + `target/findings/occurrences/*.json` - the scanner's raw, pre-grouping occurrences (mechanical, not enriched). You normally don't need to read these.
- `target/findings/footprint.json` + `target/findings/endpoints/*.json` - the analyzer's grouped, enriched output. This is what you read in Step 5.

(or `footprint_error.json` if the scan fails)

## Step 4 - Verify the Scan Succeeded

```bash
ls /absolute/path/to/target/findings/footprint_error.json 2>/dev/null
```

If `footprint_error.json` exists, read it, report the error to the user, and stop. Otherwise confirm `findings/footprint.json` exists. If it is missing with no error file, report the failure and stop.

## Step 5 - Read the Findings

Findings are split one file per endpoint so each is a small, self-contained chunk.

Read `findings/footprint.json` first - it is the **index**:

- `meta` - target, scan time, scanner version, duration.
- `summary` - `total_endpoints`, `files_scanned`, `by_direction`, `by_usage`, `schemes`, `public_ips`, `excluded_identifiers_count`.
- `endpoints[]` - one row per external host, already grouped and de-duplicated. Each row has `id`, `endpoint`, `host`, `protocol`, `schemes`, `is_ip`, `ports`, `paths`, a `direction` hint, a `usage` hint, `occurrence_count`, `config_keys` (if any occurrence is config-bound), and `finding_file` - the path (relative to `findings/`) to that endpoint's full record.
- `excluded_identifiers` - package/namespace names already filtered out of the network set.

Then, for every row, `Read(findings/[finding_file])` to get that endpoint's `occurrences[]` (`file`, `line`, `in_comment`, `line_text`, `context`). Process finding files individually or in small batches rather than trying to hold them all at once.

For a URL found only in a config file, its occurrence may also carry `config_key` (the config key it's bound to, e.g. `service.uploadUrl`) and `usage_locations[]` (every place in the codebase that reads that key, found by searching source files for quoted key access, `config.get()`, `process.env.KEY`, dotted property access like `CONFIG.service.uploadUrl`, Spring `@Value`, etc.). Each usage location includes `detected_operation` (e.g. `axios.post` / direction `out`) when a recognizable HTTP call was found near it. When `usage_locations` exist, the endpoint's `usage` is already `code` and its `direction` hint already accounts for them.

The scanner captures references of **any protocol** (http, https, ws/wss, ftp, ssh, postgres, redis, mongodb, amqp, grpc, `git@` SSH, plus bare public domains and public IPs) and already excludes internal hosts (localhost, private/reserved IPs). Do not re-scan with find/grep/sed - everything is in `footprint.json` and `findings/endpoints/*.json`.

## Step 6 - Analyze Each External Reference

The scanner attaches a `direction` and `usage` hint to every endpoint and has already separated code identifiers. Confirm or correct each hint from the occurrence `context`, then determine three things and nothing more:

**a) Usage status** - the scanner's raw `usage` hint (`code`/`config`/`documentation`) only tells you which *kind of file* the reference was found in - it is not evidence of genuine usage. A string that looks like a domain but is really test-fixture text, an example message, or a bundled dataset's column value still comes back `code`. Read the context and decide the reported status the same way you decide direction:
- `Active` - the reference is genuinely read/called/connected to in code (an HTTP client call, a loader, a socket, etc. - use `usage_locations` and `detected_operation` as evidence when present)
- `Config-only` - defined in configuration or present in source, but not exercised in code
- `Documentation` - not a real, functioning network reference: comments, README/markdown mentions, example/test-fixture text, dataset content, or a filename that only coincidentally matches a TLD - regardless of whether it sits in a live, non-comment source line

**b) Data flow direction** - read the usage context (variable names, function names, request bodies, response handling, detected HTTP method) and classify:
- `OUT` - the app sends data to the endpoint (uploads, posts, submits, pushes; `axios.post(url, payload)`, `requests.post(...)`, `JSON.stringify(data)` in a body)
- `IN` - the app receives data from the endpoint (fetches, downloads, pulls; `const data = await res.json()`, `.data`, response handling)
- `BOTH` - the app both sends and receives (upload then read the result, sync operations, streaming/websocket)
- `None` - no data transfer occurs (documentation, metadata, config-only, unused)
- `Unknown` - context is insufficient to tell

**c) Where it appears** - file paths and line numbers for every occurrence, and the config key(s) it is bound to if any.

Also record, factually and without any risk labeling:
- **Protocol** - HTTPS, HTTP, SSH (`git@...`), FTP, DNS (bare domain), or Unknown.
- **Endpoint type** - a neutral descriptor of what it is: cloud storage/service (AWS/Azure/GCP), code repository or package registry (GitHub/npm/PyPI/Docker), database, monitoring/analytics, authentication provider, CDN, internal/localhost, or third-party service. This is description, not judgment.
- **Specificity** - whether the endpoint is generic (`s3.amazonaws.com`) or carries a specific identifier (`mybucket.s3.amazonaws.com`, `myaccount.blob.core.windows.net`). Useful for knowing the concrete data destination.

### Distinguishing real endpoints from code artifacts

The DNS pattern also catches package and namespace names (`com.example.app`, `org.springframework.boot`, Python modules). These are not network references. Using the file path and surrounding lines (import/package/require statements), separate:

- **Network references** - domains used in URLs, connection strings, API calls, service endpoints. Include these in the report.
- **Code artifacts** - package names, namespaces, dependency coordinates. Exclude from the data flow tables and report their count separately as "code identifiers excluded."

## Step 7 - Write the Markdown Report

Build the report in memory from your analysis and save it with the Write tool to `findings/NetworkFootprint_Report.md`. Do not generate it via a script. Structure:

### Overview
- Target directory, scan date, scanner version, scan duration.
- Totals: unique external endpoints, unique domains, IP addresses, files with external references.
- Direction breakdown: how many endpoints are OUT, IN, BOTH, None, Unknown.
- Usage breakdown: Active vs Config-only vs Documentation.
- Count of code identifiers excluded as non-network artifacts.

### Data Flow Inventory
One table listing every external endpoint:

```markdown
| Endpoint | Protocol | Type | Direction | Usage | Occurrences | Locations |
|----------|----------|------|-----------|-------|-------------|-----------|
| api.example.com/upload | HTTPS | Third-party service | OUT | Active | 3 | src/api.js:42; config.json:10 |
```

Direction values: OUT, IN, BOTH, None, Unknown. No severity column.

### Endpoint Details
For each Active endpoint, a short subsection: what the endpoint is, how the code uses it, what data moves and in which direction, the detected HTTP operation(s), the config key binding it, and a representative code snippet from the context. Two to three sentences of plain description each.

### Data Direction Summary
Group endpoints by direction (Outbound / Inbound / Bidirectional / No transfer / Unknown) so the reader can see, at a glance, where the app sends data and where it pulls data from.

### Configuration-Only and Documentation References
List endpoints that are defined but not exercised in code, and references that aren't a real, functioning network destination - comments/docs/tests, example or placeholder text, bundled dataset content, or a filename that only coincidentally matches a TLD. Note them as such - not as problems.

### Excluded Code Identifiers
State the count of package/namespace/dependency names filtered out of the network analysis and why (they are code structure, not network communication).

### Appendix
Point to the raw JSON outputs and note the scan methodology (automated static analysis; a human should confirm anything ambiguous). Include a one-line note that this report describes data flow and does not assign risk or compliance status.

## Step 8 - Write the HTML Report

1. Read the template at `[SCRIPTS_DIR]/footprint_report_template.html`.
2. Replace every `{{PLACEHOLDER}}` with your analyzed data, keeping the template's CSS and structure.
3. Save to `findings/NetworkFootprint_Report_[project]_[YYYYMMDD].html`.

The template placeholders are:
- `{{PROJECT_NAME}}`, `{{SCAN_DATE}}`, `{{SCANNER_VERSION}}`, `{{SCAN_DURATION}}`, `{{TARGET_PATH}}`
- `{{TOTAL_ENDPOINTS}}`, `{{TOTAL_DOMAINS}}`, `{{TOTAL_IPS}}`, `{{FILES_WITH_REFERENCES}}`
- `{{COUNT_OUT}}`, `{{COUNT_IN}}`, `{{COUNT_BOTH}}`, `{{COUNT_NONE}}`, `{{COUNT_UNKNOWN}}`
- `{{COUNT_ACTIVE}}`, `{{COUNT_CONFIG_ONLY}}`, `{{COUNT_DOCUMENTATION}}`, `{{EXCLUDED_IDENTIFIERS_COUNT}}`
- `{{INVENTORY_ROWS}}` - one `<tr>` per endpoint (endpoint, protocol, type, direction, usage, occurrences, locations)
- `{{ENDPOINT_DETAIL_SECTIONS}}` - one block per active endpoint with description and a code snippet
- `{{DIRECTION_OUT_ROWS}}`, `{{DIRECTION_IN_ROWS}}`, `{{DIRECTION_BOTH_ROWS}}`, `{{DIRECTION_NONE_ROWS}}` - endpoints grouped by direction
- `{{CONFIG_ONLY_ROWS}}`, `{{DOCUMENTATION_ROWS}}` - non-active references
- `{{GENERATION_DATE}}`

Use the `dir-out`, `dir-in`, `dir-both`, `dir-none` CSS classes on direction cells so directions are color-coded by flow (not by risk).

## Step 9 - Verify Outputs Exist

Confirm all of these are present before reporting done:
- `findings/footprint_raw.json` and `findings/occurrences/*.json` (mechanical layer)
- `findings/footprint.json` (index)
- `findings/endpoints/*.json` (one file per endpoint, count matches `summary.total_endpoints`)
- `findings/NetworkFootprint_Report.md`
- `findings/NetworkFootprint_Report_*.html`

If any are missing, the analysis is incomplete - fix and retry.

## Step 10 - Summarize for the User

Report briefly:
- Where the two report files are.
- Total unique external endpoints, and the direction split (how many OUT / IN / BOTH / None / Unknown).
- How many endpoints are actively used vs configuration-only.
- The two or three most notable outbound destinations (where the app sends data), described neutrally.

## Reference: Direction Cues

**Outbound (OUT):** function names like `send`, `post`, `upload`, `push`, `submit`, `create`, `update`; variables like `payload`, `requestBody`, `dataToSend`; `axios.post(url, DATA)`, `fetch(url, {body: DATA})`, `JSON.stringify(data)`, `FormData`.

**Inbound (IN):** function names like `fetch`, `get`, `retrieve`, `download`, `pull`, `load`; variables like `response`, `result`, `data`; `await res.json()`, `.then(r => r.data)`, `.text()`, `.blob()`.

**Bidirectional (BOTH):** upload followed by reading the response, query-with-parameters then parse, sync push/pull, websocket/SSE/streaming.

**None:** config-only, documentation, comments, test fixtures, repository/metadata links.

**Unknown:** generic wrapper or abstracted client where the context does not reveal the actual flow.

## Output Files

After a successful run, `findings/` contains:

- `footprint_raw.json` - index of the scanner's raw, pre-grouping occurrences
- `occurrences/*.json` - one file per raw occurrence (mechanical, unenriched)
- `footprint.json` - the index (summary, and one row per endpoint with a pointer to its finding file)
- `endpoints/*.json` - one file per endpoint, each with its full occurrences and context, plus `config_key`/`usage_locations` where a config-bound URL's reader was found in code
- `NetworkFootprint_Report.md` - descriptive markdown report
- `NetworkFootprint_Report_[project]_[date].html` - formatted HTML report
