# Sample App - Expected Analysis (Answer Key)

This file is the test oracle for `sample-app/`. It lives **outside** the scan target
so it does not pollute the scan. Point the analyzer at `samples/sample-app` and compare
its report to the table below.

Run:

```bash
python skills/network-footprint/scripts/footprint_scan.py "$(pwd)/samples/sample-app"
```

This writes `samples/sample-app/findings/footprint_raw.json` + `occurrences/*.json` (the
scanner's raw, pre-grouping layer) and `samples/sample-app/findings/footprint.json` (an
index) + one file per endpoint under `samples/sample-app/findings/endpoints/` (the
analyzer's grouped, enriched layer). Then have the Network Footprint skill/command read
the latter and produce the report. The report should match these expectations.

## Expected endpoints (data flow inventory)

| Endpoint | Protocol | Type | Direction | Usage | Where |
|----------|----------|------|-----------|-------|-------|
| api.acme-service.com/v1/upload | HTTPS | Third-party service | OUT | Active | upload.js (config.service.uploadUrl) |
| acme-artifacts.s3.us-east-2.amazonaws.com | HTTPS | Cloud storage (specific bucket) | OUT | Active | upload.js |
| collector.mixpanel.com/track | HTTPS | Analytics | OUT | Active | upload.js |
| api.datadoghq.com/api/v1/series | HTTPS | Monitoring | OUT | Active | services/db.py |
| api.acme-service.com/v1/users/{id} | HTTPS | Third-party service | IN | Active | fetch.js |
| storage.googleapis.com/acme-public | HTTPS | Cloud storage (generic) | IN | Active | fetch.js |
| registry.npmjs.org | HTTPS | Package registry | IN | Active | fetch.js |
| api.exchangerate.host/latest | HTTPS | Third-party service | IN | Active | services/db.py |
| status.acme-service.com/v1/health | HTTPS | Third-party service | IN | Active | legacy/LegacyClient.java |
| api.docparser.io/process | HTTPS | Third-party service | BOTH | Active | sync.js |
| stream.acme-realtime.com/socket | WSS | Realtime stream | BOTH | Active | sync.js |
| 52.20.16.7:5432 (postgres) | - | Database | BOTH | Active | services/db.py |
| 54.230.0.10:6514 (syslog) | - | Log forwarding | BOTH/OUT | Active | services/net.py |
| stream.acme-realtime.com | WSS | Realtime stream | BOTH | Active | sync.js (captured as a wss:// endpoint) |
| s3.us-east-2.amazonaws.com | HTTPS | Cloud storage (generic) | None | Config-only | config/settings.yaml |
| acme.us.auth0.com | HTTPS | Auth provider | IN/None | Config-only* | config/settings.yaml |
| hooks.billing-vendor.com/v2/events | HTTPS | Third-party webhook | None | Config-only | config/config.json |
| export.old-partner.net/api/dump | HTTPS | Third-party service | None | Config-only | config/config.json |
| cdn.jsdelivr.net | HTTPS | CDN | None/IN | Config-only | config/config.json |
| examplePublicKey@o0.ingest.sentry.io | HTTPS | Error tracking | None | Config-only | config/settings.yaml |
| docs.acme-service.com/reference | - | Documentation | - | NOT detected | README.md (.md not scanned) |
| wiki.internal.example/deploy | - | Documentation | - | NOT detected | README.md (.md not scanned) |

\* auth0 is referenced only in config in this sample; if the analyzer sees no code usage it is Config-only.

The last two rows are listed to show a known non-detection: `.md` files are excluded, so
these do not appear in the report. See "Scanner behavior notes" below.

## Expected public IP addresses

Captured (globally-routable):

- `52.20.16.7` - Postgres host (services/db.py)
- `54.230.0.10` - syslog host (services/net.py)

NOT captured as external (private / loopback / non-global):

- `192.168.10.5` - private range
- `127.0.0.1` - loopback
- `localhost` - loopback name

## Scanner behavior notes (important when reading the report)

This scanner makes some deliberate choices - the sample is built around them:

- **`.md` files are not scanned.** So the two URLs in `sample-app/README.md`
  (`docs.acme-service.com`, `wiki.internal.example`) are intentionally NOT detected.
  README is there for a human reading the sample, not as scan input.
- **URLs inside code comments are excluded** from the network scan (treated as
  documentation). Only URLs in live code and config are captured. As a result the
  "Documentation references" section of the report is usually empty - that is expected.
- **Only globally-routable IPs are captured.** Private ranges (10/8, 172.16/12,
  192.168/16), loopback, and reserved/documentation ranges (e.g. 198.51.100.x,
  203.0.113.x) are filtered out as non-external.
- **Any protocol is captured**, not just HTTP. `wss://`, `postgres://`, `redis://`,
  `ssh`, `git@`, etc. are all recognized. So `wss://stream.acme-realtime.com` is a
  first-class endpoint, and `postgres://...@52.20.16.7` is captured with its host IP.
- **No secrets scanning.** The `user:pass` in the Postgres URL is captured only as part
  of the endpoint (host + scheme); the plugin does not detect or report credentials.
- **Config-bound URLs get traced to their reader in code.** `api.acme-service.com`'s
  `/v1/upload` occurrence in `config/config.json:3` is bound to config key
  `service.uploadUrl`; the analyzer searches the codebase and finds it read at
  `src/upload.js:11` via `axios.post(CONFIG.service.uploadUrl, payload, ...)`
  (dotted property access), with `detected_operation` `axios.post` / `out`. This is why
  that endpoint is Active/OUT for that path even though the URL literal itself never
  appears in `upload.js`. The six genuinely config-only endpoints
  (`s3.us-east-2.amazonaws.com`, `acme.us.auth0.com`, `hooks.billing-vendor.com`,
  `export.old-partner.net`, `cdn.jsdelivr.net`, `o0.ingest.sentry.io`) get a `config_key`
  extracted too, but the same search finds no reader for any of them - confirming they
  really are unused, not just missed.

## Expected exclusions (code identifiers, NOT network references)

From `legacy/LegacyClient.java`, these look like domains but are Java namespaces and
must be excluded from the inventory:

- `com.acme.sample.legacy` (package)
- `org.springframework.boot`, `org.springframework.web.client` (imports)
- `com.fasterxml.jackson.databind` (import)
- `java.net.http` (import)

## Direction tally (rough)

- OUT: ~4 (upload API, S3 bucket, mixpanel, datadog)
- IN: ~5 (users API, gcs, npm, exchangerate, status)
- BOTH: ~4 (docparser, websocket, postgres, syslog socket)
- Config-only: ~6 (generic s3, billing webhook, legacy export, cdn, sentry, auth0)
- Documentation: 0 detected (README `.md` is not scanned - see behavior notes)

Counts are approximate - the point is that each category is represented so you can
confirm the analyzer classifies direction and usage correctly. The scanner's direction
is a keyword-based hint; a couple of endpoints (e.g. the syslog socket IP, or a Java
constant defined on a separate line from its use) may come back UNKNOWN until the agent
refines them from the stored context. That is expected.
