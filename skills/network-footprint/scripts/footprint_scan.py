#!/usr/bin/env python3
"""
Network Footprint - entry point.

Scans a codebase for every external reference (any protocol) and writes the
findings the agent reads, in two layers:

    <target>/findings/footprint_raw.json   - index of the scanner's raw,
                                              pre-grouping occurrences
    <target>/findings/occurrences/*.json   - one file per raw occurrence
                                              (mechanical layer, unenriched)

    <target>/findings/footprint.json       - index: meta, summary, one row per
                                              endpoint with a pointer to its
                                              finding file
    <target>/findings/endpoints/*.json     - one file per endpoint (finding),
                                              grouped and enriched with
                                              direction/usage hints and, where
                                              a URL is config-bound, the
                                              config key and every place in
                                              code that reads it

Splitting one file per finding (at both layers) keeps each chunk small enough
for an LLM to read and reason about individually, instead of loading every
occurrence of every endpoint into context at once.

This also keeps the scan itself memory-bounded: the scanner writes each
occurrence to disk as it's found rather than accumulating the whole project's
matches in memory, and the analyzer reads occurrences back one host at a time
rather than building one big report - so peak memory stays roughly constant
regardless of project size or how large `context_lines` is configured.

Usage:
    python footprint_scan.py <target_dir>
"""
import json
import os
import sys
import time
import traceback
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import footprint_network_scanner as scanner   # noqa: E402
import footprint_config_analyzer as analyzer  # noqa: E402


def main(argv):
    if len(argv) < 2:
        print("Usage: python footprint_scan.py <target_dir>")
        return 2

    target = os.path.abspath(argv[1])
    if not os.path.isdir(target):
        print(f"Error: not a directory: {target}")
        return 2

    findings_dir = os.path.join(target, "findings")
    os.makedirs(findings_dir, exist_ok=True)
    out_path = os.path.join(findings_dir, "footprint.json")

    try:
        cfg = scanner.load_config()
        start = time.time()

        # Scans and writes each occurrence straight to disk as it's found -
        # never holds the full project's matches (with context) in memory.
        raw_index = scanner.scan_and_write(target, cfg, findings_dir)
        meta = {
            "target": target,
            "scanned_at": datetime.now().isoformat(timespec="seconds"),
            "scanner_version": cfg.get("version", "unknown"),
            "duration_seconds": round(time.time() - start, 3),
        }
        raw_path = os.path.join(findings_dir, "footprint_raw.json")
        with open(raw_path, "w", encoding="utf-8") as f:
            json.dump(raw_index, f, indent=2)

        # Reads occurrences back one host's worth at a time and writes each
        # endpoint file as it goes - never builds one big in-memory report.
        index = analyzer.build_and_write_findings(findings_dir, raw_index, cfg, meta)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(index, f, indent=2)
    except Exception as exc:  # noqa: BLE001
        err_path = os.path.join(findings_dir, "footprint_error.json")
        with open(err_path, "w", encoding="utf-8") as f:
            json.dump({
                "error": str(exc),
                "type": type(exc).__name__,
                "traceback": traceback.format_exc(),
                "target": target,
            }, f, indent=2)
        print(f"Scan failed: {exc}\nDetails written to {err_path}")
        return 1

    s = index["summary"]
    d = s["by_direction"]
    print("Network footprint scan complete.")
    print(f"  Files scanned:      {s['files_scanned']}")
    print(f"  External endpoints: {s['total_endpoints']}")
    print(f"  Direction:          OUT {d['OUT']}  IN {d['IN']}  BOTH {d['BOTH']}  "
          f"NONE {d['NONE']}  UNKNOWN {d['UNKNOWN']}")
    print(f"  Protocols:          {', '.join(s['schemes']) or '(none)'}")
    print(f"  Public IPs:         {len(s['public_ips'])}")
    print(f"  Raw occurrences:    {os.path.join(findings_dir, 'occurrences')}/ "
          f"({len(raw_index['references'])} files)")
    print(f"  Index:              {out_path}")
    print(f"  Findings:           {os.path.join(findings_dir, 'endpoints')}/ "
          f"({len(index['endpoints'])} files)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
