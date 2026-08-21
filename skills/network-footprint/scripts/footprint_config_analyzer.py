#!/usr/bin/env python3
"""
Network Footprint - config analyzer.

Takes the raw references from the network scanner, groups them by host, and
works out for each endpoint:

  - protocol / scheme(s)
  - a data-flow DIRECTION hint  (OUT, IN, BOTH, NONE, UNKNOWN)
  - a USAGE hint                (code, config, documentation - which kind of
                                 file it was found in; not a claim that it's
                                 genuinely used as a network reference)
  - every file:line where it appears, with context
  - for a URL found in a config file: the config key it is bound to, and
    every place in source code that reads that key (with context and any
    detected HTTP operation nearby) - so a config-only-looking endpoint that
    is actually read and called from code isn't misreported as unused

These are hints derived from simple keyword, file-type, and cross-file
reference-search heuristics. They give an immediately useful report; the
agent can refine them from the context that travels with each occurrence.

Standalone:
    python footprint_config_analyzer.py <raw_references.json> [report.json] [target_dir]

target_dir enables the config-key usage search (it needs the codebase to
search); without it, endpoints are still grouped and hinted as before.
"""
import json
import os
import re
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_CONFIG = Path(os.getenv("FOOTPRINT_CONFIG", HERE / "footprint_config.json"))


def load_config(path=DEFAULT_CONFIG):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _word_set(text):
    return set(re.findall(r"[a-z]+", text.lower()))


def _file_is_config(path, cfg):
    return path.lower().endswith(tuple(cfg["config_suffixes"]))


def _protocol(schemes, is_ip, cfg):
    names = cfg["protocol_names"]
    for s in schemes:
        if s in names:
            return names[s]
    if schemes:
        return schemes[0].upper()
    return "IP" if is_ip else "DNS"


def _direction(occurrences, schemes, cfg):
    """Direction hint for an ACTIVE endpoint, from a tight window around each use
    and, for config-bound endpoints, around every place in code that reads the
    config key (plus any HTTP operation detected there)."""
    if set(schemes) & set(cfg["stream_schemes"]):
        return "BOTH"  # sockets, DBs, streams, websockets are inherently two-way
    out_words = set(cfg["direction_hints"]["out"])
    in_words = set(cfg["direction_hints"]["in"])
    comment_prefixes = tuple(cfg["comment_prefixes"])
    out_found = in_found = False

    def scan_window(window):
        nonlocal out_found, in_found
        words = set()
        for ln in window:
            if ln.lstrip().startswith(comment_prefixes):
                continue
            words |= _word_set(ln)
        if words & out_words:
            out_found = True
        if words & in_words:
            in_found = True

    for occ in occurrences:
        if not occ["in_comment"]:
            ctx = occ["context"]
            c = occ.get("ctx_center", 0)
            scan_window(ctx[max(0, c - 1):c + 2])  # center line +/- 1
        for usage in occ.get("usage_locations", []):
            uc = usage.get("ctx_center", 0)
            scan_window(usage["context"][max(0, uc - 1):uc + 2])
            op = usage.get("detected_operation")
            if op and op.get("direction") == "out":
                out_found = True
            elif op and op.get("direction") == "in":
                in_found = True

    if out_found and in_found:
        return "BOTH"
    if out_found:
        return "OUT"
    if in_found:
        return "IN"
    return "UNKNOWN"


def _usage(occurrences, cfg):
    """Mechanical hint only: which kind of file this was found in - not a
    claim that it's genuinely used as a network reference. 'code' just means
    "a non-comment line in a non-config file"; a string that looks like a
    domain but is really test/example data still comes back 'code'. The
    agent is expected to confirm or correct this from context, same as
    direction - see the skill doc's "Usage status" section."""
    in_live_code = any(
        (not occ["in_comment"]) and not _file_is_config(occ["file"], cfg)
        for occ in occurrences
    )
    if in_live_code:
        return "code"
    if any(_file_is_config(occ["file"], cfg) and not occ["in_comment"] for occ in occurrences):
        return "config"
    return "documentation"


def _slugify(text):
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug or "endpoint"


def _context_window(lines, line_num, n):
    """1-indexed line_num -> (window_lines, center_offset), like the scanner's own window."""
    idx = line_num - 1
    lo, hi = max(0, idx - n), min(len(lines), idx + n + 1)
    return [lines[i] for i in range(lo, hi)], idx - lo


def _extract_yaml_key_path(lines, line_num):
    """Walk indentation upward from line_num to build a dotted YAML key path."""
    if line_num < 1 or line_num > len(lines):
        return None
    m = re.match(r"^(\s*)([^:]+):", lines[line_num - 1])
    if not m:
        return None
    target_indent = len(m.group(1))
    parts = [m.group(2).strip()]
    current_indent = target_indent
    for i in range(line_num - 2, -1, -1):
        line = lines[i]
        if not line.strip() or line.strip().startswith("#"):
            continue
        m2 = re.match(r"^(\s*)([^:]+):", line)
        if m2:
            indent = len(m2.group(1))
            if indent < current_indent:
                parts.insert(0, m2.group(2).strip())
                current_indent = indent
                if indent == 0:
                    break
    return ".".join(parts) if len(parts) > 1 else parts[0]


def _extract_json_key_path(data, needle):
    """Recursively search a parsed JSON document for a string value containing
    needle and return the dotted path to it."""
    def walk(obj, path):
        if isinstance(obj, dict):
            for key, value in obj.items():
                new_path = path + [key]
                if isinstance(value, str) and needle in value:
                    return ".".join(new_path)
                found = walk(value, new_path)
                if found:
                    return found
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                found = walk(item, path + [f"[{i}]"])
                if found:
                    return found
        return None
    return walk(data, [])


def _extract_config_key(abs_path, line_num, needle, lines_cache):
    """Given a config file and the line a URL was found on, work out the
    config key it is bound to (e.g. 'service.uploadUrl', 'DATABASE_URL')."""
    lines = lines_cache.get(abs_path)
    if lines is None:
        try:
            with open(abs_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except OSError:
            lines = []
        lines_cache[abs_path] = lines

    if line_num < 1 or line_num > len(lines):
        return None

    low = abs_path.lower()
    full_key = None

    if low.endswith((".yaml", ".yml")):
        full_key = _extract_yaml_key_path([ln.rstrip("\n") for ln in lines], line_num)
    elif low.endswith(".json"):
        try:
            data = json.loads("".join(lines))
            full_key = _extract_json_key_path(data, needle)
        except (json.JSONDecodeError, ValueError):
            full_key = None

    if not full_key:
        start, end = max(0, line_num - 11), min(len(lines), line_num + 10)
        window = "".join(lines[start:end])
        needle_re = re.escape(needle)
        for pat in (
            rf'^([^=\n]+)=.*{needle_re}',                       # properties / .env
            rf'^\s*([^:\n]+):\s*.*{needle_re}',                 # yaml/generic key: value
            rf'([A-Z_][A-Z0-9_]*)\s*=\s*["\'].*{needle_re}',    # source-level constant assignment
            rf'"([^"]+)"\s*:\s*"[^"]*{needle_re}',              # generic JSON "key": "...needle..."
        ):
            m = re.search(pat, window, re.MULTILINE)
            if m:
                full_key = m.group(1).strip()
                break

    if not full_key:
        return None
    parts = full_key.split(".")
    return {"full_key": full_key, "section": parts[0] if len(parts) > 1 else None, "key": parts[-1]}


def _detect_operation(window_lines, cfg):
    """Match a small context window against known HTTP client/framework call
    patterns to get a concrete detected operation (e.g. 'axios.post')."""
    text = "\n".join(window_lines)
    for pat in cfg.get("http_operation_patterns", []):
        try:
            if re.search(pat["regex"], text, re.IGNORECASE):
                return {"operation": pat["operation"], "direction": pat.get("direction")}
        except re.error:
            continue
    return None


def _index_source_files(target, cfg):
    """Walk the target once and return (rel_path, abs_path, ext) for every
    non-config text file - paths only, no content. Content is read on demand,
    one file at a time, inside _search_key_usage(), so the whole source tree
    is never held in memory at once regardless of project size."""
    files = []
    if not target or not os.path.isdir(target):
        return files
    exclude_dirs = set(cfg["exclude_dirs"])
    suffixes = tuple(cfg["exclude_suffixes"])
    max_bytes = cfg["max_file_size_kb"] * 1024
    for root, dirs, names in os.walk(target):
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        for name in names:
            if name.lower().endswith(suffixes):
                continue
            fp = os.path.join(root, name)
            rel = os.path.relpath(fp, target)
            if _file_is_config(rel, cfg):
                continue
            try:
                if os.path.getsize(fp) > max_bytes:
                    continue
            except OSError:
                continue
            files.append((rel, fp, os.path.splitext(fp)[1].lower()))
    return files


def _search_key_usage(source_files, config_info, cfg, ctx_n):
    """Search indexed source files for code that reads a config key, using the
    per-language patterns in cfg['config_key_patterns']. source_files is
    (rel_path, abs_path, ext) tuples - each file's content is read on demand
    and discarded before moving to the next, so only one file's text is ever
    resident at a time."""
    cap = cfg.get("max_usage_locations_per_key", 10)
    full_key = config_info["full_key"]
    key_esc = re.escape(full_key)
    key_upper_esc = re.escape(full_key.upper())
    section_esc = re.escape(config_info.get("section") or "")

    results = []
    for rel, abs_path, ext in source_files:
        lang_cfg = next(
            (lc for lc in cfg.get("config_key_patterns", {}).values()
             if isinstance(lc, dict) and ext in lc.get("extensions", [])),
            None,
        )
        if not lang_cfg:
            continue  # skip reading files whose extension has no patterns to check

        try:
            with open(abs_path, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
        except OSError:
            continue
        if "\x00" in text[:1024]:
            continue  # binary
        lines = text.splitlines()

        for template in lang_cfg.get("patterns", []):
            pattern = (template.replace("{KEY}", key_esc)
                                .replace("{KEY_UPPER}", key_upper_esc)
                                .replace("{SECTION}", section_esc))
            try:
                regex = re.compile(pattern, re.IGNORECASE)
            except re.error:
                continue
            for m in regex.finditer(text):
                line_num = text.count("\n", 0, m.start()) + 1
                window, center = _context_window(lines, line_num, ctx_n)
                results.append({
                    "file": rel, "line": line_num,
                    "line_text": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    "context": window, "ctx_center": center,
                    "detected_operation": _detect_operation(window, cfg),
                })
                if len(results) >= cap:
                    return results
    return results


def write_findings(report, findings_dir):
    """Split an already-built, fully in-memory report into one JSON file per
    endpoint (finding) under findings_dir/endpoints/, plus a lightweight
    index. Pairs with build_report() for standalone/small-scale use where
    holding the whole report in memory isn't a concern. The main pipeline
    uses build_and_write_findings() instead, which never builds one big
    report - it writes each endpoint file as it goes.

    Returns the index dict (the shape written to findings_dir/footprint.json).
    """
    endpoints_dir = os.path.join(findings_dir, "endpoints")
    # Wipe any findings from a previous run so stale per-endpoint files (from a
    # target that has since changed) can't linger alongside the new index.
    shutil.rmtree(endpoints_dir, ignore_errors=True)
    os.makedirs(endpoints_dir, exist_ok=True)

    width = max(3, len(str(len(report["endpoints"]))))
    index_endpoints = []
    for i, ep in enumerate(report["endpoints"], start=1):
        fid = str(i).zfill(width)
        fname = f"{fid}-{_slugify(ep['host'])}.json"
        finding = dict(ep)
        finding["id"] = fid
        with open(os.path.join(endpoints_dir, fname), "w", encoding="utf-8") as f:
            json.dump(finding, f, indent=2)

        index_row = {
            "id": fid,
            "host": ep["host"],
            "endpoint": ep["endpoint"],
            "protocol": ep["protocol"],
            "schemes": ep["schemes"],
            "is_ip": ep["is_ip"],
            "kind": ep["kind"],
            "ports": ep["ports"],
            "paths": ep["paths"],
            "direction": ep["direction"],
            "usage": ep["usage"],
            "occurrence_count": ep["occurrence_count"],
        }
        if "config_keys" in ep:
            index_row["config_keys"] = ep["config_keys"]
        index_row["finding_file"] = f"endpoints/{fname}"
        index_endpoints.append(index_row)

    return {
        "meta": report["meta"],
        "summary": report["summary"],
        "endpoints": index_endpoints,
        "excluded_identifiers": report["excluded_identifiers"],
    }


def build_and_write_findings(findings_dir, raw_index, cfg, meta=None):
    """Group the scanner's raw occurrence index by host and write one enriched
    finding file per endpoint - reading each occurrence's full content
    (including its context window) from findings_dir/occurrences/ only while
    its host group is being processed, then letting it go before moving to
    the next host. This is what the main pipeline (footprint_scan.py) uses.

    Unlike build_report()/write_findings() (kept for standalone/small-scale
    use), this never holds more than one host's occurrences - or one config
    search's source file - in memory at once, so peak memory stays roughly
    constant regardless of project size or how large context_lines is
    configured.

    Returns the index dict (also written to findings_dir/footprint.json).
    """
    cap = cfg["max_occurrences_per_endpoint"]
    ctx_n = cfg["context_lines"]
    target = (meta or {}).get("target")

    endpoints_dir = os.path.join(findings_dir, "endpoints")
    shutil.rmtree(endpoints_dir, ignore_errors=True)
    os.makedirs(endpoints_dir, exist_ok=True)

    # The raw index entries carry no context - grouping them by host is cheap
    # regardless of how project-wide occurrence count or context_lines scale.
    groups = {}
    for r in raw_index["references"]:
        groups.setdefault(r["host"], []).append(r)

    lines_cache = {}
    source_files_cache = {}

    def source_files():
        if "v" not in source_files_cache:
            source_files_cache["v"] = _index_source_files(target, cfg)
        return source_files_cache["v"]

    width = max(4, len(str(len(groups))))
    index_endpoints = []

    for eid, host in enumerate(sorted(groups), start=1):
        # Load only this host's occurrences (with full context) from disk.
        items = []
        for r in groups[host]:
            with open(os.path.join(findings_dir, r["occurrence_file"]), "r", encoding="utf-8") as f:
                items.append(json.load(f))

        schemes, ports, paths = [], [], []
        for r in items:
            if r["scheme"] and r["scheme"] not in schemes:
                schemes.append(r["scheme"])
            if r["port"] and r["port"] not in ports:
                ports.append(r["port"])
            if r["path"] and r["path"] not in paths:
                paths.append(r["path"])
        is_ip = items[0]["is_ip"]

        occurrences = []
        config_keys = set()
        for r in items:
            ctx, center = r.get("context", []), r.get("ctx_center", 0)
            occ = {
                "file": r["file"], "line": r["line"],
                "in_comment": r["in_comment"],
                "line_text": (ctx[center].strip() if ctx else r["raw"]),
                "context": ctx, "ctx_center": center,
            }
            if not r["in_comment"] and target and _file_is_config(r["file"], cfg):
                abs_path = os.path.join(target, r["file"])
                if os.path.isfile(abs_path):
                    config_info = _extract_config_key(abs_path, r["line"], r.get("raw") or host, lines_cache)
                    if config_info:
                        occ["config_key"] = config_info["full_key"]
                        usages = _search_key_usage(source_files(), config_info, cfg, ctx_n)
                        if usages:
                            occ["usage_locations"] = usages
                        config_keys.add(config_info["full_key"])
            occurrences.append(occ)

        usage = _usage(occurrences, cfg)
        if usage != "code" and any(o.get("usage_locations") for o in occurrences):
            usage = "code"  # config key is genuinely read in code
        direction = _direction(occurrences, schemes, cfg) if usage == "code" else "NONE"
        primary = schemes[0] if schemes else ("" if not is_ip else "")
        endpoint = f"{primary}://{host}" if primary else host

        entry = {
            "host": host,
            "endpoint": endpoint,
            "protocol": _protocol(schemes, is_ip, cfg),
            "schemes": schemes,
            "is_ip": is_ip,
            "kind": items[0]["kind"],
            "ports": ports,
            "paths": paths[:cap],
            "direction": direction,
            "usage": usage,
            "occurrence_count": len(items),
            "occurrences": occurrences[:cap],
        }
        if config_keys:
            entry["config_keys"] = sorted(config_keys)

        fid = str(eid).zfill(width)
        fname = f"{fid}-{_slugify(host)}.json"
        finding = dict(entry)
        finding["id"] = fid
        with open(os.path.join(endpoints_dir, fname), "w", encoding="utf-8") as f:
            json.dump(finding, f, indent=2)

        index_row = {
            "id": fid, "host": host, "endpoint": endpoint,
            "protocol": entry["protocol"], "schemes": schemes, "is_ip": is_ip,
            "kind": entry["kind"], "ports": ports, "paths": entry["paths"],
            "direction": direction, "usage": usage,
            "occurrence_count": entry["occurrence_count"],
        }
        if config_keys:
            index_row["config_keys"] = entry["config_keys"]
        index_row["finding_file"] = f"endpoints/{fname}"
        index_endpoints.append(index_row)
        # `items`/`occurrences` for this host fall out of scope here, before
        # the next host is loaded.

    def _count(field, values):
        return {v: sum(1 for e in index_endpoints if e[field] == v) for v in values}

    schemes_seen = sorted({s for e in index_endpoints for s in e["schemes"]})
    excluded = raw_index.get("excluded_identifiers", [])
    index = {
        "meta": meta or {},
        "summary": {
            "total_endpoints": len(index_endpoints),
            "total_occurrences": sum(e["occurrence_count"] for e in index_endpoints),
            "files_scanned": raw_index.get("files_scanned", 0),
            "by_direction": _count("direction", ["OUT", "IN", "BOTH", "NONE", "UNKNOWN"]),
            "by_usage": _count("usage", ["code", "config", "documentation"]),
            "schemes": schemes_seen,
            "public_ips": sorted({e["host"] for e in index_endpoints if e["is_ip"]}),
            "excluded_identifiers_count": len(excluded),
        },
        "endpoints": index_endpoints,
        "excluded_identifiers": excluded[:200],
    }
    return index


def build_report(refs, files_scanned, excluded, cfg, meta=None):
    """Build one big in-memory report from a fully-materialized refs list.
    Pairs with write_findings() for standalone/small-scale use. The main
    pipeline uses build_and_write_findings() instead - see its docstring."""
    cap = cfg["max_occurrences_per_endpoint"]
    ctx_n = cfg["context_lines"]
    target = (meta or {}).get("target")

    groups = {}
    for r in refs:
        groups.setdefault(r["host"], []).append(r)

    lines_cache = {}
    source_files_cache = {}

    def source_files():
        # Indexed lazily, once, only if some endpoint actually needs it.
        if "v" not in source_files_cache:
            source_files_cache["v"] = _index_source_files(target, cfg)
        return source_files_cache["v"]

    endpoints = []
    for host, items in sorted(groups.items()):
        schemes, ports, paths = [], [], []
        for r in items:
            if r["scheme"] and r["scheme"] not in schemes:
                schemes.append(r["scheme"])
            if r["port"] and r["port"] not in ports:
                ports.append(r["port"])
            if r["path"] and r["path"] not in paths:
                paths.append(r["path"])
        is_ip = items[0]["is_ip"]
        occurrences = []
        config_keys = set()
        for r in items:
            ctx, center = r.get("context", []), r.get("ctx_center", 0)
            occ = {
                "file": r["file"], "line": r["line"],
                "in_comment": r["in_comment"],
                "line_text": (ctx[center].strip() if ctx else r["raw"]),
                "context": ctx, "ctx_center": center,
            }
            # A URL that only ever appears in a config file has no literal
            # code occurrence for the scanner to find - trace it back to the
            # config key it's bound to and search the codebase for wherever
            # that key is actually read, so genuine usage isn't missed.
            if not r["in_comment"] and target and _file_is_config(r["file"], cfg):
                abs_path = os.path.join(target, r["file"])
                if os.path.isfile(abs_path):
                    config_info = _extract_config_key(abs_path, r["line"], r.get("raw") or host, lines_cache)
                    if config_info:
                        occ["config_key"] = config_info["full_key"]
                        usages = _search_key_usage(source_files(), config_info, cfg, ctx_n)
                        if usages:
                            occ["usage_locations"] = usages
                        config_keys.add(config_info["full_key"])
            occurrences.append(occ)

        usage = _usage(occurrences, cfg)
        if usage != "code" and any(o.get("usage_locations") for o in occurrences):
            usage = "code"  # config key is genuinely read in code
        direction = _direction(occurrences, schemes, cfg) if usage == "code" else "NONE"
        primary = schemes[0] if schemes else ("" if not is_ip else "")
        endpoint = f"{primary}://{host}" if primary else host
        entry = {
            "host": host,
            "endpoint": endpoint,
            "protocol": _protocol(schemes, is_ip, cfg),
            "schemes": schemes,
            "is_ip": is_ip,
            "kind": items[0]["kind"],
            "ports": ports,
            "paths": paths[:cap],
            "direction": direction,
            "usage": usage,
            "occurrence_count": len(items),
            "occurrences": occurrences[:cap],
        }
        if config_keys:
            entry["config_keys"] = sorted(config_keys)
        endpoints.append(entry)

    def _count(field, values):
        return {v: sum(1 for e in endpoints if e[field] == v) for v in values}

    schemes_seen = sorted({s for e in endpoints for s in e["schemes"]})
    report = {
        "meta": meta or {},
        "summary": {
            "total_endpoints": len(endpoints),
            "total_occurrences": sum(e["occurrence_count"] for e in endpoints),
            "files_scanned": files_scanned,
            "by_direction": _count("direction", ["OUT", "IN", "BOTH", "NONE", "UNKNOWN"]),
            "by_usage": _count("usage", ["code", "config", "documentation"]),
            "schemes": schemes_seen,
            "public_ips": sorted({e["host"] for e in endpoints if e["is_ip"]}),
            "excluded_identifiers_count": len(excluded),
        },
        "endpoints": endpoints,
        "excluded_identifiers": excluded[:200],
    }
    return report


def main(argv):
    if len(argv) < 2:
        print("Usage: python footprint_config_analyzer.py <raw_references.json> [report.json] [target_dir]")
        return 2
    with open(argv[1], "r", encoding="utf-8") as f:
        raw = json.load(f)
    cfg = load_config()
    target = argv[3] if len(argv) > 3 else None
    meta = {"target": os.path.abspath(target)} if target else {}
    report = build_report(
        raw.get("references", []),
        raw.get("files_scanned", 0),
        raw.get("excluded_identifiers", []),
        cfg,
        meta,
    )
    dest = argv[2] if len(argv) > 2 else None
    if dest:
        with open(dest, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"Wrote report with {report['summary']['total_endpoints']} endpoints -> {dest}")
    else:
        print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
