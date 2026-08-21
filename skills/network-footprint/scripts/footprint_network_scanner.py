#!/usr/bin/env python3
"""
Network Footprint - network reference scanner.

Walks a directory tree and extracts every *external* reference it can find,
regardless of protocol:

  - Any scheme URL:      https://, ws://, wss://, ftp://, ssh://, postgres://,
                         redis://, mongodb://, amqp://, grpc://, ... anything://
  - Git SSH shorthand:   git@github.com:org/repo.git
  - Bare public domains:  api.example.com  (in config/code, with a known TLD)
  - Public IP addresses:  52.20.16.7  (only globally-routable IPs)

This module only *extracts* facts (what, where, with surrounding context).
It does not judge direction or risk - that is the analyzer's / agent's job.

Standalone:
    python footprint_network_scanner.py <target_dir> [output.json]
"""
import ipaddress
import json
import os
import re
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_CONFIG = Path(os.getenv("FOOTPRINT_CONFIG", HERE / "footprint_config.json"))

# scheme://rest   (scheme = letter followed by letters/digits/+/-/.)
URL_RE = re.compile(r"([a-zA-Z][a-zA-Z0-9+.\-]*)://([^\s\"'`<>)\]}]+)")
# git@host:path
GIT_SSH_RE = re.compile(r"\b([a-zA-Z0-9_.\-]+)@([a-zA-Z0-9.\-]+):([~/\w.\-]+)")
# 1.2.3.4 with optional :port
IPV4_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b(?::(\d{1,5}))?")
# bare domain: labels + alpha TLD
DOMAIN_RE = re.compile(
    r"\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24})\b"
)
_TRAILING = ".,;:!?)'\"]}>`"


def load_config(path=DEFAULT_CONFIG):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _is_ip(text):
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def _is_global_ip(text):
    try:
        return ipaddress.ip_address(text).is_global
    except ValueError:
        return False


def parse_authority(rest):
    """Split 'user:pass@host:port/path?x' into (host, port, path)."""
    rest = rest.rstrip(_TRAILING)
    cut = len(rest)
    for ch in ("/", "?", "#"):
        i = rest.find(ch)
        if i != -1:
            cut = min(cut, i)
    authority, path = rest[:cut], rest[cut:]
    if "@" in authority:
        authority = authority.rsplit("@", 1)[1]
    port = None
    if authority.startswith("["):  # IPv6 literal [::1]:port
        end = authority.find("]")
        host = authority[1:end] if end != -1 else authority.strip("[]")
        tail = authority[end + 1:] if end != -1 else ""
        if tail.startswith(":"):
            port = tail[1:]
    elif ":" in authority:
        host, maybe_port = authority.rsplit(":", 1)
        if maybe_port.isdigit():
            port = maybe_port
        else:
            host = authority
    else:
        host = authority
    return host.lower().strip("."), port, path


def is_comment(line, cfg):
    stripped = line.lstrip()
    return any(stripped.startswith(p) for p in cfg["comment_prefixes"])


def iter_text_files(target, cfg):
    exclude_dirs = set(cfg["exclude_dirs"])
    suffixes = tuple(cfg["exclude_suffixes"])
    max_bytes = cfg["max_file_size_kb"] * 1024
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        for name in files:
            low = name.lower()
            if low.endswith(suffixes):
                continue
            fp = os.path.join(root, name)
            try:
                if os.path.getsize(fp) > max_bytes:
                    continue
                with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read()
            except (OSError, ValueError):
                continue
            if "\x00" in text[:1024]:  # binary
                continue
            yield fp, text


def _context(lines, idx, n):
    """Return (window_lines, center_offset) for +/- n lines around idx."""
    lo, hi = max(0, idx - n), min(len(lines), idx + n + 1)
    return [lines[i].rstrip("\n") for i in range(lo, hi)], idx - lo


def iter_references(target, cfg, stats):
    """Walk target and yield each external reference found, one at a time,
    with its context window - instead of accumulating the full match list
    (which can be large if context_lines is configured high, or the project
    has many matches) in memory for the whole project.

    stats is a dict this function updates in place as it goes:
    stats['files_scanned'] (int) and stats['excluded'] (set of strings that
    matched the domain pattern but turned out to be code identifiers, e.g.
    Java package names).
    """
    target = os.path.abspath(target)
    ctx_n = cfg["context_lines"]
    known_tlds = set(cfg["known_tlds"])
    internal = set(h.lower() for h in cfg["internal_hosts"])
    code_prefixes = tuple(cfg["code_identifier_prefixes"])
    stats.setdefault("files_scanned", 0)
    stats.setdefault("excluded", set())

    for fp, text in iter_text_files(target, cfg):
        stats["files_scanned"] += 1
        rel = os.path.relpath(fp, target)
        lines = text.splitlines()
        for idx, line in enumerate(lines):
            in_comment = is_comment(line, cfg)
            claimed = []  # (start, end) spans already taken by an earlier match

            def inside_claimed(pos):
                return any(s <= pos < e for s, e in claimed)

            def make(match_start, match_end, ref):
                claimed.append((match_start, match_end))
                window, center = _context(lines, idx, ctx_n)
                ref.update({
                    "file": rel, "line": idx + 1,
                    "in_comment": in_comment,
                    "context": window, "ctx_center": center,
                })
                return ref

            # 1) scheme:// URLs (any protocol) - claimed first
            for m in URL_RE.finditer(line):
                scheme = m.group(1).lower()
                host, port, path = parse_authority(m.group(2))
                if not host or host in internal:
                    continue
                host_is_ip = _is_ip(host)
                if host_is_ip and not _is_global_ip(host):
                    continue
                yield make(m.start(), m.end(), {
                    "raw": m.group(0).rstrip(_TRAILING),
                    "kind": "url", "scheme": scheme,
                    "host": host, "port": port, "path": path or "",
                    "is_ip": host_is_ip,
                })

            # 2) git@host:path  (SSH shorthand) - real domain hosts only
            for m in GIT_SSH_RE.finditer(line):
                if inside_claimed(m.start()):
                    continue
                host = m.group(2).lower()
                if host in internal or not DOMAIN_RE.fullmatch(host):
                    continue
                if host.rsplit(".", 1)[-1] not in known_tlds:
                    continue
                yield make(m.start(), m.end(), {
                    "raw": m.group(0), "kind": "git_ssh", "scheme": "ssh",
                    "host": host, "port": None, "path": m.group(3),
                    "is_ip": False,
                })

            # 3) public IP addresses (with optional port)
            for m in IPV4_RE.finditer(line):
                if inside_claimed(m.start()):
                    continue
                ip = m.group(1)
                if not _is_global_ip(ip):
                    continue
                yield make(m.start(), m.end(), {
                    "raw": m.group(0), "kind": "ip", "scheme": None,
                    "host": ip, "port": m.group(2), "path": "",
                    "is_ip": True,
                })

            # 4) bare domains (known TLD, not a code namespace)
            for m in DOMAIN_RE.finditer(line):
                if inside_claimed(m.start()):
                    continue
                raw_host = m.group(1)
                host = raw_host.lower()
                tld = host.rsplit(".", 1)[-1]
                if host.startswith(code_prefixes) and host.count(".") >= 2:
                    stats["excluded"].add(host)
                    continue
                if tld not in known_tlds or host in internal:
                    continue
                # A handful of TLDs (.info, .run, .app, .dev, .page, .live, ...)
                # double as common method/attribute names, so "logger.info",
                # "runner.run", "logging.INFO" match this pattern too. Real
                # domains are written lowercase and are never themselves
                # called or accessed as a constant - filter those two cases
                # out rather than misreport code as a network reference.
                tail_label = raw_host.rsplit(".", 1)[-1]
                if not tail_label.islower():
                    continue
                if re.match(r"\s*\(", line[m.end():]):
                    continue
                yield make(m.start(), m.end(), {
                    "raw": host, "kind": "domain", "scheme": None,
                    "host": host, "port": None, "path": "",
                    "is_ip": False,
                })


def scan_tree(target, cfg):
    """Return (references, files_scanned, excluded_identifiers), materializing
    the full reference list in memory. Fine for standalone/small-scale use;
    the main pipeline uses scan_and_write() instead, which streams each
    occurrence straight to disk without holding the full list in memory."""
    stats = {}
    refs = list(iter_references(target, cfg, stats))
    return refs, stats["files_scanned"], sorted(stats["excluded"])


def _slugify(text):
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug or "ref"


def scan_and_write(target, cfg, findings_dir):
    """Walk target and write each occurrence straight to its own file under
    findings_dir/occurrences/ as it's found, instead of accumulating the full
    match list (with context windows - large if context_lines is configured
    high, or the project has many matches) in memory for the whole project
    before writing anything. Peak memory stays close to "one file's content
    at a time", matching iter_text_files()'s own streaming behavior.

    Returns the lightweight index dict (also written to
    findings_dir/footprint_raw.json) - no context, just enough per reference
    to group by host and locate its full record on disk.
    """
    occ_dir = os.path.join(findings_dir, "occurrences")
    # Wipe stale occurrence files from a previous run before writing the new set.
    shutil.rmtree(occ_dir, ignore_errors=True)
    os.makedirs(occ_dir, exist_ok=True)

    stats = {}
    index_refs = []
    for i, ref in enumerate(iter_references(target, cfg, stats), start=1):
        fid = f"{i:05d}"
        fname = f"{fid}-{_slugify(ref['host'])}.json"
        record = dict(ref)
        record["id"] = fid
        with open(os.path.join(occ_dir, fname), "w", encoding="utf-8") as f:
            json.dump(record, f, indent=2)

        index_refs.append({
            "id": fid, "host": ref["host"], "raw": ref["raw"], "kind": ref["kind"],
            "scheme": ref["scheme"], "file": ref["file"], "line": ref["line"],
            "in_comment": ref["in_comment"], "occurrence_file": f"occurrences/{fname}",
        })

    return {
        "files_scanned": stats["files_scanned"],
        "total_occurrences": len(index_refs),
        "excluded_identifiers": sorted(stats["excluded"]),
        "references": index_refs,
    }


def main(argv):
    if len(argv) < 2:
        print("Usage: python footprint_network_scanner.py <target_dir> [output.json]")
        return 2
    target = argv[1]
    cfg = load_config()
    refs, n, excluded = scan_tree(target, cfg)
    out = {"references": refs, "files_scanned": n, "excluded_identifiers": excluded}
    dest = argv[2] if len(argv) > 2 else None
    if dest:
        with open(dest, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2)
        print(f"Wrote {len(refs)} references from {n} files -> {dest}")
    else:
        print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
