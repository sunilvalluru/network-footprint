---
description: Map a codebase's network footprint - every external endpoint, which way data flows, and where it appears in the source
argument-hint: "[path-to-target]"
allowed-tools: Read, Write, Glob, Bash(python3:*), Bash(python:*), Bash(ls:*)
---

# Network Footprint Scan

Target directory: `$ARGUMENTS` (if empty, ask the user which directory to analyze).

The full workflow lives in the plugin's skill so it is defined in one place:

1. Read `${CLAUDE_PLUGIN_ROOT}/skills/network-footprint/SKILL.md`.
2. Follow it from "Target" through "Phase 7" for the target above.
3. Wherever the skill refers to `[SCRIPTS_DIR]` or `${CLAUDE_SKILL_DIR}/scripts`, use `${CLAUDE_PLUGIN_ROOT}/skills/network-footprint/scripts`.

Key rules (the skill has the details): run only the bundled `footprint_scan.py` with `python3`, do not modify the target's source files, write the reports yourself with Read and Write (no helper scripts), HTML-escape anything taken from scanned code, and never assign risk, severity, or compliance labels.
