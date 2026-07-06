#!/usr/bin/env python3
"""
yforge - local YARA ruleset validator
======================================

A single-command dashboard that mirrors what the pytest CI harness enforces,
but with human-friendly output for iterating on rules locally:

    python scripts/validate.py

It reports, per rule:
  * compile status (warnings-as-errors)
  * metadata-policy status
  * true-positive result against its designated sample
  * false-positive count against the goodware corpus
  * scan time over the full corpus vs. the performance budget

Exit code is 0 only if every check passes, so it doubles as a CI gate.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import yaml

try:
    import yara
except ImportError:
    sys.exit(
        "ERROR: yara-python not installed. Run `pip install yara-python pyyaml`."
    )

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = REPO_ROOT / "rules"
POSITIVE_DIR = REPO_ROOT / "tests" / "samples" / "positive"
NEGATIVE_DIR = REPO_ROOT / "tests" / "samples" / "negative"
MAPPING_FILE = REPO_ROOT / "tests" / "mapping.yml"

REQUIRED_META_KEYS = (
    "author", "date", "description", "reference",
    "mitre_attack", "severity", "version",
)

# ANSI colors (disabled automatically when output is not a TTY).
_TTY = sys.stdout.isatty()
def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _TTY else text
GREEN = lambda s: _c("32", s)
RED = lambda s: _c("31", s)
YELLOW = lambda s: _c("33", s)
BOLD = lambda s: _c("1", s)
OK = GREEN("PASS")
BAD = RED("FAIL")


def _files(directory: Path) -> list[Path]:
    return sorted(p for p in directory.iterdir() if p.is_file())


def main() -> int:
    mapping = yaml.safe_load(MAPPING_FILE.read_text(encoding="utf-8"))
    expected: dict[str, list[str]] = mapping["expected_matches"]
    budget_ms = float(mapping.get("perf_budget_ms", 50))

    # Invert the mapping: rule -> its positive sample file.
    rule_to_sample: dict[str, str] = {}
    for sample, rules in expected.items():
        for r in rules:
            rule_to_sample[r] = sample

    rule_paths = sorted(RULES_DIR.glob("*.yar")) + sorted(RULES_DIR.glob("*.yara"))
    corpus = _files(POSITIVE_DIR) + _files(NEGATIVE_DIR)

    print(BOLD(f"\nyforge :: validating {len(rule_paths)} rule file(s)\n"))
    header = f"{'RULE':32} {'COMPILE':8} {'META':6} {'TP':4} {'FP':4} {'TIME':>9}"
    print(BOLD(header))
    print("-" * len(header))

    total_pass = 0
    total_fail = 0
    fp_total = 0
    slow_rules: list[str] = []

    for path in rule_paths:
        row_ok = True

        # --- compile (warnings-as-errors) ---
        try:
            compiled = yara.compile(filepath=str(path), error_on_warning=True)
            compile_cell = OK
        except yara.Error as exc:
            print(f"{path.name:32} {BAD}   -- cannot compile: {exc}")
            total_fail += 1
            continue

        rules = list(compiled)

        # --- metadata policy ---
        meta_ok = True
        for rule in rules:
            missing = [k for k in REQUIRED_META_KEYS
                       if not str(rule.meta.get(k, "")).strip()]
            if missing:
                meta_ok = False
        meta_cell = OK if meta_ok else BAD
        row_ok &= meta_ok

        # --- true positive ---
        tp_cell = YELLOW("n/a")
        for rule in rules:
            sample = rule_to_sample.get(rule.identifier)
            if not sample:
                tp_cell = RED("none")
                row_ok = False
                continue
            hit = {m.rule for m in compiled.match(str(POSITIVE_DIR / sample))}
            if rule.identifier in hit:
                tp_cell = GREEN("hit")
            else:
                tp_cell = RED("miss")
                row_ok = False

        # --- false positives over goodware ---
        fp_count = 0
        for neg in _files(NEGATIVE_DIR):
            fp_count += len({m.rule for m in compiled.match(str(neg))})
        fp_total += fp_count
        fp_cell = GREEN("0") if fp_count == 0 else RED(str(fp_count))
        if fp_count:
            row_ok = False

        # --- performance ---
        best_ms = float("inf")
        for _ in range(3):
            start = time.perf_counter()
            for sample in corpus:
                compiled.match(str(sample))
            best_ms = min(best_ms, (time.perf_counter() - start) * 1000.0)
        time_cell = f"{best_ms:6.2f}ms"
        if best_ms > budget_ms:
            time_cell = RED(time_cell)
            slow_rules.append(path.name)
            row_ok = False
        else:
            time_cell = GREEN(time_cell)

        print(f"{path.name:32} {compile_cell:8} {meta_cell:6} "
              f"{tp_cell:4} {fp_cell:4} {time_cell:>9}")

        total_pass += int(row_ok)
        total_fail += int(not row_ok)

    # --- summary ---
    print("-" * len(header))
    print(BOLD("\nSummary"))
    print(f"  rules validated : {len(rule_paths)}")
    print(f"  passed          : {GREEN(str(total_pass))}")
    print(f"  failed          : {(RED if total_fail else GREEN)(str(total_fail))}")
    print(f"  false positives : {(RED if fp_total else GREEN)(str(fp_total))}")
    print(f"  perf budget     : {budget_ms:.0f}ms/rule over full corpus")
    if slow_rules:
        print(f"  slow rules      : {RED(', '.join(slow_rules))}")
    print()

    return 0 if total_fail == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
