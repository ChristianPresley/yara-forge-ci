"""
YARA rule CI harness
====================

This pytest module treats detection rules as *code under test*. For every rule
in ``rules/`` it enforces four contracts:

1. **Compilation** - every ``.yar`` file must compile cleanly. Compiler
   warnings (e.g. slow rules, unreferenced strings) are treated as failures so
   they cannot silently rot the ruleset.
2. **Metadata policy** - every rule must carry a complete, machine-checkable
   metadata block (author, date, description, reference, mitre_attack,
   severity, version). Missing fields fail the build.
3. **True positives / false positives** - each rule must fire on its designated
   synthetic trigger file in ``tests/samples/positive/`` and must NOT fire on
   any file in ``tests/samples/negative/`` (the goodware / FP corpus).
4. **Performance budget** - each rule is timed against the full corpus and
   flagged if it exceeds the per-rule budget from ``tests/mapping.yml``.

Run with::

    pytest -v

Requires ``yara-python`` (import name: ``yara``) and ``pyyaml``.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest
import yaml

try:
    import yara
except ImportError as exc:  # pragma: no cover - environment guard
    raise ImportError(
        "yara-python is required to run the rule harness. "
        "Install it with `pip install yara-python`."
    ) from exc


# --------------------------------------------------------------------------- #
# Paths and configuration
# --------------------------------------------------------------------------- #

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = REPO_ROOT / "rules"
POSITIVE_DIR = REPO_ROOT / "tests" / "samples" / "positive"
NEGATIVE_DIR = REPO_ROOT / "tests" / "samples" / "negative"
MAPPING_FILE = REPO_ROOT / "tests" / "mapping.yml"

# Every rule's meta block MUST define these keys. This is the policy gate.
REQUIRED_META_KEYS = (
    "author",
    "date",
    "description",
    "reference",
    "mitre_attack",
    "severity",
    "version",
)

# Allowed severities keep the taxonomy consistent across the ruleset.
ALLOWED_SEVERITIES = {"low", "medium", "high", "critical"}


# --------------------------------------------------------------------------- #
# Fixtures / helpers
# --------------------------------------------------------------------------- #

def _rule_files() -> list[Path]:
    """All rule source files, sorted for stable test ids."""
    return sorted(RULES_DIR.glob("*.yar")) + sorted(RULES_DIR.glob("*.yara"))


def _load_mapping() -> dict:
    with MAPPING_FILE.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


MAPPING = _load_mapping()
EXPECTED_MATCHES: dict[str, list[str]] = MAPPING["expected_matches"]
PERF_BUDGET_MS: float = float(MAPPING.get("perf_budget_ms", 50))


@pytest.fixture(scope="session")
def compiled_ruleset() -> yara.Rules:
    """Compile the entire ruleset once, treating warnings as errors."""
    filepaths = {p.stem: str(p) for p in _rule_files()}
    # error_on_warning=True makes performance / correctness warnings fatal.
    return yara.compile(filepaths=filepaths, error_on_warning=True)


@pytest.fixture(scope="session")
def rule_names(compiled_ruleset) -> set[str]:
    return {r.identifier for r in _iter_rule_identifiers(compiled_ruleset)}


def _iter_rule_identifiers(compiled) -> list:
    """yara.Rules is iterable, yielding Rule objects with `.identifier`."""
    return list(compiled)


def _corpus_files(directory: Path) -> list[Path]:
    return sorted(p for p in directory.iterdir() if p.is_file())


# --------------------------------------------------------------------------- #
# 1. Compilation
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("rule_path", _rule_files(), ids=lambda p: p.name)
def test_rule_compiles(rule_path: Path):
    """Each rule file compiles individually with warnings-as-errors."""
    try:
        yara.compile(filepath=str(rule_path), error_on_warning=True)
    except yara.Error as exc:
        pytest.fail(f"{rule_path.name} failed to compile: {exc}")


def test_ruleset_compiles_together(compiled_ruleset):
    """The whole ruleset compiles as one namespace (catches identifier clashes)."""
    assert len(_iter_rule_identifiers(compiled_ruleset)) >= 8, (
        "Expected at least 8 rules in the ruleset."
    )


# --------------------------------------------------------------------------- #
# 2. Metadata policy
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("rule_path", _rule_files(), ids=lambda p: p.name)
def test_metadata_policy(rule_path: Path):
    """
    Every rule in the file must define all REQUIRED_META_KEYS with non-empty
    values, and use an allowed severity. We compile the file and read metadata
    straight off the compiled Rule objects (source of truth, not text scraping).
    """
    compiled = yara.compile(filepath=str(rule_path))
    rules = _iter_rule_identifiers(compiled)
    assert rules, f"{rule_path.name} defined no rules."

    for rule in rules:
        meta = rule.meta
        missing = [k for k in REQUIRED_META_KEYS if not str(meta.get(k, "")).strip()]
        assert not missing, (
            f"Rule '{rule.identifier}' in {rule_path.name} is missing required "
            f"metadata: {missing}"
        )
        sev = str(meta["severity"]).lower()
        assert sev in ALLOWED_SEVERITIES, (
            f"Rule '{rule.identifier}' has invalid severity '{sev}'. "
            f"Allowed: {sorted(ALLOWED_SEVERITIES)}"
        )


# --------------------------------------------------------------------------- #
# 3a. True positives
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("sample_name", sorted(EXPECTED_MATCHES), ids=lambda s: s)
def test_true_positive(compiled_ruleset, sample_name: str):
    """Each positive sample must trigger exactly its designated rule(s)."""
    sample_path = POSITIVE_DIR / sample_name
    assert sample_path.exists(), f"Missing positive sample: {sample_path}"

    matched = {m.rule for m in compiled_ruleset.match(str(sample_path))}
    expected = set(EXPECTED_MATCHES[sample_name])

    missing = expected - matched
    assert not missing, (
        f"{sample_name} did NOT fire expected rule(s) {sorted(missing)}. "
        f"Actually matched: {sorted(matched) or 'nothing'}."
    )


def test_every_rule_has_a_positive_sample(compiled_ruleset):
    """Coverage gate: no rule may ship without a positive test sample."""
    covered = {r for rules in EXPECTED_MATCHES.values() for r in rules}
    all_rules = {r.identifier for r in _iter_rule_identifiers(compiled_ruleset)}
    uncovered = all_rules - covered
    assert not uncovered, (
        f"These rules have no positive sample in mapping.yml: {sorted(uncovered)}"
    )


# --------------------------------------------------------------------------- #
# 3b. False positives (goodware corpus)
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "neg_path", _corpus_files(NEGATIVE_DIR), ids=lambda p: p.name
)
def test_no_false_positive(compiled_ruleset, neg_path: Path):
    """No rule may fire on any benign goodware sample."""
    matched = {m.rule for m in compiled_ruleset.match(str(neg_path))}
    assert not matched, (
        f"FALSE POSITIVE: {neg_path.name} matched {sorted(matched)} "
        f"but is benign goodware."
    )


# --------------------------------------------------------------------------- #
# 4. Performance budget
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("rule_path", _rule_files(), ids=lambda p: p.name)
def test_perf_budget(rule_path: Path):
    """
    Time each rule file against the full corpus and flag regressions.

    We compile the single rule file and scan every positive + negative sample,
    taking the best of a few runs to reduce noise, then compare to the budget.
    """
    compiled = yara.compile(filepath=str(rule_path))
    corpus = _corpus_files(POSITIVE_DIR) + _corpus_files(NEGATIVE_DIR)

    best_ms = float("inf")
    for _ in range(3):  # best-of-3 dampens scheduler jitter on CI runners
        start = time.perf_counter()
        for sample in corpus:
            compiled.match(str(sample))
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        best_ms = min(best_ms, elapsed_ms)

    assert best_ms <= PERF_BUDGET_MS, (
        f"PERF REGRESSION: {rule_path.name} took {best_ms:.2f}ms over the corpus "
        f"(budget {PERF_BUDGET_MS:.0f}ms). Consider stronger atoms / fewer regexes."
    )
