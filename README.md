# yara-forge-ci

**Rules-as-code for detection engineering.** A small, self-contained YARA rule
repository wrapped in a CI/testing harness that compiles every rule, enforces a
metadata policy, tests each rule against a labeled positive/negative corpus, and
guards against performance regressions — the same discipline you would apply to
application code, applied to detection content.

[![yara-ci](https://img.shields.io/badge/CI-yara--forge-blue)](.github/workflows/ci.yml)
![rules](https://img.shields.io/badge/rules-10-green)
![license](https://img.shields.io/badge/license-MIT-lightgrey)

---

## Why this exists

Detection rules rot silently. A rule that compiled last quarter can start
throwing warnings after a YARA upgrade; a "quick fix" to reduce noise can quietly
kill a true positive; a lazily-written regex can blow a scan-time budget across a
fleet. In a threat-intelligence / detection-engineering context, the rule *is* the
product — so it deserves the same guardrails we give production code: version
control, automated tests, a review workflow, and CI that fails loudly.

This repo is a compact reference implementation of that idea. Every rule ships
with a positive sample that proves it fires and is exercised against a goodware
corpus that proves it doesn't over-fire. Nothing here requires live malware:
all triggers are hand-crafted, inert, synthetic fixtures.

> **Portfolio note.** This project was built by **Christian Presley** as a public
> proof-of-work artifact for detection-engineering / threat-collections work.
> The detection ideas, corpus, and harness are original; the samples are safe,
> synthetic trigger files (clearly marked `SYNTHETIC TEST FIXTURE - NOT MALWARE`),
> so the repository is safe to clone, run, and grade end-to-end.

---

## What's in the box

```
yara-forge-ci/
├── rules/                     # 10 original YARA rules, one detection idea each
├── tests/
│   ├── samples/
│   │   ├── positive/          # inert fixtures that SHOULD match a specific rule
│   │   └── negative/          # goodware / FP corpus that must match NOTHING
│   ├── mapping.yml            # sample -> expected-rule map + perf budget
│   └── test_rules.py          # pytest harness (compile/policy/TP/FP/perf)
├── scripts/
│   └── validate.py            # `yforge` CLI dashboard for local iteration
├── .github/workflows/ci.yml   # ruff lint + harness on every push/PR
├── pyproject.toml             # deps, ruff + pytest config
├── requirements.txt
├── LICENSE                    # MIT (c) 2026 Christian Presley
└── README.md
```

### The ruleset

| Rule | Detection idea | ATT&CK | Severity |
|------|----------------|--------|----------|
| `PowerShell_EncodedCommand` | PowerShell `-enc`/`-EncodedCommand` Base64 payloads | T1059.001 | high |
| `PowerShell_DownloadCradle` | In-memory download-and-execute cradles (`IEX (New-Object Net.WebClient)...`) | T1059.001 | high |
| `PowerShell_AMSI_Bypass` | Reflective AMSI tampering (`amsiInitFailed`, `AmsiScanBuffer` patch) | T1562.001 | critical |
| `Webshell_PHP_Eval_Base64` | PHP webshells: `eval`/`assert` fed by `base64_decode($_POST[...])` | T1505.003 | high |
| `Webshell_ASPX_CodeExec` | ASPX/JScript webshells incl. China-Chopper `eval(Request.Item[...])` | T1505.003 | high |
| `Phishing_Kit_CredHarvest_HTML` | Static credential-harvest pages with off-site POST + base64 second stage | T1566.002 | medium |
| `LNK_ScriptHost_Dropper` | Shortcut/container droppers spawning hidden script hosts | T1204.002 | high |
| `Base64_Encoded_PE_Heuristic` | Windows PE embedded as a Base64 blob in a text carrier | T1027 | medium |
| `LLM_Jailbreak_PromptInjection` | Known jailbreak / prompt-injection payloads in untrusted text | T1204 | medium |
| `Ransomware_Note_Template` | Ransom-note artifacts (encryption claim + payment channel + threat) | T1486 | high |

The last two rules deliberately lean into **AI-abuse detection** — scanning
untrusted text (RAG corpora, uploads, support tickets) for prompt-injection
payloads, and catching ransom notes whether hand-written or LLM-generated. Both
are exactly the kind of content-abuse signal an AI lab cares about, and both are
demonstrable without any real malware.

---

## The three contracts every rule must satisfy

**1. Metadata policy (governance).** Every rule must carry a complete meta block:

```
author, date, description, reference, mitre_attack, severity, version
```

`severity` must be one of `low | medium | high | critical`. The harness reads
metadata off the *compiled* rule (not by scraping text), so the policy can't be
faked with a comment. Missing or empty fields fail the build. This keeps the
ruleset self-documenting and lets downstream tooling pivot on ATT&CK id / severity.

**2. Positive & negative corpus (accuracy).**
- `tests/samples/positive/` — each file is a minimal, inert artifact crafted to
  trip exactly one rule. `tests/mapping.yml` records which sample must match which
  rule. A rule with no positive sample fails the **coverage gate**.
- `tests/samples/negative/` — benign goodware (an admin PowerShell script, a real
  contact-form handler, a legitimate login page with a password field, security
  blog prose, a config with a `TVpQ`-lookalike token). **Any** match here is a
  false positive and fails the build. Several negatives are adversarial on
  purpose — e.g. the benign login page has a password field and a POST form, so it
  proves the phishing rule's extra conditions actually suppress the easy FP.

**3. Performance budget (cost).** Each rule is timed (best-of-3) against the full
corpus and must stay under the per-rule budget in `mapping.yml` (default 50 ms).
This is where sloppy regexes get caught early. The rules themselves are written
performance-aware: string atoms are ≥ 4 bytes for strong Aho-Corasick matching,
regex quantifiers are bounded (`.{0,64}` rather than `.*`) to avoid catastrophic
backtracking, and generic tokens (`eval`, `cmd`) are only ever used as
corroborating conditions, never as sole triggers.

---

## Setup & usage

```bash
# 1. Install (a C toolchain may be needed to build yara-python from source;
#    most platforms have prebuilt wheels).
python -m pip install -r requirements.txt

# 2. Local dashboard — fast, colorized, per-rule status. Great for iterating.
python scripts/validate.py

# 3. Full CI harness — the authoritative gate (also run in GitHub Actions).
pytest -v

# 4. Lint the Python.
ruff check .
```

`scripts/validate.py` prints a per-rule table (compile / metadata / true-positive
/ false-positive count / scan time vs. budget) and exits non-zero on any failure,
so it works both as a human dashboard and as a CI gate.

---

## Adding a new rule (contribution workflow)

1. **Write the rule** in `rules/<name>.yar` with a full meta block (all seven
   required keys). Prefer long, specific atoms; bound every regex quantifier.
2. **Add a positive sample** to `tests/samples/positive/` — the smallest inert
   file that legitimately trips the rule. Mark it `SYNTHETIC TEST FIXTURE`.
3. **Register it** in `tests/mapping.yml` under `expected_matches`.
4. **Sanity-check the goodware corpus.** If your rule risks a plausible FP, add a
   representative benign file to `tests/samples/negative/` so the guard is real.
5. **Run `python scripts/validate.py` and `pytest`** until green, then open a PR.
   CI re-runs everything on push.

The coverage gate guarantees no rule can merge without a positive sample, and the
FP guard guarantees it was tested against goodware.

---

## Future work / notes

- **YARA-X.** VirusTotal's 2025 Rust rewrite of the engine ([YARA-X](https://virustotal.github.io/yara-x/))
  is the direction of travel: faster scanning, stricter/cleaner rule semantics,
  and a maintained `yara-x-py` binding. This harness intentionally uses the mature
  `yara-python` (libyara) binding today for maximum portability, but the design is
  engine-agnostic — porting is mostly swapping the `compile`/`match` calls and
  re-baselining the perf budget. A `yara-x` matrix leg in CI is the natural next
  step, plus a compatibility pass on the regex quantifier syntax.
- **Richer corpus.** The negative corpus could grow into a proper goodware set
  (common scripts, installers, framework files) to harden the FP guard.
- **Rule packaging.** Emit a signed, versioned ruleset bundle on tagged releases.
- **Coverage reporting.** Surface ATT&CK-technique coverage as a generated matrix.

---

## License

MIT © 2026 Christian Presley. See [LICENSE](LICENSE).

All samples in this repository are synthetic, inert, and clearly labeled. This
project contains **no** malware and requires none to run.
