# Spec 001: System Overview

Status: Implemented (reverse-engineered from the current codebase)

## Overview

`typesafe-security-review` is a security-review toolkit that scores
arbitrary input text (typically source code) against a large bank of
security-risk sub-categories. Each sub-category is judged independently by
a TypeSafe System One `Noul` question ("does this input exhibit this
specific risk pattern?"), which returns a calibrated probability in
`[0, 1]`. There is no single "vulnerable / not vulnerable" verdict --
instead the system returns every (source, category) pair whose probability
is greater than 0, ranked by confidence, so a caller can triage by
severity/confidence rather than trust a binary pass/fail.

## Goals

- Cover the full breadth of the [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
  (122 cheat sheets) plus additional [CWE](https://cwe.mitre.org/)-sourced
  weakness families the OWASP series has no dedicated page for (9
  classifiers as of this spec, see spec 005) -- 131 classifiers total.
- Let a single input (e.g. one source file) be checked against all
  classifiers cheaply, by only running the classifiers likely to be
  relevant (see spec 003) and running all selected classifiers concurrently.
- Keep every classifier structurally uniform (spec 002) so the system can
  add a new classifier by dropping in one file, with zero coordinator code
  changes.
- Degrade gracefully: a missing API key, a network failure, or a bug in one
  classifier module must not prevent the rest of the run from completing.

## Non-Goals

- The system does not by itself decide what counts as "the input" for a
  whole repository (single file vs. many files vs. only executable code) --
  today it operates on one blob of text per invocation. Extending it to
  whole-repository scanning is the subject of spec 006 and is not yet
  implemented.
- The system does not fix, patch, or auto-remediate findings; it only
  classifies and reports.
- The system does not replace human security review or a dedicated SAST
  engine's data-flow/taint analysis -- Nouls are pattern/semantic judgments
  over text, not a control/data-flow analysis.

## Components

```
                         ┌────────────────────┐
   input text/file  ───▶ │     router.py      │  (optional pre-filter)
                         │  ROUTES: 131 stems  │
                         └─────────┬──────────┘
                                   │ relevant module stems (>= threshold)
                                   ▼
                         ┌────────────────────┐
                         │ run_all_classifiers │  (coordinator)
                         │  .py                │
                         └─────────┬──────────┘
                                   │ classify_with_nouls(text) in parallel
                                   ▼
                    ┌──────────────────────────────┐
                    │  classifiers/*_classifier.py  │  (131 modules)
                    │  each: CATEGORIES + Nouls      │
                    └──────────────┬───────────────┘
                                   │ {category: probability}
                                   ▼
                         consolidated findings report
                         (source, category, confidence), sorted desc
```

- **`classifiers/*_classifier.py`** (spec 002) -- 131 independent, uniform
  modules. Each owns one source document (an OWASP cheat sheet or a CWE
  definition) and exposes a fixed set of sub-category Nouls.
- **`router.py`** (spec 003) -- a 131-entry registry (`ROUTES`) plus a
  `route()` function that asks one relevance Noul per classifier in a
  single parallel `system_one()` call, so obviously-irrelevant classifiers
  (e.g. Django cheat sheet for a `.java` file) can be skipped.
- **`run_all_classifiers.py`** (spec 004) -- discovers every classifier
  module by globbing `classifiers/*_classifier.py`, validates each exposes
  the required interface, optionally routes, then fans the input out to
  every selected module concurrently (thread pool) and prints one
  consolidated, confidence-sorted report.
- **`classifiers/_TEMPLATE.py.txt`** -- the canonical template new
  classifier files are copied from; not itself an executable module
  (`.txt` extension, excluded from discovery).
- **`bad.java`** -- a small, intentionally vulnerable sample Java file
  (hardcoded credentials, SQL/command injection, path traversal, XSS, SSRF,
  insecure deserialization, weak PRNG) used to sanity-check the system
  end-to-end.

## Design Principles (as embodied by the current code)

1. **Uniform interface, zero registration.** Every classifier module
   exposes the same four attributes (spec 002). `run_all_classifiers.py`
   discovers files by glob, not by an explicit registry -- adding a
   classifier never requires editing the coordinator. `router.py` is the
   one place that *does* need a new entry per classifier (its `ROUTES`
   dict), because routing needs a human-written `applies_when` scope
   description that can't be derived automatically.
2. **Speculative fan-out.** Both routing (one Noul per classifier,
   asking "is this relevant?") and classification (one Noul per category)
   send all their questions in a single parallel `system_one()` call
   rather than one round trip per question, following
   [the fan-out pattern](https://docs.typesafe.ai/patterns/fan-out.md).
3. **Independent categories, not mutually exclusive.** Categories are
   scored as `Noul`s (independent yes/no probabilities), not a `Choice`
   (pick one) -- an input can and often does match zero, one, or several
   categories across one or many classifiers at once. Overlap between
   classifiers (e.g. `hardcoded_credentials_classifier` and
   `secrets_management_classifier` both firing on the same hardcoded
   password) is expected and treated as a feature, not a bug: different
   classifiers frame the same underlying weakness from different angles.
4. **Fail soft, per-module.** A module that fails to import, fails to
   expose the required interface, or raises during classification (e.g.
   missing `TYPESAFE_API_KEY`) is recorded as an error and skipped; it
   never aborts the whole run. The same applies to the routing pass itself
   -- if `router.route()` raises, the coordinator falls back to running
   every classifier unfiltered rather than failing the request.
5. **Source-attribution in the interface, not the code.** Whether a
   classifier is OWASP-sourced or CWE-sourced only affects the *content* of
   `CHEATSHEET_NAME`/`CHEATSHEET_URL`/`CATEGORIES` -- the field names,
   discovery mechanism, and coordinator logic are identical either way
   (confirmed design decision; see spec 005).

## Key Data Types (informal)

- **Category score**: `category_key: str -> probability: float in [0, 1]`.
- **Finding** (as emitted by `run_all_classifiers.py`): `{cheatsheet: str,
  url: str, category: str, description: str, confidence: float}`.
- **Route score** (as emitted by `router.py`): `module_stem: str ->
  probability: float in [0, 1]`.

## Environment / Dependencies

- Python 3 standard library (`argparse`, `importlib.util`,
  `concurrent.futures`, `pathlib`) plus the `typesafe_sdk` package
  (`Noul`, `TypeSafeClient`, `system_one()`).
- Requires a `TYPESAFE_API_KEY` environment variable (or an explicit
  `api_key=` argument to `TypeSafeClient`) at classification/routing time;
  without one every module/route call raises, which the coordinator
  reports as a per-module error rather than crashing (design principle 4).

## Open Questions

- None blocking for the current single-file-input system; see spec 006 for
  open questions specific to extending this to whole-repository scanning.
