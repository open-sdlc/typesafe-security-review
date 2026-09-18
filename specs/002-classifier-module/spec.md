# Spec 002: Classifier Module Interface

Status: Implemented (reverse-engineered from `classifiers/_TEMPLATE.py.txt`
and all 131 `classifiers/*_classifier.py` files)

## Overview

A **classifier module** is a single, self-contained Python file under
`classifiers/` whose name matches `*_classifier.py`. Each module represents
one source document -- an OWASP cheat sheet or a CWE definition -- broken
into several independently-scored sub-categories. This spec defines the
interface every such file MUST implement so that both `run_all_classifiers.py`
(spec 004) and `router.py` (spec 003) can discover, load, validate, and
invoke it uniformly, and so it remains individually runnable as a CLI tool.

## Goals

- Let a new classifier be added by creating exactly one file, with no
  changes required to the coordinator (`run_all_classifiers.py` discovers
  files by glob).
- Keep every module runnable standalone (`python classifiers/xxx_classifier.py
  "some text"`) for debugging/manual use, independent of the coordinator.
- Keep the interface source-agnostic: the same four attributes and one
  function serve both OWASP-cheat-sheet-sourced and CWE-sourced modules
  (see spec 005) with no branching in caller code.

## Requirements

### File location and naming

1. A classifier module MUST live at `classifiers/<topic>_classifier.py`
   (stem ending in `_classifier`, so `run_all_classifiers.py`'s
   `CLASSIFIERS_DIR.glob("*_classifier.py")` finds it).
2. `classifiers/_TEMPLATE.py.txt` MUST NOT be treated as a classifier
   module -- its `.txt` extension deliberately excludes it from the glob.
   It exists solely as a copy-source for authoring new classifiers.

### Required module attributes

Every classifier module MUST define, at module scope:

3. `CHEATSHEET_NAME: str` -- a human-readable display name for the source
   document. For OWASP-sourced modules this is the cheat sheet's title
   (e.g. `"Access Control Cheat Sheet"`). For CWE-sourced modules this is
   the CWE family name with its ID in parentheses (e.g.
   `"Use of Hard-coded Credentials (CWE-798)"`) -- there is no separate
   field name for CWE-sourced modules; they reuse `CHEATSHEET_NAME` /
   `CHEATSHEET_URL` as-is (confirmed design decision, see spec 005).
4. `CHEATSHEET_URL: str` -- a URL to the primary source page (an
   `https://cheatsheetseries.owasp.org/cheatsheets/*.html` page, or an
   `https://cwe.mitre.org/data/definitions/<id>.html` page, or another
   authoritative CWE reference such as the CWE Top 25 page).
5. `CATEGORIES: dict[str, str]` -- an ordered mapping of short
   `snake_case` category keys to a detailed, specific natural-language
   description of one concrete risk/attack pattern/checklist item drawn
   from the source document.
   - Each module SHOULD define between 5 and 12 categories; the observed
     range across all 131 current modules is 5-11, with most modules in
     the 7-10 range.
   - Category descriptions MUST be specific enough that the TypeSafe Jev
     model can distinguish a category from its neighbors within the same
     module -- vague/generic wording (e.g. "insecure code") is insufficient.
   - Category keys are stable identifiers: they appear verbatim in
     findings reports and MUST NOT collide with other keys in the same
     module's `CATEGORIES` dict (ordinary Python dict-key uniqueness).
     Category-key collisions *across different modules* are permitted and
     expected (see design principle 3 in spec 001).
6. `classify_with_nouls(text: str) -> dict[str, float]` -- given input
   text, MUST return a mapping of every key in `CATEGORIES` to a
   probability in `[0, 1]` (or `None` if the underlying answer is
   unavailable). The reference implementation:
   - Opens one `TypeSafeClient` (as a context manager).
   - Calls `client.system_one(state=text, questions={...})` exactly once,
     passing one `Noul(instructions=...)` per category, so all categories
     for this module are scored in a single parallel round trip.
   - Returns `{name: answer.noul for name, answer in result.nouls.items()}`.
   - Each `Noul`'s `instructions` MUST reference the specific category
     description, not just the category key (reference wording: `f"Does
     the input relate to or exhibit this issue: {desc}"`).

### Required module functions (CLI support)

7. `print_table(headers, rows) -> None` -- prints `rows` as a simple
   left-aligned table with a header and a `-`-underline separator (copied
   verbatim from `_TEMPLATE.py.txt`/a reference module such as
   `classifiers/cryptographic_storage_classifier.py`). This is per-module
   duplication by design (each file stays standalone/copy-paste-able), not
   a shared import.
8. `main() -> int` -- an `argparse`-based CLI entry point that:
   - Accepts an optional positional `text` argument.
   - Accepts `--file <path>` to read input from a file instead.
   - Falls back to reading `sys.stdin` if neither is given.
   - Calls `parser.error(...)` (exit code 2) if the resulting text is empty
     or whitespace-only.
   - Calls `classify_with_nouls(text)`, sorts categories by descending
     probability, and prints them via `print_table(("category",
     "probability"), rows)` with probabilities formatted to 3 decimal
     places.
   - Returns `0` on success.
9. The module MUST have an `if __name__ == "__main__": raise
   SystemExit(main())` guard, so it works both as a standalone CLI
   (`python classifiers/xxx_classifier.py ...`) and as an importable module
   (dynamically loaded by `run_all_classifiers.py` via
   `importlib.util.spec_from_file_location`, which does not execute this
   guard).

### Module docstring

10. The module MUST start with a docstring identifying: the cheat
    sheet/CWE source by name, that it's "built on the TypeSafe System One
    API", a one-line description of the Noul-per-category /
    single-parallel-call scoring approach, and a `Usage:` section showing
    the three invocation forms (positional text, `--file`, stdin).
    CWE-sourced modules' docstrings MUST NOT claim to be from "an OWASP
    cheat sheet" -- they should describe themselves as CWE-derived, citing
    cwe.mitre.org.

### Imports

11. Every classifier module MUST `import argparse`, `import sys`, and
    `from typesafe_sdk import Noul, TypeSafeClient`, and MUST NOT import
    anything from `run_all_classifiers.py` or `router.py` (no reverse
    dependency -- classifiers are leaf modules).

## Interfaces / Data Model

```python
CHEATSHEET_NAME: str
CHEATSHEET_URL: str
CATEGORIES: dict[str, str]                          # category_key -> description
def classify_with_nouls(text: str) -> dict[str, float]   # category_key -> probability
def print_table(headers: tuple, rows: list[tuple]) -> None
def main() -> int
```

`run_all_classifiers.py`'s `REQUIRED_ATTRS` constant
(`("CHEATSHEET_NAME", "CHEATSHEET_URL", "CATEGORIES", "classify_with_nouls")`)
is the authoritative, machine-checked subset of this contract; `print_table`
and `main` are conventions enforced only by code review / this spec, since
the coordinator never calls them.

## Error Handling

- If a module is missing any of `REQUIRED_ATTRS`, `run_all_classifiers.py`
  raises `AttributeError` while loading it; the coordinator catches this
  per-module (see spec 004) and reports it as a load error rather than
  aborting.
- If `classify_with_nouls` raises (e.g. no API key, network error), the
  coordinator catches this per-module as a run error (see spec 004).
- A classifier module itself does not need defensive error handling beyond
  what `TypeSafeClient`/`system_one()` already raises -- graceful
  degradation is the coordinator's responsibility, not each module's.

## How to Add a New Classifier

1. Copy `classifiers/_TEMPLATE.py.txt` to
   `classifiers/<topic>_classifier.py`.
2. Fill in `CHEATSHEET_NAME` / `CHEATSHEET_URL` and derive `CATEGORIES`
   from the real source document's content (an OWASP cheat sheet page, or
   a CWE definition page for topics the OWASP series doesn't cover).
3. No coordinator changes needed -- `run_all_classifiers.py` discovers it
   automatically.
4. Add one entry to `ROUTES` in `router.py` keyed by the same module stem,
   with a short `applies_when` scope description (spec 003) -- this step
   IS required, since routing relevance can't be derived automatically.

## Open Questions

- None -- this interface has been stable across all 131 existing modules
  (122 OWASP-sourced, 9 CWE-sourced) with no exceptions.
