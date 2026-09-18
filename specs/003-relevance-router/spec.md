# Spec 003: Relevance Router (`router.py`)

Status: Implemented (reverse-engineered from `router.py`)

## Overview

`router.py` is a pre-filter that decides which of the 131 classifier
modules (spec 002) are worth running against a given input, so
`run_all_classifiers.py` (spec 004) doesn't waste API calls running, e.g.,
the Django/Laravel/Ruby-on-Rails classifiers against a plain `.java` file.
It follows the same "speculative fan-out" pattern the classifiers
themselves use: one relevance question per classifier, all sent in a
single parallel `system_one()` call.

## Goals

- Reduce the number of classifier calls made per input to only those
  plausibly relevant, without a second network round trip per classifier.
- Be safe to disable or to fail: routing is an optimization, not a
  correctness requirement -- if it's wrong or unavailable, the system MUST
  still be able to run every classifier.
- Require exactly one manual step to register a new classifier's routing
  rule (an entry in `ROUTES`), since "when does this classifier apply" is
  not mechanically derivable from the module file itself.

## Non-Goals

- `router.py` does not run any classifier itself -- it only scores
  relevance and lets the caller filter.
- `router.py` does not attempt language/framework auto-detection via file
  extension, shebang, or static parsing; relevance is judged the same way
  classification is, by asking the model.

## Requirements

### Registry (`ROUTES`)

1. `router.py` MUST define a module-level `ROUTES: dict[str, dict]` with
   exactly one entry per classifier module stem (the filename without
   `.py`, e.g. `"access_control_classifier"`). As of this spec, `ROUTES`
   has 131 entries, matching the 131 files under `classifiers/`.
2. Each `ROUTES[stem]` value MUST be a dict with keys:
   - `"name": str` -- SHOULD match that module's `CHEATSHEET_NAME` (kept in
     sync by convention/code review, not by importing the module at
     registry-definition time).
   - `"url": str` -- SHOULD match that module's `CHEATSHEET_URL`.
   - `"applies_when": str` -- a short, human-authored scope description of
     the language/framework/content-shape that makes this classifier
     relevant (e.g. `"any code that accepts a user-supplied file path,
     filename, or archive for reading, writing, serving, or extraction"`).
3. Entries whose `"name"` cites a `CWE-XXXX` ID are CWE-sourced (see spec
   005); all others are OWASP-cheat-sheet-sourced. This is a naming
   convention only -- `ROUTES` has no separate `source_kind` field.
4. `ROUTES` keys MUST correspond 1:1 with `classifiers/*_classifier.py`
   stems for `run_all_classifiers.py`'s routing filter (step 8 below) to
   have any effect; a stem present in one but not the other is not
   currently validated automatically (see Open Questions).

### `route(text: str) -> dict[str, float]`

5. MUST open one `TypeSafeClient` and issue exactly one `system_one()`
   call with one `Noul` per `ROUTES` entry, instructions of the form:
   `f"Does '{info['name']}' apply to reviewing this content? It applies
   when the content involves: {info['applies_when']}."`
6. MUST return `{stem: answer.noul for stem, answer in
   result.nouls.items()}` -- a flat mapping of every registered stem to a
   probability in `[0, 1]`.
7. MUST NOT catch exceptions itself (e.g. missing API key propagates to
   the caller) -- callers (both `router.py`'s own `main()` and
   `run_all_classifiers.py`'s `route_modules()`) are responsible for
   deciding how to degrade.

### `select_relevant(text: str, threshold: float = 0.35) -> dict[str, float]`

8. MUST call `route(text)` and return only the `{stem: probability}`
   entries where `probability is not None and probability >= threshold`.
   Default `threshold` is `0.35`.

### CLI (`main()`)

9. MUST support the same three input modes as classifier modules
   (positional `text`, `--file`, stdin fallback), plus a `--threshold`
   flag (default `0.35`) controlling the "selected" cutoff shown in the
   printed table.
10. MUST print one row per `ROUTES` entry via `print_table` with columns
    `(cheat_sheet, relevance, selected)`, sorted by descending relevance,
    followed by a one-line summary: `"{n}/{total} cheat sheet
    classifier(s) selected at threshold {threshold}."`.

## Interfaces / Data Model

```python
ROUTES: dict[str, dict]     # stem -> {name: str, url: str, applies_when: str}

def route(text: str) -> dict[str, float]                       # stem -> probability
def select_relevant(text: str, threshold: float = 0.35) -> dict[str, float]
def print_table(headers, rows) -> None
def main() -> int
```

## Behavior Notes

- Routing and classification are deliberately decoupled: `router.py` has
  no dependency on any `classifiers/*.py` module, and vice versa. The only
  coupling point is the shared module-stem string used as the dict key on
  both sides.
- The wording of each routing `Noul`'s `instructions` intentionally avoids
  asserting a classifier's provenance ("OWASP cheat sheet" vs. "CWE
  definition") since that distinction is irrelevant to *whether it
  applies* -- it says `"Does '{name}' apply..."`, not `"Does the '{name}'
  OWASP cheat sheet apply..."`, so the same wording is correct for both
  OWASP- and CWE-sourced entries.

## Error Handling

- `router.py`'s own `main()` does not catch `route()` failures; an
  unhandled exception (e.g. no API key) propagates and the CLI exits
  non-zero with a traceback -- this is acceptable since `router.py` run
  standalone is a diagnostic tool, not a production path.
- `run_all_classifiers.py`'s `route_modules()` wraps its call to
  `router.route()` in a `try/except`, and on failure keeps every
  originally-loaded module (i.e. behaves as if every classifier passed
  routing) -- see spec 004 requirement on graceful routing fallback.

## Open Questions

- No automated check currently confirms `ROUTES` and
  `classifiers/*_classifier.py` stay in exact 1:1 sync (a stem removed
  from one but not the other silently becomes a no-op entry, or a
  classifier that never gets routed unless `--no-route` is passed). A
  future improvement could add a startup assertion in
  `run_all_classifiers.py` or a small `tests/`-style check.
