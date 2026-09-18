# Spec 004: Coordinator CLI (`run_all_classifiers.py`)

Status: Implemented (reverse-engineered from `run_all_classifiers.py`)

## Overview

`run_all_classifiers.py` is the primary entry point for the whole system:
given one piece of input text (or a file), it discovers every classifier
module (spec 002), optionally narrows them via the router (spec 003),
runs the survivors concurrently, and prints one consolidated,
confidence-ranked findings report.

## Goals

- Provide a single command (`python run_all_classifiers.py --file
  bad.java`) that exercises the entire classifier bank against one input.
- Discover classifiers by convention (file glob), not by a maintained
  import list, so adding/removing classifier files never requires editing
  this file.
- Run classification in parallel (thread pool) since each classifier's
  `system_one()` call is I/O-bound (network).
- Never let one module's failure (missing interface, exception during
  classification) abort the whole run.

## Requirements

### Discovery and loading

1. `discover_classifier_paths()` MUST return every path matching
   `classifiers/*_classifier.py`, sorted for deterministic ordering.
2. `load_classifier_module(path)` MUST import the file as an independent
   module via `importlib.util.spec_from_file_location` /
   `module_from_spec` / `exec_module` (no package/`__init__.py` required),
   under the synthetic module name `f"owasp_classifiers.{path.stem}"`.
3. After import, it MUST verify the module defines every attribute in
   `REQUIRED_ATTRS = ("CHEATSHEET_NAME", "CHEATSHEET_URL", "CATEGORIES",
   "classify_with_nouls")`, raising `AttributeError` naming every missing
   attribute if any are absent.
4. `load_all_classifiers(paths)` MUST attempt every path independently,
   collecting `(path.name, error_message)` pairs for failures into
   `load_errors` instead of raising -- one bad module must not prevent
   the other 130 from loading.

### Routing integration

5. Unless `--no-route` is passed, the coordinator MUST call
   `route_modules(modules, text, threshold=args.route_threshold)` before
   classification.
6. `route_modules` MUST call `router.route(text)`; on success, it MUST
   keep only modules whose stem's routed probability is `>=
   threshold` (module stems absent from the route result default to
   `1.0`, i.e. included, to fail open rather than silently drop an
   unregistered classifier).
7. On any exception from `router.route()`, `route_modules` MUST return the
   *original, unfiltered* module list plus the error string, rather than
   propagating the exception -- so a routing failure (e.g. no API key)
   degrades to "run everything" instead of crashing.
8. Default `--route-threshold` is `0.35`, matching `router.py`'s own
   default.

### Parallel classification

9. `run_all(modules, text, workers, quiet)` MUST submit one
   `classify_one(module, text)` call per module to a
   `ThreadPoolExecutor(max_workers=max(1, workers))`, and MUST process
   results via `as_completed` (not submission order), so slower modules
   don't block reporting on faster ones.
10. Default `--workers` is `16`.
11. For each module, on success, MUST emit one finding per category where
    `confidence is not None and confidence > 0` -- categories scoring
    exactly `0` (or `None`) MUST be excluded from findings (this is the
    system's literal definition of "a finding": confidence strictly
    greater than zero).
12. Each finding MUST have the shape `{cheatsheet: module.CHEATSHEET_NAME,
    url: module.CHEATSHEET_URL, category: <key>, description:
    module.CATEGORIES.get(<key>, ""), confidence: <float>}`.
13. A module whose `classify_with_nouls` call raises MUST be recorded as
    `(module.CHEATSHEET_NAME, str(exc))` in `run_errors` and skipped,
    without stopping other modules' futures.
14. Unless `--quiet`, a live progress line (`\r[{done}/{total}]
    classified: {name}`) MUST be written to stderr as each future
    completes, followed by a trailing newline once all are done.

### Reporting

15. Findings MUST be filtered again by `--threshold` (default `0.0`, i.e.
    strictly `> 0.0`) after collection, then sorted by descending
    `confidence`, then truncated to `--top N` if given.
16. The report MUST be printed as a table with columns `(#, cheat_sheet,
    category, confidence)` (confidence formatted to 3 decimals), preceded
    by a header line `=== Security Classifier Findings Report ({elapsed}s)
    ===` and followed by a one-line summary: `"{n} finding(s) with
    confidence > {threshold} out of {m} classifier(s) checked ({total}
    available; use --no-route to check all)."`.
17. If `run_errors` is non-empty, a summary of per-module failures MUST be
    printed to stderr after the report (not mixed into the findings table).
18. If no classifier files are found at all, the coordinator MUST print an
    error to stderr and return exit code `1` without attempting anything
    else.

### CLI flags

19. MUST support: positional `text` (optional), `--file <path>`,
    `--workers <int>` (default 16), `--threshold <float>` (default 0.0),
    `--top <int>` (default: unlimited), `--quiet`, `--no-route`,
    `--route-threshold <float>` (default 0.35). Exactly one of positional
    `text` / `--file` / stdin MUST supply the input; empty/whitespace-only
    resolved text MUST trigger `parser.error(...)` (exit code 2).

## Interfaces / Data Model

```python
REQUIRED_ATTRS = ("CHEATSHEET_NAME", "CHEATSHEET_URL", "CATEGORIES", "classify_with_nouls")

def discover_classifier_paths() -> list[Path]
def load_classifier_module(path: Path) -> ModuleType
def load_all_classifiers(paths) -> tuple[list[ModuleType], list[tuple[str, str]]]
def route_modules(modules, text, threshold) -> tuple[list[ModuleType], dict[str, float], str | None]
def classify_one(module, text) -> tuple[ModuleType, dict[str, float]]
def run_all(modules, text, workers, quiet=False) -> tuple[list[dict], list[tuple[str, str]]]
```

Finding dict shape: `{cheatsheet: str, url: str, category: str,
description: str, confidence: float}`.

## Behavior Notes

- The coordinator never imports any `classifiers/*.py` module statically
  at the top of the file -- every module is loaded dynamically at runtime
  via `discover_classifier_paths()` + `load_classifier_module()`. This is
  what makes "drop in a new file, zero coordinator changes" true.
- `router` (the module) IS a static top-level import (`import router`),
  since routing is an integral, always-available coordinator feature, not
  a plugin.
- The "131 available" vs. "{m} classifiers checked" distinction in the
  final summary line reflects routing having filtered `total_loaded` down
  to `len(modules)`; when `--no-route` is passed the two numbers are equal.

## Error Handling Summary

| Failure | Effect |
|---|---|
| One classifier file fails to import / missing interface | Recorded in `load_errors`, printed as a warning, excluded from `modules`; run continues |
| `router.route()` raises (e.g. no API key) | Warning printed; ALL loaded modules run unfiltered |
| One module's `classify_with_nouls()` raises | Recorded in `run_errors`, printed after the report; that module contributes zero findings |
| No classifier files found at all | Error to stderr, exit code 1, nothing else attempted |
| No input text resolved | `parser.error(...)`, exit code 2 |

## Open Questions

- None for current single-input usage; see spec 006 for how this
  coordinator is expected to be invoked (once per code unit) from a
  future whole-repository scan driver, without needing any change to this
  file itself.
