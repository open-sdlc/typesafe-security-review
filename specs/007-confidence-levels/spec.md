# Spec 007: Confidence Levels (`confidence_levels.py`)

Status: Implemented

## Overview

Both entry points that produce a findings report --
`run_all_classifiers.py` (spec 004) and `repo_scan.py` (spec 006) -- emit
one finding per `(module, category)` pair with a raw `confidence` score in
`[0, 1]`. Raw scores are precise but not directly actionable for a human
triaging a report: this spec adds a small, shared classification of that
score into exactly three human-facing **levels** -- `"Pass"`, `"Review"`,
and `"Failed"` -- computed identically by every caller via a single new
module, `confidence_levels.py`.

## Goals

- Give every finding a `level` field derived from its `confidence`, using
  one shared definition (not duplicated/re-derived per entry point).
- Make the two threshold boundaries configurable, without requiring a code
  change, since "how confident is confident enough" is a policy decision
  callers should be able to tune.
- Reduce report noise: printed tables should default to showing only
  actionable findings (`Review`/`Failed`), while machine-readable output
  (`--json`) stays complete for auditability/tooling.

## Non-Goals

- Does not change how `confidence` itself is computed (that remains each
  classifier module's `classify_with_nouls()`, spec 002) -- this is a pure
  post-hoc bucketing of an existing score.
- Does not remove or hide `Pass`-level findings from any data structure
  returned by `run_all()`/`scan_repo()` -- only the *printed table* omits
  them; every finding (including `Pass`) is always present in memory and
  in `--json` output.
- Does not by itself resolve `Review`-level ambiguity -- that is the
  purpose of the separate, optional LLM-assisted review pass (spec 003).

## Requirements

### Thresholds and levels

1. `confidence_levels.py` MUST define two threshold constants:
   `DEFAULT_FAILED_THRESHOLD = 0.65` and `DEFAULT_REVIEW_THRESHOLD = 0.40`.
2. `confidence_level(confidence, failed_threshold=None,
   review_threshold=None) -> str` MUST return exactly one of `"Failed"`,
   `"Review"`, or `"Pass"` (module constants `LEVEL_FAILED`, `LEVEL_REVIEW`,
   `LEVEL_PASS`), with no gap or overlap across `[0, 1]`:
   - `confidence > failed_threshold` → `"Failed"`
   - `review_threshold <= confidence <= failed_threshold` → `"Review"`
   - `confidence < review_threshold` → `"Pass"`
   A `None` confidence MUST be treated as `"Pass"` (never raise).
3. Threshold resolution order (highest precedence first) MUST be: (a) an
   explicit `failed_threshold`/`review_threshold` argument passed by the
   caller, (b) the `TSR_FAILED_THRESHOLD`/`TSR_REVIEW_THRESHOLD`
   environment variables (parsed as `float`; an unset or unparsable value
   falls through), (c) the built-in defaults. `get_thresholds(...)`
   exposes this resolution directly so callers can query the effective
   values (e.g. for `--help` text) without duplicating the logic.
4. `add_threshold_args(parser)` MUST add `--failed-threshold` and
   `--review-threshold` float flags (default `None`, so an omitted flag
   falls through to the environment-variable/default resolution in
   Requirement 3) to a given `argparse.ArgumentParser`, so every entry
   point defines these flags identically.

### Consumption by findings-producing entry points

5. `run_all_classifiers.run_all()` (spec 004) and `repo_scan.scan_repo()`
   (spec 006, via the same `run_all()` call per file) MUST accept optional
   `failed_threshold`/`review_threshold` parameters and MUST add a `level`
   key (spec 004/006's finding shape gains this field) to every emitted
   finding, computed via `confidence_levels.confidence_level()`.
6. Both entry points' CLI (`main()`) MUST wire `add_threshold_args()` in
   and pass the parsed `args.failed_threshold`/`args.review_threshold`
   straight through (`None` if not given, deferring to Requirement 3's
   fallback chain).

### Reporting

7. The printed findings table in both entry points MUST exclude
   `level == "Pass"` rows. The summary line MUST still report how many
   `Pass`-level findings were hidden (not simply omit the count silently).
8. `repo_scan.py`'s `--json <path>` output MUST include every finding
   regardless of level (including `Pass`), each with its `level` field, so
   downstream tooling can apply its own filtering/aggregation.
   `run_all_classifiers.py` has no `--json` output today; this is not
   introduced by this spec.

## Interfaces / Data Model

```python
DEFAULT_FAILED_THRESHOLD: float  # 0.65
DEFAULT_REVIEW_THRESHOLD: float  # 0.40
LEVEL_FAILED = "Failed"
LEVEL_REVIEW = "Review"
LEVEL_PASS = "Pass"

def get_thresholds(failed_threshold: float | None = None,
                    review_threshold: float | None = None) -> tuple[float, float]
def confidence_level(confidence: float | None,
                      failed_threshold: float | None = None,
                      review_threshold: float | None = None) -> str
def add_threshold_args(parser: argparse.ArgumentParser) -> None
```

Finding shape (extends spec 004's/006's shape with one new key):
`{cheatsheet: str, url: str, category: str, description: str,
confidence: float, level: str, file: str}` (`file` only present in
`repo_scan.py`'s findings, per spec 006).

## Behavior Notes

- The three levels intentionally partition `[0, 1]` with `Review`
  inclusive of both its own boundaries (`>= review_threshold` and
  `<= failed_threshold`), so every possible `confidence` value maps to
  exactly one level regardless of where the two thresholds are set
  (including edge cases like `failed_threshold == review_threshold`,
  which collapses `Review` to a single point).
- Environment-variable configuration exists so the same threshold policy
  can be set once (e.g. in CI) without every invocation needing explicit
  flags; explicit flags always win when both are present.

## Error Handling

- An invalid (non-numeric) environment variable value is silently ignored
  in favor of the built-in default (`_env_float`'s fail-soft behavior) --
  never raises, consistent with this codebase's general fail-soft design
  principle (spec 001, principle 4).

## Open Questions

- Whether `run_all_classifiers.py` should gain its own `--json` output
  (mirroring `repo_scan.py`) is left open; today its `Pass`-hiding applies
  only to the printed table, and there is no machine-readable escape
  hatch for that entry point specifically.
