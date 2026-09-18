# Spec 006: Full-Repo Scan with CodeGraph

Status: Proposed → Implemented as `repo_scan.py` (see Implementation Notes)

## Overview

Today the system classifies exactly one blob of text per invocation
(`run_all_classifiers.py "..."` / `--file <path>`). Scanning a whole
repository naively (concatenate or loop over every file) would waste
classifier calls on non-code files (docs, lockfiles, generated/vendored
code, data/config) and would give equal weight to a one-line getter and a
security-critical HTTP handler. This spec defines **`repo_scan.py`**, a new
driver that scans an entire repository by first using
[CodeGraph](https://github.com/colbymchenry/codegraph) to find the
repo's actual *executable code* -- and, where available, which of it is
externally reachable -- before handing anything to the existing
classifier pipeline (specs 002-004), which are used unmodified.

## Goals

- Scan an entire repository (not just one file) in one command, given
  either a local path or a remote git URL to clone.
- Only spend classifier calls on files CodeGraph's parser recognizes as
  source code with real symbols, not on docs/config/data/lockfiles/images
  -- "find executable code" is CodeGraph's file+symbol index acting as
  the noise filter, not a hand-maintained extension allowlist.
- When the repo is large enough that scanning everything is impractical,
  prioritize files that are more likely to be attacker-reachable (contain
  a detected framework route/handler, or are called from one) over pure
  internal utility code, using CodeGraph's call-graph/impact data.
- Reuse the existing coordinator/router/classifier machinery (specs
  002-004) completely unmodified -- this driver only decides *what text*
  to feed them and how to merge many per-file reports into one repo-wide
  report.
- Degrade gracefully if CodeGraph isn't installed/initialized: fall back
  to a plain source-file walk so the tool still works, consistent with
  spec 001 design principle 4 (fail soft).

## Non-Goals

- Not a replacement for CodeGraph itself -- this driver shells out to the
  `codegraph` CLI and reads its JSON output; it does not reimplement
  parsing, symbol extraction, or call-graph resolution.
- Not a data-flow/taint tracker -- "reachable from an entry point" here
  means CodeGraph's static call-graph/route-linking data, not verified
  runtime taint propagation from a specific untrusted source to a sink.
- Does not change anything about the classifier modules, the router, or
  the single-file coordinator (specs 002-004) -- it is purely an
  additional entry point that calls into `run_all_classifiers.py`'s
  existing functions.

## How CodeGraph Is Used (verified CLI behavior)

- `codegraph init --yes [path]` -- builds `<path>/.codegraph/` if it
  doesn't exist (idempotent: running it again on an already-initialized
  project is a fast no-op / re-sync, not an error).
- `codegraph status --json [path]` -- returns `{initialized, fileCount,
  nodeCount, edgeCount, nodesByKind: {function, method, class, variable,
  constant, import, namespace, file, ...}, languages: [...], ...}`. Used
  to confirm the index exists and to report what kinds of executable
  nodes are available before querying them.
- `codegraph files --json [--path]` -- returns one entry per **source
  file CodeGraph's parser recognizes** (`{path, language, nodeCount,
  size}`). Verified behavior: files with no supported grammar (`README.md`,
  `.gitignore`, `classifiers/_TEMPLATE.py.txt`) do **not** appear in this
  list at all -- this list *is* the "find executable code" file-level
  filter; nothing extra needs to be hand-coded to exclude docs/config.
- `codegraph query "" --kind <function|method|class> --json --limit
  <N>` -- an **empty search string** matches every symbol of the given
  `--kind`, returned with `score: 1` (no ranking applied) and full
  location data (`filePath`, `startLine`, `endLine`, `signature`, etc.).
  Verified: summing counts for `function` + `method` + `class` exactly
  matches `nodesByKind` from `status --json`, confirming this is a
  complete enumeration, not a lossy search. This is the mechanism for
  enumerating "every unit of executable code in the repo".
- `codegraph callers <symbol> --json` / `codegraph impact <symbol>
  --json` -- used opportunistically (best-effort, see Requirements) to
  estimate reachability/blast-radius for prioritization when a repo is
  too large to scan in full; CodeGraph's framework-aware route detection
  (documented upstream for 17+ frameworks: Django, Flask, FastAPI,
  Express, Spring, Rails, etc.) means a file containing a detected route
  handler is treated as a stronger entry-point signal than an
  un-called internal helper.
- Actual source text for classification is read directly from disk by
  `repo_scan.py` (not re-derived from CodeGraph's own formatted `node`
  output) using the file paths CodeGraph already resolved -- CodeGraph is
  the index/selector, not the text source.

## Requirements

### CodeGraph availability and index lifecycle

1. `repo_scan.py` MUST check whether the `codegraph` executable is on
   `PATH` (e.g. `shutil.which("codegraph")`). If absent, it MUST fall back
   to Requirement 8 (naive file walk) rather than failing.
2. If `codegraph` is available, `repo_scan.py` MUST ensure the target
   repo has a `.codegraph/` index, running `codegraph init --yes <path>`
   if `codegraph status --json <path>` reports `initialized: false` (or
   the command errors), and MUST run `codegraph sync <path>` first if the
   index already exists, so a repo scanned repeatedly (e.g. in CI on
   every commit) reflects the current working tree rather than a stale
   index from a previous run.
3. Any CodeGraph CLI invocation that fails unexpectedly (non-zero exit,
   malformed JSON) MUST be caught and MUST cause `repo_scan.py` to fall
   back to Requirement 8 for that run, with a warning printed to stderr
   -- CodeGraph integration is an enhancement, never a hard dependency
   (mirrors spec 004's routing-fallback requirement).

### Selecting what to scan

4. With CodeGraph available, `repo_scan.py` MUST build its file list from
   `codegraph files --json`, not from its own glob/walk -- this is the
   "use CodeGraph to find executable code" requirement. Each listed file
   MUST be scanned as a whole (its full current on-disk text), not
   split into one classifier call per function, so surrounding context
   (imports, class fields such as hardcoded constants, adjacent helper
   functions) stays in view for the classifiers, exactly as a
   human-selected `--file` input would be today.
5. `repo_scan.py` SHOULD also record, per file, the executable-symbol
   count from `codegraph files --json`'s `nodeCount` and (optionally, via
   the enumeration technique above) the specific `function`/`method`
   symbol locations, for reporting purposes (e.g. "3 findings in
   `payment.py`, which defines 12 functions including the Stripe webhook
   handler") -- this is informational, not a scanning-unit boundary.
6. `repo_scan.py` MUST support include/exclude glob filters (`--include`,
   `--exclude`) layered on top of CodeGraph's own file list, and MUST
   always exclude its own working directories (`.git/`, `.codegraph/`,
   common dependency directories such as `node_modules/`, `vendor/`,
   `venv/` -- CodeGraph itself already skips most of these by convention,
   but the flag exists for repo-specific overrides).
7. When `--max-files N` (or a `--budget` cost/time cap) restricts the scan
   below "every file CodeGraph found", `repo_scan.py` SHOULD prioritize
   files in this order: (a) files CodeGraph links to a detected framework
   route/handler (attacker-reachable entry points), (b) files with a
   nonzero `codegraph callers`/`impact` count above a small threshold
   (code other code depends on), (c) all other files, largest `nodeCount`
   first as a tie-breaker. This ranking is best-effort: if route/impact
   data isn't available for a given repo/language, `repo_scan.py` MUST
   still proceed using only tie (c).

### Fallback mode (no CodeGraph)

8. Without CodeGraph, `repo_scan.py` MUST fall back to walking the
   filesystem itself, filtered by a small built-in extension allowlist
   covering the languages the classifiers are meaningfully written for
   (the same language families CodeGraph supports is a reasonable
   default list), skipping common non-code directories
   (`.git`, `node_modules`, `vendor`, `venv`, `dist`, `build`, etc.) and
   binary/media files. This mode has no reachability-based prioritization
   -- `--max-files` in fallback mode simply takes the first N files found
   in walk order (or largest-first, see Requirement 7's tie-breaker).
   `repo_scan.py` MUST print a clear notice when running in this degraded
   mode so the difference in selection quality is visible to the caller.

### Classification

9. For each selected file, `repo_scan.py` MUST reuse
   `run_all_classifiers.py`'s existing internals as a library (import,
   not subprocess): load all classifier modules once (spec 004
   requirements 1-4), route once per file through `router.route_modules`
   (spec 003/004) unless `--no-route`, then run the routed classifiers
   for that file's text through `run_all_classifiers.run_all` (spec 004
   requirements 9-14). Classifier modules and the router are loaded
   **once** for the whole repo scan, not once per file, since import cost
   is fixed and per-file cost is only the classification call itself.
10. Findings MUST retain a `file` key (the repo-relative path) in
    addition to the existing finding shape (spec 004 requirement 12), so
    a repo-wide report can group/sort by file as well as by confidence.
11. A per-file classification failure (e.g. one file's text causes a
    single module to raise) MUST be handled exactly as spec 004 already
    handles it (recorded, skipped, run continues) and MUST NOT abort the
    scan of remaining files.

### Reporting

12. `repo_scan.py` MUST print a single consolidated report across all
    scanned files: all findings above `--threshold` (default `0.0`),
    sorted by descending confidence, each row showing `(file, cheat_sheet
    or CWE source, category, confidence)`, plus a summary line with
    total files scanned, total findings, and (if CodeGraph was used) the
    index stats from `codegraph status`.
13. `repo_scan.py` MUST support `--json <path>` to additionally (or
    instead of the table) write the full findings list as JSON, so CI
    systems can consume it without scraping the printed table.
14. `repo_scan.py` MUST support `--top N` (top N findings overall) and
    SHOULD support `--top-per-file N` (top N findings per file) since a
    single very-vulnerable file could otherwise crowd out the rest of
    the report.

### Remote repositories (`--repo-url`)

16. `repo_scan.py` MUST accept a positional target that is *either* a
    local path (default `.`) *or* a git remote URL, plus an explicit
    `--repo-url <url>` flag as an unambiguous alternative to the
    positional form (e.g. for scripting where a bare URL string might be
    mistaken for a path). A value is treated as a remote URL if it looks
    like one (`https://`, `git@`, `ssh://`, or ends in `.git`); anything
    else is treated as a local path.
17. When a remote URL is given, `repo_scan.py` MUST: (a) create a
    temporary clone directory (`tempfile.mkdtemp(prefix="repo_scan_")`,
    unless `--clone-dir <path>` names an explicit destination); (b) run
    `git clone --depth 1 [--branch <ref>] <url> <dest>` (shallow clone --
    full history isn't needed for a point-in-time scan); (c) proceed with
    the normal local-path flow (Requirements 1-14) using `<dest>` as the
    repo path; (d) remove the temporary clone directory afterward (on
    success, on error, and on early exit) unless `--keep-clone` was
    passed, in which case the path is printed so the caller can inspect
    or reuse it.
18. `--ref <branch-or-tag-or-commit>` MUST be accepted alongside
    `--repo-url` to scan a specific branch/tag instead of the remote's
    default branch. If a bare commit SHA is given (not resolvable as a
    shallow-cloneable ref), `repo_scan.py` MAY fall back to a full clone
    plus `git checkout <sha>` for that one case, since shallow-cloning an
    arbitrary SHA isn't universally supported by all git hosts.
19. A `git clone` failure (bad URL, auth required and unavailable, no
    network) MUST print a clear error and exit non-zero -- there is no
    fallback for an unclonable remote (unlike CodeGraph's own
    availability, which degrades gracefully per Requirement 8, a remote
    that can't be fetched has no local content to fall back to).
20. Authentication for private remotes is intentionally out of scope for
    `repo_scan.py` itself -- it shells out to the caller's own `git`, so
    whatever credential helper / SSH agent / `GIT_ASKPASS` the caller's
    environment already has configured applies unchanged; `repo_scan.py`
    MUST NOT prompt for or accept credentials directly (no
    `--username`/`--token` flags), to avoid ever handling secrets itself.

### CLI

21. `repo_scan.py` MUST accept a positional target (local path, default
    `.`, or a git URL per Requirement 16), plus: `--repo-url <url>`,
    `--ref <branch|tag|sha>`, `--clone-dir <path>`, `--keep-clone`,
    `--no-codegraph` (force fallback mode even if `codegraph` is on
    `PATH`, for comparison/debugging), `--max-files <int>`, `--include
    <glob>` (repeatable), `--exclude <glob>` (repeatable), `--workers
    <int>` (passed through to the per-file classification pass, default
    matching spec 004's default of 16), `--threshold <float>`, `--top
    <int>`, `--top-per-file <int>`, `--no-route`, `--route-threshold
    <float>`, `--json <path>`, `--quiet`.

## Interfaces / Data Model

```python
def resolve_target(target: str, ref: str | None, clone_dir: str | None) -> tuple[Path, bool]
    # returns (local_repo_path, is_temporary_clone); clones via git if `target` is a URL
def codegraph_available() -> bool
def ensure_codegraph_index(repo_path: Path) -> bool           # True if usable index exists after this call
def list_files_via_codegraph(repo_path: Path) -> list[dict]   # [{path, language, nodeCount}, ...]
def list_files_fallback(repo_path: Path) -> list[dict]        # same shape, walk-based
def rank_files(files: list[dict], repo_path: Path) -> list[dict]  # reachability-aware ordering (Req. 7)
def scan_repo(repo_path: Path, **options) -> RepoScanResult
```

`RepoScanResult` finding shape extends spec 004's finding dict with one
extra key: `{file: str, cheatsheet: str, url: str, category: str,
description: str, confidence: float}`.

## Error Handling Summary

| Failure | Effect |
|---|---|
| `--repo-url` given but `git clone` fails (bad URL, auth, network) | Clear error printed, exit non-zero, no fallback |
| `codegraph` not on `PATH` | Fallback file walk (Req. 8), notice printed |
| `codegraph init`/`sync`/`status`/`files`/`query` errors or returns malformed JSON | Fallback file walk for this run, warning printed |
| One file's text fails a classifier module | That (file, module) pair recorded as an error, rest of scan continues (spec 004 semantics, per file) |
| `router.route()` fails for a given file | That file falls back to running all loaded classifiers unfiltered (spec 004 semantics, per file) |
| Zero files selected to scan | Print a clear message and exit non-zero rather than a silent empty report |

## Implementation Notes

- CodeGraph install used for verification during spec authoring:
  `npm install -g @colbymchenry/codegraph` (v1.6.0), confirmed working
  fully offline/local after install (no API key, no network calls at
  scan time -- CodeGraph's own docs describe it as 100% local/SQLite-backed).
- The empty-string `codegraph query "" --kind <kind> --json --limit <N>`
  enumeration trick and the `codegraph files --json` file inventory were
  both verified against this repo (`classifiers/`, `router.py`,
  `run_all_classifiers.py`, `bad.java`) before writing this spec; counts
  were cross-checked against `codegraph status --json`'s `nodesByKind`
  for an exact match.
- `repo_scan.py` intentionally does not vendor or require CodeGraph as a
  Python dependency -- it is invoked purely as an external CLI (subprocess
  + JSON), matching CodeGraph's own design as a standalone, per-project
  local tool rather than a library dependency.

## Open Questions

- Route/impact-based prioritization (Requirement 7) depends on
  CodeGraph's per-language/per-framework route detection, which is far
  stronger for common web frameworks than for, e.g., embedded/systems
  code with no routing concept at all -- for those repos, ranking
  degrades to the `nodeCount` tie-breaker only. This is accepted as a
  reasonable degradation rather than a blocking gap.
- Whether per-symbol (function-level) classification granularity is ever
  worth the extra API-call cost over whole-file classification (Req. 4)
  is left open for future measurement; whole-file was chosen initially
  to keep behavior identical to the existing single-file coordinator and
  to preserve cross-statement context within a file.
