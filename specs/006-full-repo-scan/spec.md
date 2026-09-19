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
- Degrade gracefully if CodeGraph isn't installed/initialized: attempt an
  automatic **local, per-repo** install by default (Requirement 1) --
  never a global install, never dependent on `PATH` -- and fall back to a
  plain source-file walk if that isn't possible or is explicitly skipped
  (`--no-codegraph`), so the tool still works, consistent with spec 001
  design principle 4 (fail soft).
- Scan multiple files concurrently (`--file-workers`), not just multiple
  classifiers within one file (`--workers`), so repo-wide scan time
  scales with wall-clock parallelism rather than the sum of every file's
  classification time.
- Bucket every finding into a `Pass`/`Review`/`Failed` confidence level
  (spec 007) and, optionally, send `Review`-band findings to an external
  coding-agent CLI for a second opinion before the final report is
  printed (spec 003), reducing the amount of borderline output a human
  has to triage manually.

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

1. `repo_scan.py` MUST check whether `codegraph` is available **locally
   for the target repo**, by resolving a fixed on-disk path --
   `<repo_path>/.codegraph-cli/node_modules/.bin/codegraph`
   (`codegraph_bin_path(repo_path)`) -- and checking whether that file
   exists (`codegraph_available(repo_path)`). This MUST NOT consult
   `PATH`/`shutil.which` at all: CodeGraph is a **per-repo local
   dependency**, not a global/PATH-resolved tool, so two different target
   repos scanned back-to-back never share or clobber each other's
   install. If the local binary is absent, and CodeGraph usage was not
   disabled (`--no-codegraph`), `repo_scan.py` MUST attempt to
   auto-install CodeGraph by running `npm install --prefix
   <repo_path>/.codegraph-cli --no-save @colbymchenry/codegraph`
   (Requirement 1a) before deciding whether to fall back to Requirement 8
   (naive file walk). `--no-save` keeps this from touching the target
   repo's own `package.json`/lockfile if it has one.
1a. Auto-install (Requirement 1) is itself best-effort and MUST NOT raise:
    if `npm` is not on `PATH`, or the install command exits non-zero, or
    the local binary still doesn't exist afterward, `repo_scan.py` MUST
    print a clear notice/warning to stderr and fall through to
    Requirement 8 exactly as if CodeGraph were simply absent. `--no-
    codegraph` MUST skip this auto-install attempt entirely (no `npm`
    invocation at all) and always use Requirement 8, for callers who want
    a deterministic plain-walk comparison or don't want the implicit
    local `npm install` side effect (which creates
    `<repo_path>/.codegraph-cli/`).
2. If `codegraph` is available locally (whether it was already installed
   or the auto-install in Requirement 1 succeeded), every CodeGraph CLI
   invocation MUST use the resolved local binary path from Requirement 1
   as `argv[0]` (never the bare string `"codegraph"`), so no invocation
   ever depends on `PATH`. `repo_scan.py` MUST ensure the target repo has
   a `.codegraph/` index, running `<codegraph_bin> init --yes <path>` if
   `<codegraph_bin> status --json <path>` reports `initialized: false`
   (or the command errors), and MUST run `<codegraph_bin> sync <path>`
   first if the index already exists, so a repo scanned repeatedly (e.g.
   in CI on every commit) reflects the current working tree rather than
   a stale index from a previous run.
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

8. Without CodeGraph (not installed, auto-install failed/skipped, or
   `--no-codegraph`), `repo_scan.py` MUST fall back to walking the
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

9. `repo_scan.py` MUST classify multiple files **concurrently**: an outer
   `ThreadPoolExecutor(max_workers=args.file_workers)` (`--file-workers`,
   default `25`) submits one classification task per selected file, each
   task reusing `run_all_classifiers.py`'s existing internals as a
   library (import, not subprocess) for that one file: route once through
   `router.route_modules` (spec 003/004) unless `--no-route`, then run
   the routed classifiers for that file's text through
   `run_all_classifiers.run_all` (spec 004 requirements 9-14), which
   itself fans out across `--workers` threads per file. Classifier
   modules and the router are loaded **once** for the whole repo scan (in
   the main thread, before any file task starts), not once per file,
   since import cost is fixed and per-file cost is only the
   classification call itself. Progress reporting (unless `--quiet`)
   MUST reflect a thread-safe completed-file count (`[{done}/{total}]
   file(s) scanned`) rather than which specific file is "current", since
   many files are in flight at once.
9a. `--file-workers` and `--workers` compose multiplicatively (up to
    `file_workers * workers` concurrent classification threads at once);
    this is not auto-throttled, so callers scanning very large repos
    against a rate-limited API should tune one or both down (documented
    as an Open Question, not solved by this spec).
10. Findings MUST retain a `file` key (the repo-relative path) in
    addition to the existing finding shape (spec 004 requirement 12,
    which as of spec 007 also includes a `level` key), so a repo-wide
    report can group/sort by file, confidence, or level.
11. A per-file classification failure (e.g. one file's text causes a
    single module to raise, or the file's task itself raises
    unexpectedly) MUST be handled exactly as spec 004 already handles a
    per-module failure (recorded, skipped, run continues) and MUST NOT
    abort the scan of remaining files.

### Confidence levels (spec 007)

11a. Every finding's `level` (`"Pass"`/`"Review"`/`"Failed"`,
     `confidence_levels.confidence_level()`) MUST be computed using
     `--failed-threshold`/`--review-threshold` if given, else spec 007's
     environment-variable/default resolution.
11b. The printed report (`print_report`) MUST exclude `level == "Pass"`
     findings from its table (spec 007 requirement 7), with a summary
     line reporting how many were hidden. `--json <path>` output MUST
     always include every finding regardless of level.

### Optional LLM-assisted review of "Review"-level findings (spec 003)

11c. `--llm-review` (off by default) MUST, after scanning completes,
     call `router.llm_review_findings(findings, repo_path, backend=
     args.llm_review_backend, ...)` (spec 003) so findings still at level
     `"Review"` get a second opinion from an external coding-agent CLI
     (`copilot`/`claude`/`codex`, `--llm-review-backend`, default
     `copilot`) and are reclassified to `"Pass"`/`"Failed"` accordingly
     before the report is printed.
11d. This pass MUST run against the resolved local repo path (the clone,
     if `--repo-url` was used) and MUST happen before any temporary clone
     cleanup, so the reviewing CLI can read the same file content the
     scan itself classified.
11e. `repo_scan.py` MUST support `--llm-review-timeout <seconds>`
     (default `300`), `--llm-review-prompt-path <path>` /
     `--llm-review-response-path <path>` (save the generated prompt /
     raw CLI response for inspection; an explicit `--llm-review-prompt-
     path` also disables auto-cleanup of that file), `--llm-review-arg`
     (repeatable, appended verbatim to the backend's CLI invocation), and
     `--keep-llm-review-artifacts` (don't delete the auto-generated temp
     prompt file). After the pass, `repo_scan.py` MUST print a one-line
     summary (findings reviewed, reclassified to Pass/Failed, left
     unresolved).
11f. The Failed/Review report (Requirement 12+) MUST be printed
     reflecting whatever levels resulted from the LLM-review pass **even
     if that pass fails entirely**, not just when it partially succeeds.
     `repo_scan.py` MUST wrap its call to `router.llm_review_findings()`
     in its own `try/except` as a defense-in-depth guard on top of that
     function's own never-raises contract (spec 003 requirement 8h): if
     the call raises for any reason, `repo_scan.py` MUST print a warning,
     record the error, and continue on to print the report using
     `findings` exactly as they stood beforehand (i.e. still showing
     `"Failed"`/`"Review"` levels from the scan itself), rather than
     letting an LLM-review failure abort the whole run and lose the
     scan's output entirely.

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
    `--no-codegraph` (force fallback mode, skipping the local auto-install
    attempt too, even if CodeGraph could be installed locally, for
    comparison/debugging), `--max-files <int>`, `--include <glob>`
    (repeatable), `--exclude <glob>` (repeatable), `--workers <int>`
    (per-file classification pool, passed through to spec 004's
    `run_all`, default matching spec 004's default of 16),
    `--file-workers <int>` (outer cross-file pool, default `25`),
    `--threshold <float>`, `--top <int>`, `--top-per-file <int>`,
    `--no-route`, `--route-threshold <float>`, `--failed-threshold
    <float>`, `--review-threshold <float>` (spec 007), `--llm-review`,
    `--llm-review-backend {copilot,claude,codex}` (default `copilot`),
    `--llm-review-timeout <seconds>` (default `300`),
    `--llm-review-prompt-path <path>`, `--llm-review-response-path
    <path>`, `--llm-review-arg <arg>` (repeatable), `--keep-llm-review-
    artifacts`, `--json <path>`, `--quiet`.

## Interfaces / Data Model

```python
def resolve_target(target: str, ref: str | None, clone_dir: str | None) -> tuple[Path, bool]
    # returns (local_repo_path, is_temporary_clone); clones via git if `target` is a URL
def codegraph_install_dir(repo_path: Path) -> Path             # <repo_path>/.codegraph-cli
def codegraph_bin_path(repo_path: Path) -> Path                # .../.codegraph-cli/node_modules/.bin/codegraph
def codegraph_available(repo_path: Path) -> bool               # checks the resolved local path only, never PATH
def install_codegraph(repo_path: Path) -> bool                 # best-effort local `npm install --prefix ... --no-save`, never raises
def ensure_codegraph_index(repo_path: Path) -> bool           # True if usable index exists after this call
def list_files_via_codegraph(repo_path: Path) -> list[dict]   # [{path, language, nodeCount}, ...]
def list_files_fallback(repo_path: Path) -> list[dict]        # same shape, walk-based
def rank_files(files: list[dict], repo_path: Path) -> list[dict]  # reachability-aware ordering (Req. 7)
def scan_repo(repo_path: Path, file_workers: int = 25,
              failed_threshold: float | None = None,
              review_threshold: float | None = None, **options) -> RepoScanResult
```

`RepoScanResult` finding shape extends spec 004's finding dict (which as
of spec 007 includes `level`) with one extra key: `{file: str, cheatsheet:
str, url: str, category: str, description: str, confidence: float,
level: str}`.

## Error Handling Summary

| Failure | Effect |
|---|---|
| `--repo-url` given but `git clone` fails (bad URL, auth, network) | Clear error printed, exit non-zero, no fallback |
| `codegraph` not installed locally for this repo (`<repo>/.codegraph-cli/node_modules/.bin/codegraph` missing) and `--no-codegraph` not given | Local auto-install attempted (`npm install --prefix <repo>/.codegraph-cli --no-save @colbymchenry/codegraph`); on success, proceeds as available |
| `npm` missing, or local auto-install itself fails, or the local binary still doesn't exist after install | Fallback file walk (Req. 8), notice printed |
| `codegraph init`/`sync`/`status`/`files`/`query` errors or returns malformed JSON | Fallback file walk for this run, warning printed |
| One file's text fails a classifier module | That (file, module) pair recorded as an error, rest of scan continues (spec 004 semantics, per file) |
| One file's classification task itself raises unexpectedly | Recorded as an error for that file, other files' tasks continue (Req. 11) |
| `router.route()` fails for a given file | That file falls back to running all loaded classifiers unfiltered (spec 004 semantics, per file) |
| Zero files selected to scan | Print a clear message and exit non-zero rather than a silent empty report |
| `--llm-review` backend CLI missing/times out/unparseable response, or the LLM-review step fails/raises unexpectedly for any other reason | Warning printed; unresolved findings stay at their pre-LLM-review level (`"Review"` for anything not reclassified); the Failed/Review report is still printed regardless (fail-soft, spec 003 requirement 8h; defense-in-depth in `repo_scan.py`, Req. 11f) |


## Implementation Notes

- CodeGraph install used for verification during spec authoring:
  `npm install -g @colbymchenry/codegraph` (v1.6.0), confirmed working
  fully offline/local after install (no API key, no network calls at
  scan time -- CodeGraph's own docs describe it as 100% local/SQLite-backed).
  `repo_scan.py` itself, however, installs CodeGraph **locally per target
  repo** (`npm install --prefix <repo>/.codegraph-cli --no-save
  @colbymchenry/codegraph`, `install_codegraph()`), not globally: this
  avoids mutating any shared/global npm state, works without root/admin
  install permissions, keeps different target repos' CodeGraph versions
  independent of each other, and means the check for "is CodeGraph
  available" (`codegraph_available()`) resolves a fixed on-disk path
  under the repo rather than consulting `PATH`/`shutil.which` at all --
  every CodeGraph subprocess call passes that resolved path as `argv[0]`.
  This runs automatically whenever the local binary isn't already present
  for that repo and `--no-codegraph` wasn't given, rather than requiring
  the caller to install anything (globally or locally) first.
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
- Cross-file parallelism (`--file-workers`) and per-file classifier
  parallelism (`--workers`) are nested thread pools, not a single
  flattened pool: the outer pool's worker threads each block on the
  inner `run_all_classifiers.run_all` call, which spawns its own pool.
  All result aggregation happens back on the main thread via
  `as_completed()`, so no additional locking was needed around the
  shared findings list.

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
- `--file-workers * --workers` concurrent classification threads is not
  auto-throttled against API rate limits; very large repos scanned with
  high defaults against a rate-limited backend may need manual tuning of
  one or both flags.
- The LLM-review prompt (spec 003) is not chunked/batched for repos with
  very large numbers of `Review`-level findings in one run; a single
  prompt file covering everything is built and sent in one CLI
  invocation. Batching is a possible future improvement.
- Auto-installing CodeGraph locally into `<repo_path>/.codegraph-cli/` as
  a side-effect of running `repo_scan.py` is a deliberate convenience
  trade-off: it writes into the target repo's own directory tree (like
  `.codegraph/`'s index data already does). Environments that don't want
  this side effect at all (read-only mounts, strict no-write policies on
  the scanned tree) should use `--no-codegraph`. Because the install is
  local rather than global, repeatedly scanning many different repos
  does not accumulate global npm state, but it does mean CodeGraph gets
  re-downloaded once per distinct target repo the first time it's
  scanned (no shared cache across repos in this implementation).
