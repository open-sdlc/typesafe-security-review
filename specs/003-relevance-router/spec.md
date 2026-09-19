# Spec 003: Relevance Router (`router.py`)

Status: Implemented (reverse-engineered from `router.py`; extended per
spec-driven addition of LLM-assisted review, see Requirements 8a-8g)

## Overview

`router.py` is a pre-filter that decides which of the 131 classifier
modules (spec 002) are worth running against a given input, so
`run_all_classifiers.py` (spec 004) doesn't waste API calls running, e.g.,
the Django/Laravel/Ruby-on-Rails classifiers against a plain `.java` file.
It follows the same "speculative fan-out" pattern the classifiers
themselves use: one relevance question per classifier, all sent in a
single parallel `system_one()` call.

`router.py` also hosts a second, independent feature: optional
LLM-assisted review of findings that land in the ambiguous `"Review"`
confidence band (spec 007), giving them a second opinion from an external
coding-agent CLI (`copilot`/`claude`/`codex`) before a final report is
produced. This is invoked by `repo_scan.py` (spec 006), not part of the
routing pre-filter itself, but lives here since it is conceptually the
same kind of relevance/triage judgment.

## Goals

- Reduce the number of classifier calls made per input to only those
  plausibly relevant, without a second network round trip per classifier.
- Be safe to disable or to fail: routing is an optimization, not a
  correctness requirement -- if it's wrong or unavailable, the system MUST
  still be able to run every classifier.
- Require exactly one manual step to register a new classifier's routing
  rule (an entry in `ROUTES`), since "when does this classifier apply" is
  not mechanically derivable from the module file itself.
- Optionally reduce the amount of ambiguous ("Review"-band) output a
  human has to manually triage, by delegating a second opinion to an
  external coding-agent CLI -- opt-in, configurable, and fail-soft (never
  blocks or crashes a scan if unavailable).

## Non-Goals

- `router.py` does not run any classifier itself -- it only scores
  relevance and lets the caller filter.
- `router.py` does not attempt language/framework auto-detection via file
  extension, shebang, or static parsing; relevance is judged the same way
  classification is, by asking the model.
- LLM-assisted review does not replace the classifier pipeline or the
  confidence-level bucketing (spec 007) -- it only re-judges findings
  already scored into the `"Review"` band, and only when explicitly
  enabled.

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

### LLM-assisted review of "Review"-level findings

This is a distinct, opt-in feature layered on top of the routing
registry above: instead of scoring *which classifiers to run*, it gives
findings that already ran and landed in the ambiguous `"Review"` band
(spec 007) a second opinion from an external coding-agent CLI, then
reclassifies them to `"Pass"` or `"Failed"` based on that opinion. It is
invoked by `repo_scan.py` (spec 006) via `--llm-review`, but the
mechanics live in `router.py` since it is conceptually another
relevance/triage judgment, like routing itself.

8a. `router.py` MUST define `LLM_REVIEW_BACKENDS: dict[str, list[str]]`,
    a registry of command templates keyed by backend name, with a
    `"{prompt}"` placeholder marking where the prompt text is substituted
    as a single argv element (never via a shell, to avoid shell
    injection from prompt content):
    - `"copilot": ["copilot", "-p", "{prompt}", "-s", "--allow-all-tools"]`
      (`--allow-all-tools` is required for Copilot CLI's non-interactive
      mode, per `copilot --help`).
    - `"claude": ["claude", "-p", "{prompt}"]` (print/non-interactive mode).
    - `"codex": ["codex", "exec", "{prompt}"]` (non-interactive mode;
      read-only sandbox by default per Codex's own docs).
    `DEFAULT_LLM_REVIEW_BACKEND = "copilot"`,
    `DEFAULT_LLM_REVIEW_TIMEOUT = 300` (seconds).
8b. `build_llm_review_prompt(review_findings, repo_path) -> str` MUST
    assign each finding a stable numeric `id` (its index within the
    `review_findings` list, NOT any value from the finding itself), group
    findings by their `file` key, include each referenced file's current
    on-disk text (read relative to `repo_path`; a file that can't be read
    is marked `"(file text unavailable)"` rather than aborting the whole
    prompt), and instruct the model to respond with ONLY a single fenced
    ` ```json ` array covering every id, each entry shaped `{"id": int,
    "verdict": "pass"|"fail", "reason": str}`.
8c. `run_llm_review_backend(prompt, backend, repo_path, timeout,
    extra_args=None) -> tuple[str, str | None]` MUST invoke the resolved
    command via `subprocess.run(cmd, cwd=repo_path, capture_output=True,
    text=True, timeout=timeout)` (no `shell=True`) and MUST NOT raise:
    an unknown backend name, a missing executable (`FileNotFoundError`),
    a timeout (`subprocess.TimeoutExpired`), or a non-zero exit MUST each
    be converted into a returned error string (with stdout, if any, still
    returned separately) rather than propagating an exception. Any
    `extra_args` (from `--llm-review-arg`) MUST be appended verbatim after
    the templated command.
8d. `parse_llm_review_response(raw: str) -> dict[int, dict]` MUST first
    look for fenced ` ```json ... ``` ` (or ` ``` ... ``` `) blocks
    containing a JSON array; if none are found, it MUST fall back to the
    last top-level `[...]` span in the raw text. It MUST try candidates
    in reverse order (most recent/last block first) and return the first
    one that parses as a JSON list containing at least one usable
    `{"id": int, "verdict": "pass"|"fail"}` entry (extra/malformed entries
    within an otherwise-parseable list are skipped, not fatal). If no
    candidate yields any usable entries, it MUST return `{}` -- never
    raise.
8e. `llm_review_findings(findings, repo_path, *, backend=
    DEFAULT_LLM_REVIEW_BACKEND, timeout=DEFAULT_LLM_REVIEW_TIMEOUT,
    prompt_path=None, response_path=None, keep_artifacts=False,
    extra_args=None, quiet=False) -> tuple[list, dict]` is the
    orchestration entry point:
    - It MUST select every finding whose `level ==
      confidence_levels.LEVEL_REVIEW`; if none exist, it MUST return
      immediately with a zeroed stats dict and make no CLI call at all.
    - It MUST build the prompt (8b), write it to `prompt_path` if given,
      else to a new `tempfile.mkstemp(prefix="repo_scan_llm_review_",
      suffix=".prompt.txt")` file, and print (unless `quiet`) a notice
      to stderr naming the prompt file location and chosen backend before
      invoking it.
    - It MUST call `run_llm_review_backend` (8c) exactly once for the
      whole batch (not once per finding/file).
    - If `response_path` is given, the raw response text MUST be written
      there regardless of success/failure.
    - On a backend error (8c), it MUST print a warning (unless `quiet`)
      and leave every selected finding at `"Review"` (fail-soft).
    - On success, it MUST parse the response (8d); for every finding id
      with a resolved verdict, it MUST set that finding's `level` to
      `confidence_levels.LEVEL_PASS` (verdict `"pass"`) or
      `confidence_levels.LEVEL_FAILED` (verdict `"fail"`), and MUST also
      record `llm_verdict`/`llm_reason` keys on that finding. Any
      selected finding whose id is absent from the parsed verdicts MUST
      be left unchanged at `"Review"`.
    - `findings` MUST be mutated in place (and also returned, alongside a
      `stats` dict of `reviewed`/`reclassified`/`to_pass`/`to_failed`/
      `unresolved`/`error` counts) so callers can print a summary without
      needing to recompute deltas themselves.
    - The auto-generated temp prompt file MUST be deleted afterward
      unless `keep_artifacts` is true or an explicit `prompt_path` was
      given (in which case the caller owns that file and it is never
      auto-deleted).
8f. `add_llm_review_args(parser)` MUST register `--llm-review` (off by
    default), `--llm-review-backend` (`choices=sorted(LLM_REVIEW_BACKENDS)`,
    default `copilot`), `--llm-review-timeout` (default 300),
    `--llm-review-prompt-path`, `--llm-review-response-path`,
    `--llm-review-arg` (repeatable, `action="append"`), and
    `--keep-llm-review-artifacts` on a given argparse parser, so
    `repo_scan.py` (and any future caller) gets a consistent flag set
    without duplicating argparse wiring.
8g. **Security consideration (documented, not fully solved):** granting
    an agentic coding CLI tool access (`--allow-all-tools`, etc.) while it
    reviews a possibly-untrusted third-party repository carries inherent
    prompt-injection / unintended-action risk -- file content from the
    scanned repo is included verbatim in the prompt. This is mitigated,
    but not eliminated, by: the feature being opt-in (off by default);
    the prompt being fully self-contained (correctly answering it does
    not require the backend to invoke any tools, browse, or edit files);
    Codex's `exec` defaulting to a read-only sandbox; and
    `--llm-review-arg` letting callers pass a given backend's own
    stricter permission flags (e.g. Claude's `--permission-mode`) if
    they want tighter guarantees than the default template provides.
8h. `llm_review_findings()` MUST NOT let *any* exception escape,
    including ones not otherwise anticipated by 8a-8g (e.g. an `OSError`
    writing the prompt/response file, or an unexpected error inside the
    prompt builder). The body of the function (from prompt-building
    onward) MUST run under a blanket `try/except Exception`; on any such
    failure it MUST record a descriptive message in `stats["error"]`,
    print a warning (unless `quiet`), leave every affected finding at its
    current level (`"Review"` for anything not already resolved), and
    still `return (findings, stats)` normally. This is what makes the
    "post-LLM-review report is always shown, even when the LLM review
    itself fails" guarantee (spec 006 CLI contract) actually hold for
    every failure mode, not just the ones explicitly handled by
    `run_llm_review_backend`/`parse_llm_review_response`.

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

# LLM-assisted review of "Review"-level findings
LLM_REVIEW_BACKENDS: dict[str, list[str]]   # backend name -> command template (with "{prompt}")
DEFAULT_LLM_REVIEW_BACKEND: str             # "copilot"
DEFAULT_LLM_REVIEW_TIMEOUT: int             # 300 (seconds)

def build_llm_review_prompt(review_findings: list, repo_path) -> str
def run_llm_review_backend(prompt: str, backend: str, repo_path, timeout: int,
                            extra_args: list[str] | None = None) -> tuple[str, str | None]
def parse_llm_review_response(raw: str) -> dict[int, dict]     # id -> {verdict, reason}
def llm_review_findings(findings: list, repo_path, *, backend: str = DEFAULT_LLM_REVIEW_BACKEND,
                         timeout: int = DEFAULT_LLM_REVIEW_TIMEOUT, prompt_path=None,
                         response_path=None, keep_artifacts: bool = False,
                         extra_args: list[str] | None = None, quiet: bool = False) -> tuple[list, dict]
def add_llm_review_args(parser) -> None
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
- LLM-assisted review (Requirements 8a-8g) is conceptually independent of
  the routing registry (`ROUTES`/`route`/`select_relevant`) -- it shares
  this module because it is also a "should this apply / is this real"
  triage judgment layered on top of the deterministic classifier
  pipeline, not because it reuses any routing code directly. It depends
  on `confidence_levels.py` (spec 007) for the `LEVEL_REVIEW`/
  `LEVEL_PASS`/`LEVEL_FAILED` constants it reclassifies findings into,
  and is invoked by `repo_scan.py` (spec 006), not by `router.py`'s own
  `main()`.
- The prompt (8b) is deliberately self-contained (full file text inline,
  explicit instructions to answer without using tools) so that even a
  backend granted broad tool access (`--allow-all-tools`, etc.) has no
  *need* to act on the repo to produce a correct verdict -- the tool
  access exists only because some backends require it for non-interactive
  mode at all (e.g. Copilot), not because this feature asks them to use it.
- All three backend command templates were verified against each CLI's
  own `--help`/documentation rather than assumed from memory (see spec
  006 Implementation Notes for the verification note).

## Error Handling

- `router.py`'s own `main()` does not catch `route()` failures; an
  unhandled exception (e.g. no API key) propagates and the CLI exits
  non-zero with a traceback -- this is acceptable since `router.py` run
  standalone is a diagnostic tool, not a production path.
- `run_all_classifiers.py`'s `route_modules()` wraps its call to
  `router.route()` in a `try/except`, and on failure keeps every
  originally-loaded module (i.e. behaves as if every classifier passed
  routing) -- see spec 004 requirement on graceful routing fallback.
- `llm_review_findings()` and its helpers never raise: an unknown
  backend, missing executable, timeout, non-zero exit, unparseable
  response, or any other genuinely unexpected error (e.g. disk I/O while
  writing the prompt/response file, Requirement 8h's blanket guard) are
  all converted into an error string / empty verdict dict and reported
  via `stats["error"]` and a printed warning (unless `quiet`); affected
  findings simply stay at level `"Review"` rather than the run failing
  or crashing (fail-soft, consistent with this spec's and spec 004's
  existing error-handling conventions). This is what lets `repo_scan.py`
  (spec 006) always print its Failed/Review report reflecting the
  post-LLM-review state, even when the LLM review step fails outright.

## Open Questions

- No automated check currently confirms `ROUTES` and
  `classifiers/*_classifier.py` stay in exact 1:1 sync (a stem removed
  from one but not the other silently becomes a no-op entry, or a
  classifier that never gets routed unless `--no-route` is passed). A
  future improvement could add a startup assertion in
  `run_all_classifiers.py` or a small `tests/`-style check.
- LLM-assisted review sends the full content of every file with a
  `"Review"`-band finding in one prompt/one CLI call; there is no
  chunking/batching for repos where this would produce a very large
  prompt. A future improvement could split into multiple calls once a
  size threshold is crossed.
- The reviewing CLI is trusted to read (not necessarily act on) the
  actual repo file content via `cwd=repo_path`; combined with
  `--allow-all-tools`-style flags on some backends, this is a deliberate
  trade-off documented in Requirement 8g rather than a fully solved
  sandboxing guarantee.
