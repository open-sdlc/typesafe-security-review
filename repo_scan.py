"""Whole-repository scanner built on CodeGraph + the classifier pipeline.

Implements spec 006 (specs/006-full-repo-scan/spec.md): given a local path
or a git URL, this scans an entire repository instead of one file at a
time. It uses CodeGraph (https://github.com/colbymchenry/codegraph) --
an external, local, per-project code-graph indexer -- to find the files
that actually contain executable code (functions/methods/classes) so
scanning skips docs, config, data, and other non-code files without a
hand-maintained extension allowlist. If `codegraph` isn't already
installed locally for the target repo, this module attempts to install it
automatically as a **local, per-repo** dependency (`npm install --prefix
<repo>/.codegraph-cli --no-save @colbymchenry/codegraph`, unless
`--no-codegraph` is given) before falling back to a plain filesystem walk.
This is a project-local install, not a global one, and the resulting
binary is always invoked by its resolved on-disk path -- no reliance on
`codegraph` being present on `PATH`.

Every selected file is then classified using the existing, completely
unmodified pipeline: `router.route_modules()` narrows the classifiers run
per file (unless --no-route), and `run_all_classifiers.run_all()` does the
actual parallel classification. Files are themselves scanned concurrently
(`--file-workers`, spec 006), each still fanning its own classifiers out
across `--workers` threads. This module only decides *what text* to feed
that pipeline and how to merge many per-file reports into one repo-wide
report.

Every finding is also labeled with a confidence `level` -- "Pass",
"Review", or "Failed" (spec 007, `confidence_levels.py`) -- and the
printed report hides "Pass"-level findings (`--json` output keeps
everything). Optionally (`--llm-review`, spec 003), findings left at
"Review" after scanning can be sent to an external coding-agent CLI
(copilot/claude/codex) for a second opinion that reclassifies them to
"Pass" or "Failed".

Usage:
    python repo_scan.py                                   # scan the cwd
    python repo_scan.py /path/to/repo
    python repo_scan.py --repo-url https://github.com/org/repo.git
    python repo_scan.py --repo-url git@github.com:org/repo.git --ref main
    python repo_scan.py --repo-url https://github.com/org/repo.git --json out.json
    python repo_scan.py /path/to/repo --max-files 50 --top 30
    python repo_scan.py /path/to/repo --no-codegraph   # force plain file walk, skip auto-install
    python repo_scan.py /path/to/repo --file-workers 25
    python repo_scan.py /path/to/repo --llm-review --llm-review-backend claude
"""

import argparse
import fnmatch
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import run_all_classifiers as rac
import router
import confidence_levels

CODEGRAPH_BIN = "codegraph"
CODEGRAPH_NPM_PACKAGE = "@colbymchenry/codegraph"
# Local, per-repo install location -- deliberately NOT global (`npm
# install -g`) and NOT dependent on `codegraph` being on PATH. A dedicated
# dot-directory, separate from CodeGraph's own `.codegraph/` index data,
# so the npm install and the index never interfere with each other.
CODEGRAPH_LOCAL_DIRNAME = ".codegraph-cli"

# Mirrors the language families CodeGraph itself parses -- used only by the
# fallback file walk when `codegraph` isn't available/usable at all.
FALLBACK_EXTENSIONS = {
    ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py", ".go", ".rs",
    ".java", ".cs", ".php", ".rb", ".c", ".h", ".cpp", ".cc", ".cxx",
    ".hpp", ".m", ".mm", ".swift", ".kt", ".kts", ".scala", ".dart",
    ".lua", ".r", ".cfc", ".cfm", ".cbl", ".cob", ".sol", ".tf", ".svelte",
    ".vue", ".astro", ".liquid", ".pas", ".vb", ".erl", ".ex", ".exs",
}
FALLBACK_EXCLUDE_DIRS = {
    ".git", ".codegraph", CODEGRAPH_LOCAL_DIRNAME, "node_modules", "vendor",
    "venv", ".venv", "dist", "build", "__pycache__", ".tox", "target",
    "bin", "obj", ".mypy_cache", ".pytest_cache", "coverage",
}



def looks_like_git_url(value: str) -> bool:
    """Heuristic: does `value` look like a git remote rather than a local path?"""
    return bool(value) and (
        value.startswith(("https://", "http://", "git@", "ssh://"))
        or value.endswith(".git")
    )


def run_cmd(cmd, cwd=None, timeout=None):
    """Run `cmd`, returning (returncode, stdout, stderr). Never raises for a
    non-zero exit or missing binary -- callers decide how to degrade."""
    try:
        result = subprocess.run(
            cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout
        )
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError as exc:
        return 127, "", str(exc)
    except subprocess.TimeoutExpired as exc:
        return 124, "", str(exc)


def clone_repo(url: str, ref: str, dest: Path) -> None:
    """Shallow-clone `url` (optionally at `ref`) into `dest`. Raises
    RuntimeError with a caller-facing message on failure. Falls back to a
    full clone + checkout if a shallow clone of `ref` isn't possible (e.g.
    `ref` is a bare commit SHA some hosts won't shallow-clone directly)."""
    cmd = ["git", "clone", "--depth", "1"]
    if ref:
        cmd += ["--branch", ref]
    cmd += [url, str(dest)]
    code, _, err = run_cmd(cmd)
    if code == 0:
        return

    if ref:
        # Retry: full clone, then checkout the ref explicitly (covers bare
        # commit SHAs, which --branch cannot shallow-clone on many hosts).
        shutil.rmtree(dest, ignore_errors=True)
        dest.mkdir(parents=True, exist_ok=True)
        code2, _, err2 = run_cmd(["git", "clone", url, str(dest)])
        if code2 == 0:
            code3, _, err3 = run_cmd(["git", "-C", str(dest), "checkout", ref])
            if code3 == 0:
                return
            raise RuntimeError(f"cloned '{url}' but failed to checkout ref '{ref}': {err3.strip()}")
        raise RuntimeError(f"failed to clone '{url}': {err2.strip()}")

    raise RuntimeError(f"failed to clone '{url}': {err.strip()}")


def resolve_target(target: str, repo_url: str, ref: str, clone_dir: str):
    """Return (repo_path: Path, is_temporary_clone: bool). Clones via git
    if `repo_url` is given, or if `target` itself looks like a git URL."""
    url = repo_url or (target if looks_like_git_url(target) else None)
    if not url:
        path = Path(target or ".").resolve()
        if not path.is_dir():
            raise SystemExit(f"error: path not found or not a directory: {path}")
        return path, False

    dest = Path(clone_dir).resolve() if clone_dir else Path(tempfile.mkdtemp(prefix="repo_scan_"))
    dest.mkdir(parents=True, exist_ok=True)
    print(f"Cloning {url}{f' @ {ref}' if ref else ''} -> {dest} ...", file=sys.stderr)
    try:
        clone_repo(url, ref, dest)
    except RuntimeError as exc:
        if not clone_dir:
            shutil.rmtree(dest, ignore_errors=True)
        raise SystemExit(f"error: {exc}")
    return dest, clone_dir is None


def codegraph_install_dir(repo_path: Path) -> Path:
    """Local, per-repo npm install prefix for CodeGraph -- deliberately a
    dot-directory *inside the target repo*, never the global npm prefix."""
    return Path(repo_path) / CODEGRAPH_LOCAL_DIRNAME


def codegraph_bin_path(repo_path: Path) -> Path:
    """Resolved on-disk path to the locally-installed `codegraph` binary
    for `repo_path`. Always invoked by this path -- never by bare name via
    PATH lookup -- so no global/PATH install is required at all."""
    return codegraph_install_dir(repo_path) / "node_modules" / ".bin" / CODEGRAPH_BIN


def codegraph_available(repo_path: Path) -> bool:
    return codegraph_bin_path(repo_path).is_file()


def install_codegraph(repo_path: Path) -> bool:
    """Best-effort local install of CodeGraph into
    `<repo_path>/.codegraph-cli/` (via `npm install --prefix ... --no-save`,
    NOT `npm install -g`), so a repo scan works out of the box without a
    prior global install and without requiring `codegraph` on PATH.
    Returns True if the local binary exists once this returns (whether it
    was already there or the install succeeded), False otherwise --
    callers fall back to the plain file walk (Requirement 8), never raise.
    `--no-save` keeps this from touching the target repo's own
    package.json/lockfile, in case it has one."""
    if shutil.which("npm") is None:
        print(
            "NOTICE: codegraph not found locally and npm is not on PATH; cannot auto-install "
            f"(install npm, or install codegraph yourself under {codegraph_install_dir(repo_path)}, "
            "or pass --no-codegraph to silence this notice).",
            file=sys.stderr,
        )
        return False

    install_dir = codegraph_install_dir(repo_path)
    install_dir.mkdir(parents=True, exist_ok=True)
    print(
        f"codegraph not found locally; installing it into {install_dir} with "
        f"`npm install --prefix {install_dir} --no-save {CODEGRAPH_NPM_PACKAGE}` ...",
        file=sys.stderr,
    )
    code, _, err = run_cmd(
        ["npm", "install", "--prefix", str(install_dir), "--no-save", CODEGRAPH_NPM_PACKAGE],
        timeout=600,
    )
    if code != 0:
        print(f"WARNING: local install of codegraph failed: {err.strip()}", file=sys.stderr)
        return False
    return codegraph_available(repo_path)


def ensure_codegraph_index(repo_path: Path) -> bool:
    """Build or refresh `.codegraph/` for `repo_path`. Returns True if a
    usable index exists once this returns, False otherwise (caller should
    fall back to a plain file walk)."""
    codegraph_bin = str(codegraph_bin_path(repo_path))
    code, out, _ = run_cmd([codegraph_bin, "status", "--json", str(repo_path)])
    initialized = False
    if code == 0:
        try:
            initialized = bool(json.loads(out).get("initialized"))
        except (json.JSONDecodeError, AttributeError):
            initialized = False

    if not initialized:
        code, _, err = run_cmd([codegraph_bin, "init", "--yes", str(repo_path)], timeout=1800)
        if code != 0:
            print(f"WARNING: codegraph init failed: {err.strip()}", file=sys.stderr)
            return False
    else:
        # Keep a repeated scan (e.g. in CI on every commit) accurate against
        # the current working tree rather than a stale prior index.
        run_cmd([codegraph_bin, "sync", str(repo_path)], timeout=1800)

    code, out, _ = run_cmd([codegraph_bin, "status", "--json", str(repo_path)])
    if code != 0:
        return False
    try:
        return bool(json.loads(out).get("initialized"))
    except (json.JSONDecodeError, AttributeError):
        return False


def list_files_via_codegraph(repo_path: Path):
    """Return [{path, language, nodeCount, size}, ...] for every file
    CodeGraph's parser recognizes as source code, or None on failure."""
    codegraph_bin = str(codegraph_bin_path(repo_path))
    code, out, err = run_cmd(
        [codegraph_bin, "files", "--json", "--path", str(repo_path)], timeout=300
    )
    if code != 0:
        print(f"WARNING: codegraph files failed: {err.strip()}", file=sys.stderr)
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        # CodeGraph prints a plain-text notice (not JSON) when the index has
        # zero files -- a legitimate empty result, not a failure.
        if "no files indexed" in out.lower():
            return []
        print(f"WARNING: codegraph files returned invalid JSON: {out.strip()[:200]}", file=sys.stderr)
        return None


def list_route_files(repo_path: Path) -> set:
    """Best-effort: file paths CodeGraph linked to a detected web-framework
    route/handler (Requirement 7a's entry-point priority signal). Returns an
    empty set if unavailable or the repo simply has no detected routes --
    both are treated the same way (no boost), never an error."""
    codegraph_bin = str(codegraph_bin_path(repo_path))
    code, out, _ = run_cmd(
        [codegraph_bin, "query", "", "--kind", "route", "--json", "--limit", "5000", "--path", str(repo_path)],
        timeout=120,
    )
    if code != 0:
        return set()
    try:
        nodes = json.loads(out)
    except json.JSONDecodeError:
        return set()
    files = set()
    for entry in nodes:
        file_path = (entry.get("node") or {}).get("filePath")
        if file_path:
            files.add(file_path)
    return files



def list_files_fallback(repo_path: Path):
    """Plain filesystem walk, filtered by FALLBACK_EXTENSIONS. Used only
    when CodeGraph isn't available/usable at all (Requirement 8)."""
    files = []
    for root, dirs, filenames in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in FALLBACK_EXCLUDE_DIRS and not d.startswith(".")]
        for filename in filenames:
            ext = Path(filename).suffix.lower()
            if ext not in FALLBACK_EXTENSIONS:
                continue
            full = Path(root) / filename
            try:
                size = full.stat().st_size
            except OSError:
                continue
            rel = full.relative_to(repo_path).as_posix()
            files.append({"path": rel, "language": ext.lstrip("."), "nodeCount": None, "size": size})
    return files


def apply_glob_filters(files, includes, excludes):
    if includes:
        files = [f for f in files if any(fnmatch.fnmatch(f["path"], pat) for pat in includes)]
    if excludes:
        files = [f for f in files if not any(fnmatch.fnmatch(f["path"], pat) for pat in excludes)]
    return files


def rank_files(files, route_files):
    """Order files so a `--max-files` cap keeps the highest-value files:
    (a) files linked to a detected framework route/handler first, then
    (b) largest symbol count / file size as a tie-breaker (Requirement 7)."""
    def key(f):
        is_route = f["path"] in route_files
        size_signal = f.get("nodeCount") if f.get("nodeCount") is not None else f.get("size", 0)
        return (0 if is_route else 1, -(size_signal or 0))

    return sorted(files, key=key)


def read_file_text(repo_path: Path, rel_path: str):
    try:
        return (repo_path / rel_path).read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeDecodeError):
        return None


def scan_repo(repo_path: Path, *, use_codegraph, include, exclude, max_files,
              workers, file_workers, threshold, top_per_file, no_route, route_threshold,
              failed_threshold, review_threshold, quiet):
    """Run the full scan. Returns a result dict; never raises for per-file
    or per-module failures (those are collected, not fatal)."""
    codegraph_used = False
    degraded_reason = None
    files = None

    if use_codegraph and not codegraph_available(repo_path):
        install_codegraph(repo_path)  # best-effort; falls through to availability check below either way

    if use_codegraph and codegraph_available(repo_path):
        if ensure_codegraph_index(repo_path):
            files = list_files_via_codegraph(repo_path)
            if files is not None:
                codegraph_used = True
        if not codegraph_used:
            degraded_reason = "CodeGraph index could not be built/read"
    elif use_codegraph:
        degraded_reason = "codegraph is not installed locally for this repo and auto-install did not succeed"

    if files is None:
        files = list_files_fallback(repo_path)
        if degraded_reason:
            print(
                f"NOTICE: {degraded_reason}; falling back to a plain file walk "
                f"(no executable-code filtering or route-based prioritization).",
                file=sys.stderr,
            )

    files = apply_glob_filters(files, include, exclude)

    route_files = list_route_files(repo_path) if codegraph_used else set()
    files = rank_files(files, route_files)

    if max_files:
        files = files[:max_files]

    if not files:
        return {
            "error": "no files selected to scan",
            "codegraph_used": codegraph_used,
            "files_scanned": 0,
            "findings": [],
            "load_errors": [],
            "run_errors": [],
        }

    paths = rac.discover_classifier_paths()
    modules, load_errors = rac.load_all_classifiers(paths)
    if load_errors and not quiet:
        print(f"WARNING: {len(load_errors)} classifier module(s) failed to load:", file=sys.stderr)
        for name, err in load_errors:
            print(f"  - {name}: {err}", file=sys.stderr)
    if not quiet:
        print(f"Loaded {len(modules)} classifier(s). Scanning {len(files)} file(s)"
              f"{' (CodeGraph-selected)' if codegraph_used else ' (fallback walk)'}...",
              file=sys.stderr)

    all_findings = []
    run_errors = []
    files_skipped = 0
    start = time.time()
    done_count = 0

    def scan_one_file(f):
        """Classify a single file. Returns (rel_path, findings, file_run_errors, skipped: bool)."""
        rel_path = f["path"]
        text = read_file_text(repo_path, rel_path)
        if not text or not text.strip():
            return rel_path, [], [], True

        file_modules = modules
        if not no_route:
            file_modules, _, route_error = rac.route_modules(file_modules, text, threshold=route_threshold)
            if route_error:
                file_modules = modules  # fail open: run everything for this file

        file_findings, file_run_errors = rac.run_all(
            file_modules, text, workers=workers, quiet=True,
            failed_threshold=failed_threshold, review_threshold=review_threshold,
        )
        file_findings = [f2 for f2 in file_findings if f2["confidence"] > threshold]
        file_findings.sort(key=lambda f2: -f2["confidence"])
        if top_per_file:
            file_findings = file_findings[:top_per_file]
        for finding in file_findings:
            finding["file"] = rel_path
        return rel_path, file_findings, file_run_errors, False

    if not quiet:
        print(f"Scanning with up to {file_workers} file(s) concurrently...", file=sys.stderr)

    with ThreadPoolExecutor(max_workers=max(1, file_workers)) as executor:
        future_to_path = {executor.submit(scan_one_file, f): f["path"] for f in files}
        for future in as_completed(future_to_path):
            rel_path = future_to_path[future]
            try:
                _, file_findings, file_run_errors, skipped = future.result()
            except Exception as exc:  # noqa: BLE001 - one file's failure must not abort the scan
                run_errors.append((rel_path, "scan_one_file", str(exc)))
                skipped, file_findings, file_run_errors = True, [], []

            done_count += 1
            if skipped:
                files_skipped += 1
            all_findings.extend(file_findings)
            run_errors.extend((rel_path, name, err) for name, err in file_run_errors)
            if not quiet:
                print(f"\r[{done_count}/{len(files)}] file(s) scanned", end="", file=sys.stderr, flush=True)

    if not quiet:
        print(file=sys.stderr)

    all_findings.sort(key=lambda f2: -f2["confidence"])
    elapsed = time.time() - start

    return {
        "codegraph_used": codegraph_used,
        "files_scanned": len(files) - files_skipped,
        "files_skipped": files_skipped,
        "elapsed": elapsed,
        "findings": all_findings,
        "load_errors": load_errors,
        "run_errors": run_errors,
        "classifiers_loaded": len(modules),
    }


def print_report(result: dict, top: int, json_path: str) -> None:
    findings = result["findings"]
    shown = [f for f in findings if f.get("level") != confidence_levels.LEVEL_PASS]
    hidden_pass = len(findings) - len(shown)
    if top:
        shown = shown[:top]

    print(f"\n=== Repo Scan Findings Report ({result.get('elapsed', 0):.1f}s) ===\n")
    rows = [
        (i + 1, f["file"], f["cheatsheet"], f["category"], f"{f['confidence']:.3f}", f.get("level", ""))
        for i, f in enumerate(shown)
    ]
    rac.print_table(("#", "file", "cheat_sheet", "category", "confidence", "level"), rows)

    print(
        f"\n{len(shown)} finding(s) shown (levels 'Review'/'Failed', of {len(findings)} total) across "
        f"{result['files_scanned']} file(s) scanned "
        f"({'CodeGraph-selected' if result['codegraph_used'] else 'plain file walk'})."
    )
    if hidden_pass:
        print(f"{hidden_pass} additional finding(s) at level 'Pass' are hidden from this table "
              f"(use --json to see everything, including 'Pass').")
    if result.get("files_skipped"):
        print(f"{result['files_skipped']} file(s) skipped (empty or unreadable/binary).")

    if result["run_errors"]:
        print(f"\n{len(result['run_errors'])} classification error(s):", file=sys.stderr)
        for rel_path, name, err in result["run_errors"][:20]:
            print(f"  - {rel_path} / {name}: {err}", file=sys.stderr)
        if len(result["run_errors"]) > 20:
            print(f"  ... and {len(result['run_errors']) - 20} more", file=sys.stderr)

    if json_path:
        with open(json_path, "w", encoding="utf-8") as fh:
            json.dump(result["findings"], fh, indent=2)
        print(f"\nFull findings written to {json_path}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("target", nargs="?", default=".", help="Local repo path, or a git URL")
    parser.add_argument("--repo-url", help="Git URL to clone and scan (overrides `target` as a URL)")
    parser.add_argument("--ref", help="Branch, tag, or commit to check out when cloning")
    parser.add_argument("--clone-dir", help="Clone destination (default: a temp dir, removed after scanning)")
    parser.add_argument("--keep-clone", action="store_true", help="Don't delete the temporary clone afterward")
    parser.add_argument("--no-codegraph", action="store_true", help="Skip CodeGraph entirely (no auto-install attempt); always use the plain file walk")
    parser.add_argument("--max-files", type=int, default=None, help="Scan at most N files (highest-priority first)")
    parser.add_argument("--include", action="append", default=[], help="Glob(s) of files to include (repeatable)")
    parser.add_argument("--exclude", action="append", default=[], help="Glob(s) of files to exclude (repeatable)")
    parser.add_argument("--workers", type=int, default=16, help="Parallel worker threads per file (default: 16)")
    parser.add_argument("--file-workers", type=int, default=25, help="Number of files scanned concurrently (default: 25)")
    parser.add_argument("--threshold", type=float, default=0.0, help="Minimum confidence to include in the report (default: 0.0)")
    parser.add_argument("--top", type=int, default=None, help="Only show the top N findings overall")
    parser.add_argument("--top-per-file", type=int, default=None, help="Only keep the top N findings per file")
    parser.add_argument("--no-route", action="store_true", help="Run all loaded classifiers on every file, skipping router.py")
    parser.add_argument("--route-threshold", type=float, default=0.35, help="Minimum router relevance to run a classifier on a file (default: 0.35)")
    confidence_levels.add_threshold_args(parser)
    parser.add_argument("--json", dest="json_path", help="Also write the full findings list as JSON to this path")
    parser.add_argument("--quiet", action="store_true", help="Suppress the live per-file progress output")
    router.add_llm_review_args(parser)
    args = parser.parse_args()

    repo_path, is_temp_clone = resolve_target(args.target, args.repo_url, args.ref, args.clone_dir)

    try:
        result = scan_repo(
            repo_path,
            use_codegraph=not args.no_codegraph,
            include=args.include,
            exclude=args.exclude,
            max_files=args.max_files,
            workers=args.workers,
            file_workers=args.file_workers,
            threshold=args.threshold,
            top_per_file=args.top_per_file,
            no_route=args.no_route,
            route_threshold=args.route_threshold,
            failed_threshold=args.failed_threshold,
            review_threshold=args.review_threshold,
            quiet=args.quiet,
        )
        if not result.get("error") and args.llm_review:
            try:
                result["findings"], llm_stats = router.llm_review_findings(
                    result["findings"],
                    repo_path,
                    backend=args.llm_review_backend,
                    timeout=args.llm_review_timeout,
                    prompt_path=args.llm_review_prompt_path,
                    response_path=args.llm_review_response_path,
                    keep_artifacts=args.keep_llm_review_artifacts,
                    extra_args=args.llm_review_arg,
                    quiet=args.quiet,
                )
                result["llm_review"] = llm_stats
            except Exception as exc:
                # Defense-in-depth on top of router.llm_review_findings()'s own
                # fail-soft contract: no matter what goes wrong with the LLM
                # review step, the scan's Failed/Review report below MUST still
                # be printed, reflecting whatever levels resulted (unresolved
                # findings simply remain at "Review").
                print(f"WARNING: LLM review step failed unexpectedly ({exc}); "
                      f"reporting findings without further reclassification.", file=sys.stderr)
                result["llm_review"] = {"error": str(exc)}
    finally:
        if is_temp_clone and not args.keep_clone:
            shutil.rmtree(repo_path, ignore_errors=True)
        elif is_temp_clone:
            print(f"\nClone kept at: {repo_path}", file=sys.stderr)

    if result.get("error"):
        print(f"error: {result['error']}", file=sys.stderr)
        return 1

    print_report(result, args.top, args.json_path)
    if result.get("llm_review"):
        stats = result["llm_review"]
        if "reviewed" in stats:
            print(
                f"\nLLM review ({args.llm_review_backend}): {stats['reviewed']} 'Review'-level finding(s) sent, "
                f"{stats['reclassified']} reclassified ({stats['to_pass']} -> Pass, {stats['to_failed']} -> Failed), "
                f"{stats['unresolved']} left at 'Review' (no/unparseable verdict)."
            )
            # Surface the actual failure reason even when some/all findings were
            # left unresolved due to an error (e.g. the backend CLI failing or
            # timing out), rather than silently looking like a plain parse miss.
            if stats.get("error"):
                print(f"  (reason: {stats['error']})", file=sys.stderr)
        else:
            print(f"\nLLM review ({args.llm_review_backend}): did not complete ({stats['error']}); "
                  f"findings reported at their pre-LLM-review levels.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
