"""Eval harness for the classifier bank: scores each classifier's `good`/`bad`
fixture pair and checks it discriminates the way it should.

For every `classifiers/<stem>_classifier.py`, this looks for
`evals/fixtures/<stem>/bad.txt` (text that should clearly exhibit at least
one of that classifier's CATEGORIES) and `evals/fixtures/<stem>/good.txt`
(a safe counterpart that should not). It runs `classify_with_nouls()` on
both fixtures and checks:

    bad_max_confidence  >= --bad-threshold   (default 0.5)
    good_max_confidence <= --good-threshold  (default 0.3)

A classifier "passes" its eval only if both hold. This is a coarse check
(does the classifier fire clearly on an obvious positive and stay quiet on
an obvious negative), not a substitute for reviewing category quality by
hand -- see specs/002-classifier-module/spec.md for what makes a good
category description.

Usage:
    python evals/run_evals.py                       # run every classifier with fixtures
    python evals/run_evals.py --filter "sql*"        # only stems matching a glob (repeatable)
    python evals/run_evals.py --dry-run              # check fixture coverage only, no API calls
    python evals/run_evals.py --workers 8 --json evals/results.json
"""

import argparse
import fnmatch
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"

sys.path.insert(0, str(REPO_ROOT))
import run_all_classifiers as rac  # noqa: E402


def discover_fixture_pairs(stem_filters):
    """Return list of (stem, module_path, bad_path|None, good_path|None) for
    every classifier module, optionally narrowed by `stem_filters` globs."""
    paths = rac.discover_classifier_paths()
    pairs = []
    for path in paths:
        stem = path.stem
        if stem_filters and not any(fnmatch.fnmatch(stem, pat) for pat in stem_filters):
            continue
        fixture_dir = FIXTURES_DIR / stem
        bad_path = fixture_dir / "bad.txt"
        good_path = fixture_dir / "good.txt"
        pairs.append((
            stem,
            path,
            bad_path if bad_path.is_file() else None,
            good_path if good_path.is_file() else None,
        ))
    return pairs


def read_nonempty(path: Path):
    if path is None:
        return None
    text = path.read_text(encoding="utf-8")
    return text if text.strip() else None


def eval_one(stem, module_path, bad_path, good_path):
    """Load one classifier module and score its bad/good fixtures. Returns a
    result dict; never raises (errors are captured in the dict)."""
    result = {
        "stem": stem,
        "status": None,       # "pass" | "fail" | "error" | "missing_fixtures"
        "bad_max": None,
        "good_max": None,
        "top_bad_category": None,
        "bad_scores": None,
        "good_scores": None,
        "error": None,
    }

    bad_text = read_nonempty(bad_path)
    good_text = read_nonempty(good_path)
    if bad_text is None or good_text is None:
        result["status"] = "missing_fixtures"
        missing = []
        if bad_text is None:
            missing.append("bad.txt")
        if good_text is None:
            missing.append("good.txt")
        result["error"] = f"missing/empty: {', '.join(missing)}"
        return result

    try:
        module = rac.load_classifier_module(module_path)
    except Exception as exc:  # noqa: BLE001
        result["status"] = "error"
        result["error"] = f"module load failed: {exc}"
        return result

    try:
        bad_scores = module.classify_with_nouls(bad_text)
        good_scores = module.classify_with_nouls(good_text)
    except Exception as exc:  # noqa: BLE001
        result["status"] = "error"
        result["error"] = str(exc)
        return result

    result["bad_scores"] = bad_scores
    result["good_scores"] = good_scores
    bad_valid = {k: v for k, v in bad_scores.items() if v is not None}
    good_valid = {k: v for k, v in good_scores.items() if v is not None}
    result["bad_max"] = max(bad_valid.values()) if bad_valid else 0.0
    result["good_max"] = max(good_valid.values()) if good_valid else 0.0
    if bad_valid:
        result["top_bad_category"] = max(bad_valid, key=bad_valid.get)
    return result


def run_dry_run(pairs):
    """Fixture-coverage check only -- no API calls, works with no API key."""
    results = []
    for stem, _path, bad_path, good_path in pairs:
        bad_text = read_nonempty(bad_path)
        good_text = read_nonempty(good_path)
        if bad_text is not None and good_text is not None:
            status = "ok"
        else:
            missing = []
            if bad_text is None:
                missing.append("bad.txt")
            if good_text is None:
                missing.append("good.txt")
            status = f"missing: {', '.join(missing)}"
        results.append((stem, status))
    return results


def run_evals(pairs, workers, bad_threshold, good_threshold, quiet):
    results = []
    total = len(pairs)
    done = 0
    with ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
        future_to_stem = {
            executor.submit(eval_one, stem, module_path, bad_path, good_path): stem
            for stem, module_path, bad_path, good_path in pairs
        }
        for future in as_completed(future_to_stem):
            done += 1
            stem = future_to_stem[future]
            if not quiet:
                print(f"\r[{done}/{total}] evaluated: {stem[:60]:<60}", end="", file=sys.stderr, flush=True)
            result = future.result()
            if result["status"] is None:
                passed = (
                    result["bad_max"] is not None and result["bad_max"] >= bad_threshold
                    and result["good_max"] is not None and result["good_max"] <= good_threshold
                )
                result["status"] = "pass" if passed else "fail"
            results.append(result)
    if not quiet:
        print(file=sys.stderr)
    results.sort(key=lambda r: r["stem"])
    return results


def print_table(headers, rows) -> None:
    if not rows:
        print("(no rows)")
        return
    widths = [
        max(len(str(cell)) for cell in (header, *(row[i] for row in rows)))
        for i, header in enumerate(headers)
    ]

    def fmt(row):
        return "  ".join(str(cell).ljust(width) for cell, width in zip(row, widths))

    print(fmt(headers))
    print("  ".join("-" * width for width in widths))
    for row in rows:
        print(fmt(row))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--filter", action="append", default=[], help="Glob(s) of classifier stems to include (repeatable)")
    parser.add_argument("--bad-threshold", type=float, default=0.5, help="Minimum bad.txt max confidence to pass (default: 0.5)")
    parser.add_argument("--good-threshold", type=float, default=0.3, help="Maximum good.txt max confidence to pass (default: 0.3)")
    parser.add_argument("--workers", type=int, default=8, help="Parallel classifier evals (default: 8)")
    parser.add_argument("--dry-run", action="store_true", help="Only check fixture coverage; make no API calls")
    parser.add_argument("--json", dest="json_path", help="Write full per-classifier results as JSON to this path")
    parser.add_argument("--quiet", action="store_true", help="Suppress the live progress line")
    args = parser.parse_args()

    pairs = discover_fixture_pairs(args.filter)
    if not pairs:
        print("No classifiers matched.", file=sys.stderr)
        return 1

    if args.dry_run:
        coverage = run_dry_run(pairs)
        rows = [(stem, status) for stem, status in coverage]
        print_table(("classifier", "fixture_status"), rows)
        missing = [s for s, status in coverage if status != "ok"]
        print(f"\n{len(pairs) - len(missing)}/{len(pairs)} classifier(s) have both bad.txt and good.txt.")
        if missing:
            print(f"{len(missing)} missing/incomplete: {', '.join(missing)}")
        return 0

    start = time.time()
    results = run_evals(pairs, args.workers, args.bad_threshold, args.good_threshold, args.quiet)
    elapsed = time.time() - start

    rows = [
        (
            r["stem"],
            r["status"],
            f"{r['bad_max']:.3f}" if r["bad_max"] is not None else "-",
            f"{r['good_max']:.3f}" if r["good_max"] is not None else "-",
            r["top_bad_category"] or "-",
            (r["error"] or "")[:60],
        )
        for r in results
    ]
    print(f"\n=== Classifier Eval Report ({elapsed:.1f}s) ===\n")
    print_table(("classifier", "status", "bad_max", "good_max", "top_bad_category", "error"), rows)

    counts = {}
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    summary = ", ".join(f"{v} {k}" for k, v in sorted(counts.items()))
    print(f"\n{len(results)} classifier(s) evaluated: {summary} "
          f"(bad-threshold={args.bad_threshold}, good-threshold={args.good_threshold})")

    if args.json_path:
        with open(args.json_path, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2)
        print(f"Full results written to {args.json_path}")

    return 0 if counts.get("fail", 0) == 0 and counts.get("error", 0) == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
