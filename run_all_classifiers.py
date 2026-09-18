"""Coordinator for the OWASP Cheat Sheet Series classifiers.

Loads every `*_classifier.py` module under `classifiers/` (one module per
OWASP Cheat Sheet, each built on the TypeSafe System One API -- see
https://cheatsheetseries.owasp.org/), sends the same input text to all of
them in parallel, and produces a single consolidated report listing every
finding (cheat sheet + sub-category) whose confidence score is greater
than 0.

Each classifier module is expected to expose the standard interface (see
classifiers/_TEMPLATE.py.txt):
    CHEATSHEET_NAME: str
    CHEATSHEET_URL: str
    CATEGORIES: dict[str, str]              # category -> description
    classify_with_nouls(text: str) -> dict[str, float]   # category -> probability

Usage:
    python run_all_classifiers.py "some text to classify"
    python run_all_classifiers.py --file path/to/content.txt
    echo "some text" | python run_all_classifiers.py
    python run_all_classifiers.py "..." --workers 24 --top 25
"""

import argparse
import importlib.util
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

CLASSIFIERS_DIR = Path(__file__).resolve().parent / "classifiers"
REQUIRED_ATTRS = ("CHEATSHEET_NAME", "CHEATSHEET_URL", "CATEGORIES", "classify_with_nouls")


def discover_classifier_paths():
    """Return every classifiers/*_classifier.py file, sorted for determinism."""
    return sorted(CLASSIFIERS_DIR.glob("*_classifier.py"))


def load_classifier_module(path: Path):
    """Import a single classifier file as its own module (no package/__init__
    required) and verify it implements the standard interface."""
    module_name = f"owasp_classifiers.{path.stem}"
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    missing = [attr for attr in REQUIRED_ATTRS if not hasattr(module, attr)]
    if missing:
        raise AttributeError(f"{path.name} is missing required attribute(s): {', '.join(missing)}")
    return module


def load_all_classifiers(paths):
    """Import every classifier module, collecting per-file load errors instead
    of aborting the whole run."""
    modules = []
    load_errors = []
    for path in paths:
        try:
            modules.append(load_classifier_module(path))
        except Exception as exc:  # noqa: BLE001 - report and continue
            load_errors.append((path.name, str(exc)))
    return modules, load_errors


def classify_one(module, text: str):
    """Run a single module's classify_with_nouls(text). Returns
    (module, scores_dict) or raises on failure (caught by the caller)."""
    scores = module.classify_with_nouls(text)
    return module, scores


def run_all(modules, text: str, workers: int, quiet: bool = False):
    """Send `text` to every module in parallel. Returns (findings, run_errors).

    findings: list of dicts with keys cheatsheet, url, category, description,
              confidence -- one per (module, category) pair scoring > 0.
    run_errors: list of (cheatsheet_name, error_message) for modules whose
                classify_with_nouls() call raised (e.g. missing API key,
                network failure) so the rest of the run can still complete.
    """
    findings = []
    run_errors = []
    total = len(modules)
    done = 0

    with ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
        future_to_module = {executor.submit(classify_one, m, text): m for m in modules}
        for future in as_completed(future_to_module):
            module = future_to_module[future]
            done += 1
            if not quiet:
                print(
                    f"\r[{done}/{total}] classified: {module.CHEATSHEET_NAME[:60]:<60}",
                    end="",
                    file=sys.stderr,
                    flush=True,
                )
            try:
                _, scores = future.result()
            except Exception as exc:  # noqa: BLE001 - keep going on per-module failure
                run_errors.append((module.CHEATSHEET_NAME, str(exc)))
                continue

            for category, confidence in scores.items():
                if confidence is not None and confidence > 0:
                    findings.append(
                        {
                            "cheatsheet": module.CHEATSHEET_NAME,
                            "url": module.CHEATSHEET_URL,
                            "category": category,
                            "description": module.CATEGORIES.get(category, ""),
                            "confidence": confidence,
                        }
                    )
    if not quiet:
        print(file=sys.stderr)  # newline after progress line
    return findings, run_errors


def print_table(headers, rows) -> None:
    """Print `rows` (each a tuple of column values) as a simple aligned table."""
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
    parser.add_argument("text", nargs="?", help="Text to classify")
    parser.add_argument("--file", help="Read text to classify from a file")
    parser.add_argument("--workers", type=int, default=16, help="Parallel worker threads (default: 16)")
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.0,
        help="Minimum confidence to include in the report (default: 0.0, i.e. > 0)",
    )
    parser.add_argument("--top", type=int, default=None, help="Only show the top N findings")
    parser.add_argument("--quiet", action="store_true", help="Suppress the live progress line")
    args = parser.parse_args()

    if args.file:
        with open(args.file, "r", encoding="utf-8") as fh:
            text = fh.read()
    elif args.text:
        text = args.text
    else:
        text = sys.stdin.read()

    if not text.strip():
        parser.error("no input text provided")

    paths = discover_classifier_paths()
    if not paths:
        print(f"No classifier modules found under {CLASSIFIERS_DIR}", file=sys.stderr)
        return 1

    modules, load_errors = load_all_classifiers(paths)
    if load_errors:
        print(f"WARNING: {len(load_errors)} classifier module(s) failed to load:", file=sys.stderr)
        for name, err in load_errors:
            print(f"  - {name}: {err}", file=sys.stderr)

    print(f"Loaded {len(modules)} cheat sheet classifiers. Classifying input ({len(text)} chars)...", file=sys.stderr)

    start = time.time()
    findings, run_errors = run_all(modules, text, workers=args.workers, quiet=args.quiet)
    elapsed = time.time() - start

    findings = [f for f in findings if f["confidence"] > args.threshold]
    findings.sort(key=lambda f: -f["confidence"])
    if args.top:
        findings = findings[: args.top]

    print(f"\n=== OWASP Cheat Sheet Series -- Findings Report ({elapsed:.1f}s) ===\n")

    rows = [
        (
            i + 1,
            f["cheatsheet"],
            f["category"],
            f"{f['confidence']:.3f}",
        )
        for i, f in enumerate(findings)
    ]
    print_table(("#", "cheat_sheet", "category", "confidence"), rows)

    print(f"\n{len(findings)} finding(s) with confidence > {args.threshold} "
          f"out of {len(modules)} cheat sheets checked.")

    if run_errors:
        print(f"\n{len(run_errors)} classifier(s) failed during classification:", file=sys.stderr)
        for name, err in run_errors:
            print(f"  - {name}: {err}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
