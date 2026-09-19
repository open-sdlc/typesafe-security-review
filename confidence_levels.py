"""Global confidence-level configuration (spec 007).

Every finding produced by `run_all_classifiers.py` and `repo_scan.py` has a
`confidence` score in `[0, 1]`. This module maps that raw score onto three
human-facing levels so callers can triage without re-deriving thresholds in
every entry point:

    Failed  -- confidence >  FAILED_THRESHOLD   (default 0.65)
    Review  -- REVIEW_THRESHOLD <= confidence <= FAILED_THRESHOLD (default 0.40-0.65)
    Pass    -- confidence <  REVIEW_THRESHOLD   (default 0.40)

Both thresholds are configurable, in increasing order of precedence:
    1. Built-in defaults (DEFAULT_FAILED_THRESHOLD / DEFAULT_REVIEW_THRESHOLD)
    2. Environment variables (TSR_FAILED_THRESHOLD / TSR_REVIEW_THRESHOLD)
    3. An explicit argument passed by the caller (e.g. a CLI flag)

Usage:
    from confidence_levels import confidence_level, get_thresholds

    level = confidence_level(finding["confidence"])          # "Pass"/"Review"/"Failed"
    failed_threshold, review_threshold = get_thresholds()
"""

import os

DEFAULT_FAILED_THRESHOLD = 0.65
DEFAULT_REVIEW_THRESHOLD = 0.40

FAILED_THRESHOLD_ENV = "TSR_FAILED_THRESHOLD"
REVIEW_THRESHOLD_ENV = "TSR_REVIEW_THRESHOLD"

LEVEL_FAILED = "Failed"
LEVEL_REVIEW = "Review"
LEVEL_PASS = "Pass"


def _env_float(name: str, default: float) -> float:
    """Read a float from an environment variable, falling back to `default`
    on any missing/invalid value (never raises -- config is best-effort)."""
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def get_thresholds(failed_threshold: float = None, review_threshold: float = None) -> tuple:
    """Resolve the (failed_threshold, review_threshold) pair to use, honoring
    explicit arguments first, then environment variables, then defaults."""
    if failed_threshold is None:
        failed_threshold = _env_float(FAILED_THRESHOLD_ENV, DEFAULT_FAILED_THRESHOLD)
    if review_threshold is None:
        review_threshold = _env_float(REVIEW_THRESHOLD_ENV, DEFAULT_REVIEW_THRESHOLD)
    return failed_threshold, review_threshold


def confidence_level(confidence: float, failed_threshold: float = None, review_threshold: float = None) -> str:
    """Map a raw confidence score to "Failed" / "Review" / "Pass".

    Boundaries are inclusive toward "Review": exactly `review_threshold` is
    "Review" (not "Pass"), and exactly `failed_threshold` is "Review" (not
    "Failed" -- "Failed" requires strictly greater than the threshold), so
    the three bands partition `[0, 1]` with no gaps or overlaps.
    """
    failed_threshold, review_threshold = get_thresholds(failed_threshold, review_threshold)
    if confidence is None:
        return LEVEL_PASS
    if confidence > failed_threshold:
        return LEVEL_FAILED
    if confidence >= review_threshold:
        return LEVEL_REVIEW
    return LEVEL_PASS


def add_threshold_args(parser) -> None:
    """Add the shared --failed-threshold/--review-threshold CLI flags to an
    argparse parser. Kept here so every entry point defines them identically."""
    failed_default, review_default = get_thresholds()
    parser.add_argument(
        "--failed-threshold",
        type=float,
        default=None,
        help=f"Confidence above which a finding is level 'Failed' (default: {failed_default}, "
             f"or ${FAILED_THRESHOLD_ENV})",
    )
    parser.add_argument(
        "--review-threshold",
        type=float,
        default=None,
        help=f"Confidence at/above which (and at/below --failed-threshold) a finding is level "
             f"'Review' (default: {review_default}, or ${REVIEW_THRESHOLD_ENV})",
    )
