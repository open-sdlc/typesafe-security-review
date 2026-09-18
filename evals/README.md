# Classifier Evals

A small eval harness that checks each classifier in `classifiers/` actually
discriminates: does it score clearly high on an obvious positive example and
stay quiet on a safe, structurally similar negative example?

This is a coarse sanity check, not a substitute for reviewing a classifier's
`CATEGORIES` text by hand. See
[`specs/002-classifier-module/spec.md`](../specs/002-classifier-module/spec.md)
for what makes a good category description.

## How it works

For every `classifiers/<stem>.py`, the harness looks for a matching fixture
pair:

```
evals/fixtures/<stem>/bad.txt    # should clearly exhibit >=1 of the classifier's CATEGORIES
evals/fixtures/<stem>/good.txt   # a safe counterpart that should not
```

For each pair, it calls `classify_with_nouls()` (imported from the
classifier module) on both files and checks:

```
bad_max_confidence  >= --bad-threshold   (default 0.5)
good_max_confidence <= --good-threshold  (default 0.3)
```

A classifier's eval **passes** only if both hold. Classifiers with no
fixture pair are reported as `missing_fixtures` rather than failed, so
partial fixture coverage never breaks the run.

## Running

Requires `TYPESAFE_API_KEY` to be set, since it makes real classification
calls (same as `run_all_classifiers.py`).

```bash
# Run every classifier that has fixtures
python evals/run_evals.py

# Only classifiers matching a glob (repeatable)
python evals/run_evals.py --filter "sql*" --filter "*xss*"

# Check fixture coverage only, no API calls (no API key needed)
python evals/run_evals.py --dry-run

# Tune thresholds, parallelism, and write full results to JSON
python evals/run_evals.py --bad-threshold 0.6 --good-threshold 0.2 \
    --workers 8 --json evals/results.json
```

Output is a per-classifier table (`pass` / `fail` / `error` /
`missing_fixtures`, plus `bad_max`, `good_max`, and the top-firing category
on `bad.txt`) followed by a summary line.

## Adding fixtures for a classifier

1. Read the classifier's `CATEGORIES` dict in `classifiers/<stem>.py` to see
   what it actually looks for.
2. Create `evals/fixtures/<stem>/bad.txt`: a concrete, realistic snippet
   (code, config, headers, or a process/design-doc excerpt, matching the
   classifier's domain) that unambiguously exhibits one or more categories.
3. Create `evals/fixtures/<stem>/good.txt`: a safe, structurally similar
   counterpart covering the same scenario but following the secure/correct
   practice, so the contrast is a fair, targeted test.
4. Keep both files free of meta-commentary (no `# BAD:` / `# VULNERABLE`
   comments) — they should look like genuine content, not annotated
   teaching examples. Roughly 10-40 lines each is typical.
5. Verify with `python evals/run_evals.py --dry-run --filter "<stem>"`
   (fixture presence only) and, once you have an API key,
   `python evals/run_evals.py --filter "<stem>"` (real scoring).

## Notes

- Real confidence-score behavior depends on the live TypeSafe API; the
  default 0.5 / 0.3 thresholds are a starting point and may need tuning per
  classifier once you have real API access to observe actual score
  distributions.
- `run_evals.py` never raises on a single classifier's failure — errors
  (missing module attributes, API failures, etc.) are captured per-stem and
  reported as `error` rows so one bad classifier doesn't stop the run.
