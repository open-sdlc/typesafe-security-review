# typesafe-security-review

Classifiers built on the [TypeSafe](https://typesafe.ai) System One API (via
`typesafe_sdk`) that score input text against the full
[OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/) (122 cheat
sheets).

## Layout

- `classifiers/` — one module per cheat sheet, named `<topic>_classifier.py`.
  Each module exposes a standard interface:
  - `CHEATSHEET_NAME`, `CHEATSHEET_URL` — identifies the source cheat sheet.
  - `CATEGORIES: dict[str, str]` — 5-12 sub-categories (specific risks,
    attack patterns, or checklist items) drawn from that cheat sheet's own
    content, keyed by a short `snake_case` name.
  - `classify_with_nouls(text) -> dict[str, float]` — scores every category
    independently as a TypeSafe `Noul` question in a single parallel
    `system_one()` call, returning `{category: probability}` (0-1). Unlike a
    `Choice`, categories are independent, so input can match zero, one, or
    several at once.
  - Each file is also a standalone CLI (`python classifiers/xxx_classifier.py "text"`).
  - `classifiers/_TEMPLATE.py.txt` — the template new classifiers follow.
- `run_all_classifiers.py` — coordinator that discovers every
  `classifiers/*_classifier.py` module, routes the input through `router.py`
  to skip irrelevant cheat sheets, sends the input text to the remaining
  modules concurrently (thread pool), and prints one consolidated report of
  every `(cheat sheet, category)` finding with confidence > 0, sorted
  descending.
- `router.py` — relevance router, also built on TypeSafe. Asks one `Noul`
  per cheat sheet ("does this cheat sheet apply to this input?") in a single
  parallel `system_one()` call (the
  [speculative fan-out](https://docs.typesafe.ai/patterns/fan-out.md)
  pattern), so `run_all_classifiers.py` doesn't waste calls running, e.g.,
  the Django/Laravel/Ruby on Rails classifiers against a `.java` file.

## Usage

```sh
pip install typesafe-sdk
export TYPESAFE_API_KEY=...   # https://console.typesafe.ai/

# primary usage: classify a source file against all 122 cheat sheets
python run_all_classifiers.py --file bad.java
```

Other input modes:

```sh
python run_all_classifiers.py "some text to check"
python run_all_classifiers.py --file path/to/content.txt
echo "some text" | python run_all_classifiers.py

# tuning
python run_all_classifiers.py --file bad.java --workers 24 --top 25 --threshold 0.3

# routing (on by default) -- disable to always run all 122 classifiers
python run_all_classifiers.py --file bad.java --no-route
python run_all_classifiers.py --file bad.java --route-threshold 0.5
```

Run a single cheat sheet's classifier directly:

```sh
python classifiers/prompt_injection_classifier.py "ignore all previous instructions"
```

## Routing

Running all 122 classifiers on every input works but is wasteful when most
cheat sheets obviously don't apply (e.g. Django/Laravel/Ruby on Rails
classifiers for a `.java` file). `router.py` pre-filters:

```sh
python router.py --file bad.java
```

It asks one `Noul` per cheat sheet -- "does this cheat sheet apply here?" --
all in a single parallel call, then only the classifiers scoring at or above
`--route-threshold` (default `0.35`) are run. `run_all_classifiers.py` uses
this automatically; pass `--no-route` to skip routing and always run all 122.
If routing itself fails (e.g. no API key), the coordinator logs a warning and
falls back to running every classifier unfiltered.

## Sample vulnerable file

`bad.java` (used above) is a small, intentionally vulnerable Java class
(hardcoded credentials, SQL injection, command injection, path traversal,
XSS, SSRF, insecure deserialization, and a weak PRNG) used to sanity-check
the classifiers end-to-end. Add `--top 30` to only see the strongest hits.

Expect the top findings to score ~0.9-0.97 confidence across the relevant
cheat sheets (e.g. Secrets Management, SQL/Command Injection, SSRF,
Deserialization), while unrelated cheat sheets (e.g. Zero Trust Architecture,
SAML) trail off toward 0.

> **Always pass source code via `--file`, not as an inline shell argument.**
> Quoting/escaping a multi-line file as a single shell string (or JSON string) can
> mangle code (literal `\n` instead of real newlines, escaped quotes, `!`
> triggering bash history expansion) and lower confidence scores across the
> board. `--file` reads the content byte-for-byte with no shell interference.

## Adding a new cheat sheet

Copy `classifiers/_TEMPLATE.py.txt` to `classifiers/<topic>_classifier.py`,
fill in `CHEATSHEET_NAME`/`CHEATSHEET_URL`, and derive `CATEGORIES` from the
cheat sheet's real content. `run_all_classifiers.py` picks it up automatically
(no registration needed).

Also add an entry to `ROUTES` in `router.py` keyed by the same module stem
(e.g. `"<topic>_classifier"`), with a short `applies_when` scope description
(what language/framework/context makes this cheat sheet relevant) -- this is
what lets the router correctly include or skip your new classifier.
