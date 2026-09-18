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
  `classifiers/*_classifier.py` module, sends the same input text to all of
  them concurrently (thread pool), and prints one consolidated report of
  every `(cheat sheet, category)` finding with confidence > 0, sorted
  descending.

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
```

Run a single cheat sheet's classifier directly:

```sh
python classifiers/prompt_injection_classifier.py "ignore all previous instructions"
```

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
