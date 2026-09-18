# Spec 005: Classifier Catalog

Status: Implemented (reverse-engineered from `classifiers/*.py` and `router.py`)

## Overview

This spec describes the *shape* of the classifier catalog -- how many
classifiers exist, how they're split between OWASP-cheat-sheet-sourced and
CWE-sourced, and where the authoritative list lives -- rather than
duplicating all 131 entries inline (the authoritative list is the
`classifiers/` directory listing plus `router.py`'s `ROUTES` dict; this
spec documents their structure and how they got there).

## Inventory

- **131 classifier modules total** under `classifiers/`.
- **122 OWASP-sourced** -- one module per page in the
  [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/), covering
  the full published series at the time they were authored.
- **9 CWE-sourced** -- added later to close concrete gaps identified by
  cross-referencing the 2025 [CWE Top 25](https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html)
  and the [CWE-699 Software Development View](https://cwe.mitre.org/data/definitions/699.html)
  (~400 entries) against the actual `CATEGORIES` content of all 122
  existing classifiers (not just filenames), for weakness families with
  zero or only incidental coverage:

  | Module | Primary CWE(s) | Gap it closes |
  |---|---|---|
  | `path_traversal_classifier.py` | CWE-22/23/36/41/59/66/73 | 2025 Top 25 rank #6; previously only covered narrowly inside `file_upload_classifier.py` |
  | `memory_safety_classifier.py` | CWE-787/125/120/121/122/416/415/476/190/191/134 | 7-9 of the 2025 Top 25 entries combined; `c_based_toolchain_hardening_classifier.py` only covered build/compiler-flag mitigations, not the unsafe code patterns |
  | `race_condition_classifier.py` | CWE-362/364/366/367/412-414/609/663/764/765/820-833/1265/1322 | General-purpose TOCTOU/deadlock/lock-mismanagement; previously only narrow coverage inside `nodejs_security_classifier.py` and business-logic classifiers |
  | `server_side_template_injection_classifier.py` | CWE-1336, CWE-917 | SSTI and Expression-Language injection; distinct from `injection_prevention_classifier.py`'s SQL/LDAP/XPath/eval categories |
  | `hardcoded_credentials_classifier.py` | CWE-798/259/321/1392 | Promotes a single category previously buried inside `secrets_management_classifier.py` into a dedicated "secrets scanner"-style classifier |
  | `http_request_smuggling_classifier.py` | CWE-444 | CL/TE desync attacks; distinct from `http_headers_classifier.py` (response headers) |
  | `unsafe_reflection_classifier.py` | CWE-470/843/914/915 | Untrusted-input-driven reflection/dynamic dispatch; distinct from `deserialization_classifier.py` (byte-stream deserialization) |
  | `csv_formula_injection_classifier.py` | CWE-1236 | CSV/spreadsheet formula injection on export; previously uncovered |
  | `untrusted_search_path_classifier.py` | CWE-426/427/428 | DLL hijacking / unquoted service paths / untrusted `PATH` entries; previously uncovered |

## Requirements

1. Every catalog entry MUST be identifiable as OWASP- or CWE-sourced purely
   from its `CHEATSHEET_URL` domain (`cheatsheetseries.owasp.org` vs.
   `cwe.mitre.org`) -- there is intentionally no separate `source_kind`
   field (see spec 002 requirement 3 and the design decision below).
2. A CWE-sourced module's `CHEATSHEET_NAME` MUST include its governing
   `CWE-XXXX` ID(s) in the display name so the source is visually
   identifiable in reports without following the URL.
3. Adding a classifier to the catalog (regardless of source) MUST follow
   the same two-step process: (a) add the file under `classifiers/`
   satisfying spec 002; (b) add one entry to `router.py`'s `ROUTES` (spec
   003, requirement 2). No other file requires changes.
4. Some category overlap between an existing OWASP-sourced classifier and
   a newer CWE-sourced classifier covering related ground (e.g.
   `hardcoded_credentials_classifier` vs. `secrets_management_classifier`'s
   `hardcoded_plaintext_secret` category) is expected and MUST NOT be
   "fixed" by removing categories from either -- see spec 001 design
   principle 3 (independent, overlapping classifiers are a feature).
5. Granularity MUST be one file per weakness *family*, not one file per
   individual CWE ID or per individual named risk -- e.g.
   `memory_safety_classifier.py` bundles ~11 related CWE IDs as distinct
   `CATEGORIES` entries in one file, the same way an OWASP cheat sheet
   file already bundles many sub-risks under one page/topic.

## Design Decision: field-naming reuse

CWE-sourced modules deliberately reuse the `CHEATSHEET_NAME` /
`CHEATSHEET_URL` field names verbatim rather than introducing generic
`SOURCE_NAME` / `SOURCE_URL` fields. This was a conscious choice (confirmed
with the project owner) to keep `run_all_classifiers.py`'s `REQUIRED_ATTRS`,
`router.py`'s registry shape, and `classifiers/_TEMPLATE.py.txt` completely
unchanged -- integrating 9 new classifiers required zero interface changes,
only new files plus new `ROUTES` entries.

## Explicit Exclusions

- CWE-699 entries that are pure code-quality/maintainability issues
  (identifier naming conventions, whitespace/formatting, McCabe cyclomatic
  complexity, class-inheritance-depth metrics, the "7PK Poor Code Quality"
  family, etc.) were deliberately excluded from the catalog -- these are
  lint-tool territory, not security-scanner territory.
- CWE entries that were already fully covered by an existing OWASP-sourced
  classifier's actual category content were not duplicated as new files
  (verified by dumping `CATEGORIES.keys()` per candidate classifier, not
  just checking filenames) -- confirmed already-covered topics include:
  forced browsing, log injection / sensitive data in logs, password
  storage hygiene, predictable session/randomness, XML entity expansion,
  and business-logic check-then-act races.

## Open Questions

- Whether future CWE sweeps (e.g. hardware CWEs, additional CWE-699
  entries not yet triaged) warrant further additions is left open; the
  9-classifier set in this spec reflects two rounds of gap analysis
  approved by the project owner, not an exhaustive one-time pass over all
  ~1,000 CWE entries.
