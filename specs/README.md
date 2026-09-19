# Specs

This directory documents `typesafe-security-review` as a set of individual
specs, one per component/feature, each in its own numbered folder as
`spec.md`. Specs 001-005 are **reverse-engineered** from the current,
already-implemented codebase (they describe what the system does today, as
a reference for future changes). Spec 006 was originally a **forward-looking
design** for `repo_scan.py`; that design has since been implemented as
described. Spec 007 is likewise a forward-looking design (confidence-level
bucketing) implemented as described.

| # | Spec | Status | Describes |
|---|------|--------|-----------|
| [001](001-system-overview/spec.md) | System Overview | Implemented | High-level architecture, data flow, design principles |
| [002](002-classifier-module/spec.md) | Classifier Module Interface | Implemented | The contract every `classifiers/*_classifier.py` file must satisfy |
| [003](003-relevance-router/spec.md) | Relevance Router (`router.py`) | Implemented | How relevance pre-filtering selects which classifiers run |
| [004](004-coordinator-cli/spec.md) | Coordinator CLI (`run_all_classifiers.py`) | Implemented | Discovery, routing, parallel execution, report generation |
| [005](005-classifier-catalog/spec.md) | Classifier Catalog | Implemented | Inventory of all 131 classifiers and their sources (OWASP vs. CWE) |
| [006](006-full-repo-scan/spec.md) | Full-Repo Scan with CodeGraph | Implemented (`repo_scan.py`) | Scanning an entire repository by classifying only executable, reachable code, using [CodeGraph](https://github.com/colbymchenry/codegraph) to find it |
| [007](007-confidence-levels/spec.md) | Confidence Levels (`confidence_levels.py`) | Implemented | Shared Pass/Review/Failed bucketing of confidence scores, configurable thresholds, used by both the coordinator and repo scan |

## Conventions

Each `spec.md` follows the same shape: Overview, Goals/Non-Goals,
Requirements (numbered, individually testable), Interfaces/Data Model,
Behavior, CLI/Usage, Error Handling, and Open Questions. Requirements use
RFC-2119-style language (MUST/SHOULD/MAY) so they can be checked against
the implementation.
