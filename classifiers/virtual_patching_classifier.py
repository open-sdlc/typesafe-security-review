"""Virtual Patching Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Virtual Patching Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Virtual_Patching_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python virtual_patching_classifier.py "some text to classify"
    python virtual_patching_classifier.py --file path/to/content.txt
    echo "some text" | python virtual_patching_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Virtual Patching Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Virtual_Patching_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's virtual patching methodology
# phases (preparation, identification, analysis, patch creation) and
# positive/negative security model discussion. Each description is written
# so Jev (the TypeSafe model) can distinguish it from neighboring categories
# -- be specific about what does and does not count.
CATEGORIES = {
    "unpatched_known_vulnerability": (
        "A known vulnerability (e.g. from a public advisory, penetration test, or code "
        "review) has been identified but has not yet received a code-level fix, leaving a "
        "window of exposure."
    ),
    "missing_enforcement_layer": (
        "No security enforcement layer -- such as a Web Application Firewall (WAF), IPS "
        "appliance, or application-layer filter like ModSecurity -- is deployed in front of "
        "the vulnerable application to intercept exploitation attempts."
    ),
    "negative_security_evasion_risk": (
        "A denylist/blocklist-style virtual patch rule (blocking specific known-bad "
        "characters or payload patterns) is used, which can be bypassed via encoding, "
        "alternate syntax, or other evasion techniques it did not anticipate."
    ),
    "overly_permissive_allowlist_rule": (
        "A positive-security (allowlist) virtual patch rule for a parameter is too loose "
        "(e.g. wrong character set, length, or type constraint), allowing malicious input "
        "that should have been rejected to still pass through."
    ),
    "insufficient_audit_logging": (
        "HTTP request/response data needed for incident analysis and patch creation is not "
        "fully captured -- missing full request URI, headers, cookies, or request/response "
        "bodies -- hampering vulnerability analysis and patch creation."
    ),
    "delayed_patch_authorization_process": (
        "Virtual patches must go through the same slow governance/regression-testing "
        "process as normal code patches instead of an expedited, pre-authorized process, "
        "delaying time-to-fix during an active threat."
    ),
    "missing_vulnerability_monitoring_pipeline": (
        "The organization lacks a proactive (assessments, code review) or reactive (vendor "
        "alerts, public disclosure, incident detection) process for becoming aware of new "
        "vulnerabilities affecting its applications."
    ),
    "unvalidated_patch_effectiveness": (
        "A virtual patch is deployed without adequate testing for false positives (blocking "
        "legitimate traffic) or false negatives (missing the attack, including intentionally "
        "evasive attempts)."
    ),
}


def classify_with_nouls(text: str) -> dict:
    """Return dict of category -> probability (0-1), one Noul per category,
    all evaluated in a single parallel call."""
    with TypeSafeClient() as client:
        result = client.system_one(
            state=text,
            questions={
                name: Noul(instructions=f"Does the input relate to or exhibit this issue: {desc}")
                for name, desc in CATEGORIES.items()
            },
        )
    return {name: answer.noul for name, answer in result.nouls.items()}


def print_table(headers, rows) -> None:
    """Print `rows` (each a tuple of column values) as a simple aligned table."""
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
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("text", nargs="?", help="Text to classify")
    parser.add_argument("--file", help="Read text to classify from a file")
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

    scores = classify_with_nouls(text)
    rows = [
        (name, f"{prob:.3f}")
        for name, prob in sorted(scores.items(), key=lambda kv: -kv[1])
    ]
    print_table(("category", "probability"), rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
