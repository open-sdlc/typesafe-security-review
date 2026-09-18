"""Content Security Policy Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Content Security Policy Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python content_security_policy_classifier.py "some text to classify"
    python content_security_policy_classifier.py --file path/to/content.txt
    echo "some text" | python content_security_policy_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Content Security Policy Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "unsafe_inline_or_unsafe_eval_usage": (
        "A Content-Security-Policy allows 'unsafe-inline' script/style "
        "execution or 'unsafe-eval', which permits inline scripts or "
        "text-to-JavaScript functions like eval() to run and largely defeats "
        "the XSS protection CSP is meant to provide."
    ),
    "missing_strict_csp_mechanism": (
        "The policy does not use a nonce-based or hash-based Strict CSP "
        "approach (with strict-dynamic), relying instead on a legacy, purely "
        "allowlist/domain-based policy that is easier to bypass."
    ),
    "csp_delivered_only_via_meta_tag": (
        "CSP is delivered only through an HTML <meta http-equiv> tag instead "
        "of an HTTP response header, which cannot enforce frame-ancestors, "
        "sandboxing, or a violation-reporting endpoint."
    ),
    "report_only_mode_without_enforcement": (
        "The site relies on Content-Security-Policy-Report-Only, which only "
        "logs violations and does not actually block disallowed content, "
        "without an accompanying enforced Content-Security-Policy header."
    ),
    "missing_frame_ancestors_directive": (
        "The policy omits the frame-ancestors directive (or relies solely on "
        "the obsolete X-Frame-Options header), leaving the page without CSP "
        "based clickjacking/framing protection."
    ),
    "missing_object_or_plugin_restriction": (
        "The policy does not restrict the object-src (or plugin-types) "
        "directive, leaving the page able to load legacy Flash/Java/other "
        "plugin content that could be used maliciously."
    ),
    "overly_permissive_allowlist": (
        "The policy uses a broad, granular allowlist (e.g. wildcard domains "
        "or many third-party script sources) that is too permissive and "
        "likely to be bypassable, rather than a minimal Strict CSP."
    ),
    "obsolete_legacy_csp_header_usage": (
        "The deprecated, non-standard X-Content-Security-Policy or "
        "X-WebKit-CSP headers are used instead of the standard "
        "Content-Security-Policy header."
    ),
    "hash_nonce_implementation_mistake": (
        "A nonce or hash based CSP is implemented incorrectly, such as a "
        "middleware blindly adding the same nonce to attacker-injected script "
        "tags, or a script hash breaking due to trivial content changes like "
        "whitespace/formatting."
    ),
    "missing_reporting_endpoint_configuration": (
        "The policy does not configure a violation reporting mechanism "
        "(report-to/report-uri), losing visibility into blocked resources or "
        "attempted policy violations in production."
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
