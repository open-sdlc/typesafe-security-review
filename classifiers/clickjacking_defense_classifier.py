"""Clickjacking Defense Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Clickjacking Defense Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python clickjacking_defense_classifier.py "some text to classify"
    python clickjacking_defense_classifier.py --file path/to/content.txt
    echo "some text" | python clickjacking_defense_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Clickjacking Defense Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "missing_x_frame_options_header": (
        "A page containing sensitive UI or actions does not send an "
        "X-Frame-Options HTTP response header (DENY or SAMEORIGIN), leaving it "
        "able to be embedded and clickjacked inside an attacker's <iframe>."
    ),
    "missing_csp_frame_ancestors": (
        "A page does not set the Content-Security-Policy frame-ancestors "
        "directive to restrict which origins may embed it in a frame, "
        "the modern replacement for X-Frame-Options."
    ),
    "meta_tag_framing_protection_mistake": (
        "Framing protection (X-Frame-Options or CSP frame-ancestors) is "
        "attempted using an HTML <meta http-equiv> tag rather than as a true "
        "HTTP response header, which browsers ignore for these directives."
    ),
    "obsolete_allow_from_reliance": (
        "The deprecated X-Frame-Options ALLOW-FROM directive is used to permit "
        "framing by a specific origin, which fails open (no protection at all) "
        "in modern browsers that no longer support it."
    ),
    "frame_busting_script_bypass": (
        "A legacy JavaScript 'frame-busting' script (e.g. checking `top != "
        "self` and reassigning location) is relied upon for clickjacking "
        "defense, which can be defeated via double-framing, an "
        "onbeforeunload handler, or no-content flushing tricks."
    ),
    "sandboxed_iframe_js_restriction_bypass": (
        "An attacker restricts JavaScript execution inside a framed page "
        "(e.g. via the iframe sandbox attribute or a parent's designMode) to "
        "prevent that page's own frame-busting code from running."
    ),
    "samesite_cookie_gap_for_framing": (
        "Session cookies are missing a SameSite=strict/lax attribute, so they "
        "are still sent when the site is loaded in a third-party iframe, "
        "enabling authenticated clickjacking attacks that a SameSite cookie "
        "would have blocked."
    ),
    "multi_domain_framing_policy_gap": (
        "The site needs to allow framing from multiple trusted domains but "
        "the chosen mechanism cannot express an allow-list of multiple "
        "origins, forcing an overly permissive or absent framing policy."
    ),
    "missing_defense_in_depth_for_high_value_action": (
        "A page performs a sensitive, side-effecting action (e.g. changing "
        "settings, deleting an account, transferring funds) without any "
        "layered clickjacking protections such as X-Frame-Options, CSP "
        "frame-ancestors, or a confirmatory window.confirm() dialog."
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
