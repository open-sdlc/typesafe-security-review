"""XS Leaks Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Cross-site Leaks Cheat Sheet" (XS Leaks Cheat Sheet):
https://cheatsheetseries.owasp.org/cheatsheets/XS_Leaks_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python xs_leaks_classifier.py "some text to classify"
    python xs_leaks_classifier.py --file path/to/content.txt
    echo "some text" | python xs_leaks_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "XS Leaks Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "XS_Leaks_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's catalog of cross-site leak
# (side-channel) attack techniques and their corresponding defenses. Each
# description is written so Jev (the TypeSafe model) can distinguish it from
# neighboring categories.
CATEGORIES = {
    "element_id_focus_leak": (
        "Content describes inferring cross-origin page state by embedding "
        "a target page in an iframe with a URL fragment/hash targeting a "
        "specific element ID, then detecting the resulting focus or blur "
        "event on the attacker's own page."
    ),
    "error_event_status_inference": (
        "Content describes probing whether a cross-origin resource loads "
        "successfully or errors (onload vs onerror) to infer authenticated "
        "user identity or account state, such as enumerating a victim's "
        "user ID by loading a per-user resource in a loop."
    ),
    "postmessage_wildcard_leak": (
        "Content describes a postMessage call made with a wildcard or "
        "unspecified targetOrigin, or a receiving message listener that "
        "fails to check the event's origin, allowing an unintended origin "
        "to receive sensitive message data."
    ),
    "frame_counting_leak": (
        "Content describes counting the number of frames or windows "
        "present in a cross-origin window, e.g. via window.frames.length, "
        "to infer whether a search, listing, or other conditional content "
        "was rendered for the victim."
    ),
    "cache_timing_leak": (
        "Content describes measuring the load time of a cross-origin "
        "resource to infer whether it was served from the browser cache, "
        "revealing whether the victim had previously accessed a "
        "privileged or restricted resource."
    ),
    "missing_samesite_cookie_attribute": (
        "Content discusses a cookie that lacks a properly restrictive "
        "SameSite attribute (Lax or Strict), allowing it to be attached to "
        "cross-site requests and enabling XS-Leaks-style or CSRF-style "
        "attacks."
    ),
    "missing_framing_protection": (
        "Content discusses the absence of framing protections such as a "
        "Content-Security-Policy frame-ancestors directive or the "
        "X-Frame-Options header, allowing a page to be embedded in an "
        "attacker-controlled iframe."
    ),
    "missing_fetch_metadata_isolation": (
        "Content discusses failing to check Fetch Metadata request headers "
        "(such as Sec-Fetch-Site or Sec-Fetch-Dest) on the server to reject "
        "unexpected cross-site or iframe-context requests to sensitive "
        "endpoints."
    ),
    "missing_coop_corp_isolation": (
        "Content discusses the absence of Cross-Origin-Opener-Policy or "
        "Cross-Origin-Resource-Policy response headers, which would "
        "otherwise isolate a page's browsing context group or block "
        "cross-origin loading of its resources."
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
