"""Nextjs Security Cheat Sheet classifier built on the TypeSafe System One
API.

Classifies input text against sub-categories drawn from the OWASP
"Nextjs Security Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Nextjs_Security_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python nextjs_security_classifier.py "some text to classify"
    python nextjs_security_classifier.py --file path/to/content.txt
    echo "some text" | python nextjs_security_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Nextjs Security Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Nextjs_Security_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "middleware_only_authorization": (
        "Proxy or middleware.ts is relied on as the sole authorization layer "
        "for a protected route, instead of re-checking authorization at the "
        "Data Access Layer, Server Action, or Route Handler that actually "
        "reads or writes the data."
    ),
    "unprotected_server_action": (
        "A Server Action is treated as safe because it is only rendered on a "
        "protected page, without independently validating its arguments as "
        "untrusted input or authenticating/authorizing the caller, even "
        "though the action itself is a directly callable POST endpoint."
    ),
    "unprotected_route_handler_or_api_route": (
        "A `route.ts` Route Handler or Pages API Route lacks the "
        "authentication and authorization appropriate to its audience (public "
        "endpoint, authenticated API, or webhook), or is assumed private "
        "merely because only a Server Component calls it."
    ),
    "draft_mode_privilege_bypass": (
        "Draft Mode is enabled via `draftMode().enable()` without validating "
        "a shared secret or caller identity and without confirming the "
        "requested content exists, allowing an unauthenticated caller to "
        "obtain the bypass cookie and view unpublished content."
    ),
    "sensitive_data_serialized_to_client": (
        "A full ORM record, session object, configuration object, or secret "
        "is passed to a Client Component, returned from a Server Action, or "
        "included in `getServerSideProps`/`getStaticProps` props instead of a "
        "narrow, explicitly authorized DTO."
    ),
    "cache_audience_confusion": (
        "A cached response, `use cache` function result, or ISR/ "
        "`getStaticProps` page fails to scope its cache key to the correct "
        "audience (user, tenant, permission version, locale), risking one "
        "user's or tenant's data being served to another."
    ),
    "unvalidated_rewrite_or_redirect_destination": (
        "An external rewrite, redirect, or proxy destination host/scheme/port "
        "in `next.config.*` is derived from an untrusted header, cookie, or "
        "query parameter instead of a fixed allowlist or server-controlled "
        "registry."
    ),
    "unprotected_cache_invalidation": (
        "`revalidatePath`, `revalidateTag`, or `updateTag` can be triggered by "
        "an unauthenticated or unauthorized caller, or the invalidation "
        "target is not derived from an authorized object, allowing abusive or "
        "malicious cache purges."
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
