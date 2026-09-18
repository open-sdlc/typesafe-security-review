"""Django Security Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Django Security Cheat Sheet":
https://cheatsheetseries.owasp.org/cheatsheets/Django_Security_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python django_security_classifier.py "some text to classify"
    python django_security_classifier.py --file path/to/content.txt
    echo "some text" | python django_security_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Django Security Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Django_Security_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's sections on authentication, key
# management, cookies, CSRF, XSS, HTTPS, and admin panel hardening.
CATEGORIES = {
    "debug_mode_exposure": (
        "The Django application runs with DEBUG = True (or "
        "DEBUG_PROPAGATE_EXCEPTIONS = True) in a production environment, "
        "risking exposure of stack traces, settings, and internals to users."
    ),
    "weak_secret_key_management": (
        "The SECRET_KEY is hardcoded in settings.py or another file, is "
        "shorter than 50 characters or low entropy, was not generated with a "
        "strong random generator, or is never rotated even after exposure."
    ),
    "missing_authentication_controls": (
        "Views are not protected with django.contrib.auth / @login_required, "
        "or AUTH_PASSWORD_VALIDATORS is weak/absent, allowing short, common, "
        "or easily guessable passwords."
    ),
    "brute_force_protection_gaps": (
        "Login, registration, or password endpoints lack throttling/rate "
        "limiting (e.g. via django_ratelimit or django-axes), leaving them "
        "open to brute-force credential guessing."
    ),
    "insecure_cookie_configuration": (
        "SESSION_COOKIE_SECURE or CSRF_COOKIE_SECURE is not set to True, or a "
        "custom cookie set via HttpResponse.set_cookie() omits secure=True, "
        "allowing cookies to be sent over plain HTTP."
    ),
    "csrf_protection_gaps": (
        "django.middleware.csrf.CsrfViewMiddleware is missing, a form omits "
        "the {% csrf_token %} template tag, or an AJAX call fails to attach "
        "the CSRF token before making a state-changing request."
    ),
    "xss_via_unsafe_template_rendering": (
        "Code uses the `safe` filter or mark_safe() to disable Django's "
        "automatic HTML escaping on data that is not fully trusted, or "
        "user-controlled input is inserted into a template/JavaScript context "
        "without the json_script filter."
    ),
    "missing_https_enforcement": (
        "SECURE_SSL_REDIRECT is not enabled, SECURE_PROXY_SSL_HEADER is "
        "missing behind a proxy/load balancer, or SECURE_HSTS_SECONDS is "
        "unset, allowing the site to be reached over plain HTTP."
    ),
    "clickjacking_protection_gaps": (
        "django.middleware.clickjacking.XFrameOptionsMiddleware is missing or "
        "X_FRAME_OPTIONS is not set to DENY/SAMEORIGIN, allowing the site to "
        "be embedded in a hostile frame for clickjacking."
    ),
    "admin_panel_and_deploy_check_exposure": (
        "The Django admin panel is left at the default /admin/ URL, or the "
        "`check --deploy` warnings (e.g. missing SECURE_HSTS_SECONDS, "
        "ALLOWED_HOSTS empty, DEBUG left True) are not addressed before "
        "deployment."
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
