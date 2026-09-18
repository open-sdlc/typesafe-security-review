"""File Upload Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"File Upload Cheat Sheet":
https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python file_upload_classifier.py "some text to classify"
    python file_upload_classifier.py --file path/to/content.txt
    echo "some text" | python file_upload_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "File Upload Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "File_Upload_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's "File Upload Threats" and "File
# Upload Protection" sections (extension/content-type/signature validation,
# filename safety, content validation, storage location, permissions, limits).
CATEGORIES = {
    "malicious_file_content": (
        "An uploaded file is crafted to exploit a file parser/processing "
        "module vulnerability (e.g. ImageTragick, XXE), is a zip/XML bomb, "
        "overwrites an existing file, or contains client-side active content "
        "such as XSS payloads."
    ),
    "extension_validation_bypass": (
        "A file extension check is bypassed using tricks like a double "
        "extension (.jpg.php), a null byte (.php%00.jpg), or a weak/untested "
        "regex, or the app blocks extensions instead of using an allowlist."
    ),
    "content_type_spoofing": (
        "The application trusts the client-supplied Content-Type/MIME header "
        "for an uploaded file as a security control, even though it is "
        "trivial for an attacker to spoof."
    ),
    "unsafe_filename_handling": (
        "An uploaded file's original filename is used directly for storage "
        "without generating a random name, without limiting length, or "
        "without restricting characters, risking path traversal or special/"
        "reserved filenames."
    ),
    "public_file_retrieval_risks": (
        "Publicly retrievable uploaded files disclose other users' data, "
        "enable a DoS via mass small requests yielding large responses, or "
        "host illegal/offensive/copyrighted content."
    ),
    "insecure_storage_location": (
        "Uploaded files are stored inside the webroot or on the same server "
        "as the application rather than on a separate host, outside the "
        "webroot, or behind a handler that maps an opaque ID to the file."
    ),
    "missing_malware_or_content_disarm_scanning": (
        "Uploaded files are not scanned by antivirus/sandbox tooling, and "
        "applicable document types (PDF, DOCX, etc.) are not run through "
        "Content Disarm & Reconstruct (CDR) before being trusted."
    ),
    "missing_upload_authorization": (
        "The file upload endpoint does not verify that the requester is an "
        "authenticated, authorized user before accepting or serving an "
        "uploaded file."
    ),
    "missing_size_and_rate_limits": (
        "The upload service has no file size limit (including after "
        "decompression) or no request-rate limit on uploads/downloads, "
        "allowing storage exhaustion or DoS."
    ),
    "insecure_filesystem_permissions": (
        "Uploaded files are stored with overly permissive filesystem "
        "permissions, or an executable upload is allowed to run without "
        "first being scanned for malicious macros or scripts."
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
