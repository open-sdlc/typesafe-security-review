"""Prototype Pollution Prevention Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Prototype Pollution Prevention Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python prototype_pollution_prevention_classifier.py "some text to classify"
    python prototype_pollution_prevention_classifier.py --file path/to/content.txt
    echo "some text" | python prototype_pollution_prevention_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Prototype Pollution Prevention Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "proto_property_injection": (
        "Attacker-controlled input contains a literal '__proto__' key (e.g. in a "
        "JSON body or query string) intended to reach into and modify "
        "Object.prototype when merged into an application object."
    ),
    "constructor_prototype_injection": (
        "Attacker-controlled input targets 'constructor.prototype' instead of "
        "'__proto__' to pollute the prototype chain, a bypass technique used when "
        "'__proto__' itself is blocked or filtered."
    ),
    "unsafe_recursive_merge": (
        "The code merges, extends, clones, or deep-copies user-supplied objects "
        "(e.g. a generic merge/extend/defaultsDeep utility) without checking keys "
        "against dangerous property names before assignment."
    ),
    "object_literal_over_set_map": (
        "Plain object literals ('{}') are used as key/value stores for attacker- "
        "influenced data instead of the safer 'new Set()' or 'new Map()' APIs "
        "that do not inherit from Object.prototype."
    ),
    "missing_null_prototype": (
        "Objects that will hold untrusted keys are created as ordinary object "
        "literals or with 'new Object()' rather than via 'Object.create(null)', "
        "so they still inherit from Object.prototype."
    ),
    "unfrozen_builtin_prototypes": (
        "Object.freeze() or Object.seal() are not applied to built-in prototypes "
        "(Object.prototype, Array.prototype, etc.), leaving them mutable at "
        "runtime."
    ),
    "downstream_impact_escalation": (
        "The scenario describes a downstream consequence of a polluted prototype: "
        "unauthorized data access, privilege escalation, denial of service, or "
        "remote code execution stemming from a manipulated JavaScript object."
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
