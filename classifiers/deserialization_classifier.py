"""Deserialization Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Deserialization Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python deserialization_classifier.py "some text to classify"
    python deserialization_classifier.py --file path/to/content.txt
    echo "some text" | python deserialization_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Deserialization Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "untrusted_native_deserialization": (
        "Untrusted, attacker-controllable data is passed to a language's "
        "native deserialization function, such as PHP's unserialize(), "
        "Python's pickle.load(s)/PyYAML yaml.load(), or Java's "
        "ObjectInputStream#readObject(), which can lead to remote code "
        "execution or denial of service."
    ),
    "missing_class_allowlisting": (
        "A deserializer does not restrict which classes/types it is willing "
        "to instantiate (e.g. no override of resolveClass(), no "
        "SerializationBinder allow-list), permitting an attacker to smuggle "
        "in arbitrary or malicious types."
    ),
    "insecure_third_party_library_configuration": (
        "A third-party serialization library is used with an unsafe default "
        "configuration, such as fastjson without safemode, Kryo without class "
        "registration enabled, json-io with @type deserialization, or "
        "SnakeYAML without SafeConstructor."
    ),
    "known_deserialization_gadget_chain": (
        "The input references or exploits a known 'gadget chain' class "
        "usable for deserialization RCE, such as Java's "
        "CommonsCollections/ObjectDataProvider or .NET types like "
        "System.Windows.Data.ObjectDataProvider or BinaryFormatter-based "
        "gadgets."
    ),
    "dotnet_typenamehandling_or_binaryformatter_risk": (
        ".NET code sets JSON.Net's TypeNameHandling to anything other than "
        "None, uses a JavaScriptSerializer with a JavaScriptTypeResolver, or "
        "uses the inherently unsafe BinaryFormatter type to deserialize "
        "untrusted data."
    ),
    "sensitive_field_exposure_via_serialization": (
        "A class exposes sensitive fields (such as internal profit/margin "
        "data) to serialization/deserialization because they were not marked "
        "`transient` (Java) or otherwise excluded, risking data leakage or "
        "attacker-controlled field clobbering."
    ),
    "deserialization_denial_of_service": (
        "A deserialization payload is crafted to consume excessive resources "
        "during processing, such as a 'billion laughs'-style expansion "
        "attack, rather than aiming for direct code execution."
    ),
    "opaque_serialized_payload_indicator": (
        "Captured traffic or a request parameter contains telltale signs of "
        "a serialized object stream, such as a Java `AC ED 00 05` / `rO0` "
        "prefix, a Python pickle `gASV` Base64 prefix, or a trailing dot "
        "consistent with serialized data, suggesting an untrusted "
        "deserialization attack surface."
    ),
    "unsafe_deserialization_of_domain_objects": (
        "An application-defined domain object is forced to implement a "
        "serializable interface without guarding its deserialization path "
        "(e.g. missing a readObject() override that rejects deserialization), "
        "leaving it exploitable when reached from an untrusted stream."
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
