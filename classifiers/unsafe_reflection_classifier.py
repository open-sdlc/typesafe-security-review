"""Unsafe Reflection (CWE-470) classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the CWE (Common
Weakness Enumeration) family of entries covering unsafe use of reflection
and dynamic code loading driven by untrusted input, anchored on:
https://cwe.mitre.org/data/definitions/470.html

Related entries used to ground individual categories include CWE-843 (Access
of Resource Using Incompatible Type / "Type Confusion"), CWE-914 (Improper
Control of Dynamically-Identified Variables), and CWE-915 (Improperly
Controlled Modification of Dynamically-Determined Object Attributes). This
classifier focuses specifically on reflection/dynamic-typing mechanisms; it
is distinct from deserialization_classifier.py (which covers deserializing
untrusted byte streams/objects) and from mass_assignment_classifier.py
(which covers general request-parameter-to-model binding, not reflection).

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python unsafe_reflection_classifier.py "some text to classify"
    python unsafe_reflection_classifier.py --file path/to/content.txt
    echo "some text" | python unsafe_reflection_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Unsafe Reflection (CWE-470)"
CHEATSHEET_URL = "https://cwe.mitre.org/data/definitions/470.html"

# Sub-categories drawn from CWE-470 and closely related reflection/dynamic-
# typing entries (CWE-843, CWE-914, CWE-915). Each description is written so
# Jev (the TypeSafe model) can distinguish it from neighboring categories --
# be specific about what does and does not count.
CATEGORIES = {
    "user_controlled_class_instantiation": (
        "A class or type name taken from untrusted input (a request "
        "parameter, config value, or file) is passed to a reflective "
        "instantiation API to create an object, such as Java's "
        "Class.forName(userInput).newInstance(), a PHP `new $className()` "
        "with an attacker-influenced string, or Python `getattr(module, "
        "name)()` / `importlib.import_module(name)` on a user-supplied "
        "module or class name."
    ),
    "dynamic_method_invocation_from_untrusted_input": (
        "The name of a method or function to invoke is taken from "
        "untrusted input and dispatched dynamically (e.g. Java reflection's "
        "Method.invoke, a dynamic dispatch table keyed by a request "
        "parameter, or calling `getattr(obj, user_supplied_method_name)()`), "
        "letting an attacker choose which code path executes."
    ),
    "reflective_attribute_binding_from_untrusted_keys": (
        "Object fields or properties are set by name using reflection APIs "
        "(e.g. Java Field.set, C# PropertyInfo.SetValue, Python "
        "`setattr(obj, key, value)`) where the field name/key itself comes "
        "from untrusted input, allowing an attacker to write to arbitrary "
        "or unintended object attributes via the reflection mechanism "
        "itself, as opposed to ordinary framework-level mass assignment."
    ),
    "type_confusion_from_unsafe_cast_after_reflection": (
        "A value obtained via a reflective lookup (e.g. Class.forName, "
        "generic deserialization into an Object, or a dynamically-typed "
        "container) is cast or coerced to an incompatible type without a "
        "runtime type check, leading to type confusion (CWE-843) where the "
        "resource is accessed as a type it is not."
    ),
    "untrusted_plugin_or_classloader_selection": (
        "Untrusted input determines which plugin, handler, extension, or "
        "classloader is loaded at runtime (e.g. a plugin name from a "
        "request or config file used to pick a class to load and execute), "
        "letting an attacker cause execution of arbitrary installed or "
        "planted code."
    ),
    "reflective_prototype_or_metaclass_manipulation": (
        "Reflection or dynamic attribute access is used to reach and "
        "reassign an object's prototype or metaclass (e.g. JavaScript "
        "`__proto__`/`constructor.prototype` reached through a dynamic "
        "property accessor, or Python `__class__` reassignment via "
        "`setattr`), enabling prototype pollution or object-model tampering."
    ),
    "reflection_based_access_modifier_bypass": (
        "Reflection is used to call a private, internal, or otherwise "
        "access-restricted method or field based on a name or path supplied "
        "by untrusted input, bypassing the language's normal access-control "
        "boundaries (e.g. Java's setAccessible(true) driven by user input)."
    ),
    "improper_control_of_dynamically_identified_variables": (
        "A variable, array index, or object key to read or write is chosen "
        "dynamically based on untrusted input without validating it against "
        "an allow-list, letting an attacker reference variables or fields "
        "the developer did not intend to expose (CWE-914)."
    ),
    "reflection_driven_gadget_chain_triggering": (
        "Reflection is used as the triggering step of an exploit gadget "
        "chain -- invoking a chain of otherwise-benign methods/classes "
        "reachable via reflective calls to ultimately reach a dangerous "
        "sink -- as distinct from the initial deserialization of the byte "
        "stream that constructed the gadget objects."
    ),
    "missing_allowlist_for_reflective_targets": (
        "Reflective instantiation, invocation, or attribute access accepts "
        "any class/method/field name supplied by input with no allow-list "
        "or denylist restricting which classes or members are eligible "
        "targets, relying only on implicit trust in the input source."
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
