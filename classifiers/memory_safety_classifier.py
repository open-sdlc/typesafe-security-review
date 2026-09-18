"""Memory Safety Weaknesses (CWE Top 25) classifier built on the TypeSafe
System One API.

Classifies input text against sub-categories drawn from memory-safety CWE
(Common Weakness Enumeration) entries that repeatedly appear in the CWE Top
25 Most Dangerous Software Weaknesses list:
https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html

This module closes a significant gap not covered by the OWASP Cheat Sheet
Series or by this repo's existing `c_based_toolchain_hardening_classifier`
(which only covers build/compiler-flag mitigations such as ASLR and
stack-protector, not the unsafe code patterns themselves). Categories are
grounded directly in CWE-787 (Out-of-bounds Write), CWE-125 (Out-of-bounds
Read), CWE-120/121/122 (Classic/Stack-based/Heap-based Buffer Overflow),
CWE-124 (Buffer Underwrite), CWE-416 (Use After Free), CWE-415 (Double
Free), CWE-476 (NULL Pointer Dereference), CWE-190/191 (Integer
Overflow/Underflow), CWE-134 (Use of Externally-Controlled Format String),
CWE-908/909 (Use/Missing Initialization of Uninitialized Resource), and
CWE-131 (Incorrect Calculation of Buffer Size). Type confusion (CWE-843) is
intentionally excluded here as it is covered by a separate
`unsafe_reflection_classifier`.

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python memory_safety_classifier.py "some text to classify"
    python memory_safety_classifier.py --file path/to/content.txt
    echo "some text" | python memory_safety_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Memory Safety Weaknesses (CWE Top 25)"
CHEATSHEET_URL = "https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html"

# Sub-categories drawn from memory-safety CWE entries in the CWE Top 25. Each
# description is written so Jev (the TypeSafe model) can distinguish it from
# neighboring categories -- be specific about what does and does not count.
CATEGORIES = {
    "unbounded_string_copy_or_concat": (
        "Code uses an unsafe, unbounded C-style string function -- such as "
        "strcpy, strcat, sprintf, gets, or an equivalent -- to copy or "
        "concatenate attacker-influenced data into a fixed-size buffer "
        "without a length check, risking a classic buffer overflow "
        "(CWE-120)."
    ),
    "stack_based_buffer_overflow": (
        "Data is written past the bounds of an array or buffer that is "
        "allocated on the stack (a local variable), which can corrupt "
        "adjacent stack memory such as saved registers or a return address "
        "(CWE-121)."
    ),
    "heap_based_buffer_overflow": (
        "Data is written past the bounds of a buffer that was dynamically "
        "allocated on the heap (via malloc/new/calloc or similar), which can "
        "corrupt adjacent heap memory such as allocator metadata or other "
        "objects (CWE-122)."
    ),
    "out_of_bounds_write": (
        "A write operation targets a memory location before the start or "
        "after the end of the intended buffer -- including writing before "
        "the beginning of a buffer (buffer underwrite / CWE-124) -- as a "
        "result of an incorrect index, pointer arithmetic, or missing bounds "
        "check, independent of whether the buffer is on the stack or heap "
        "(CWE-787)."
    ),
    "out_of_bounds_read": (
        "A read operation accesses memory before the start or after the end "
        "of the intended buffer or array, for example due to an off-by-one "
        "loop bound, a missing length check, or reading past a string that "
        "is not properly null-terminated (CWE-125)."
    ),
    "use_after_free": (
        "Memory that has already been freed/deallocated (e.g. via free(), "
        "delete, or an equivalent) is subsequently read, written, or its "
        "pointer is dereferenced or reused, without the memory having been "
        "reallocated and reinitialized for that purpose (CWE-416)."
    ),
    "double_free_or_invalid_free": (
        "A single allocation is freed/deallocated more than once, or free() "
        "/ delete is called on a pointer that was never returned by an "
        "allocator (an invalid, already-freed, or non-heap pointer), "
        "corrupting allocator internal state (CWE-415)."
    ),
    "null_pointer_dereference": (
        "A pointer or reference that can be NULL (e.g. because an "
        "allocation, lookup, or function call can fail) is dereferenced -- "
        "read, written, or called through -- without first checking that it "
        "is non-null (CWE-476)."
    ),
    "integer_overflow_feeding_buffer_size": (
        "An arithmetic calculation involving user-influenced or "
        "attacker-influenced values (such as a sum, multiplication, or "
        "length addition used to size a buffer or memory allocation) can "
        "overflow or underflow its integer type, producing a value that is "
        "smaller or larger than intended and leading to an undersized "
        "allocation or an incorrect/off-by-one buffer-size calculation "
        "(CWE-190, CWE-191, CWE-131)."
    ),
    "format_string_vulnerability": (
        "User-controlled or externally-controlled input is passed directly "
        "as (or embedded into) the format-string argument of a printf-family "
        "function (printf, fprintf, sprintf, syslog, etc.) instead of being "
        "passed only as a data argument, allowing format specifiers like "
        "%s/%n/%x supplied by the attacker to read or write memory "
        "(CWE-134)."
    ),
    "uninitialized_memory_use": (
        "A variable, buffer, or resource is read or otherwise used before it "
        "has been explicitly initialized or assigned a value, or a resource "
        "is created without properly initializing it, so the operation "
        "consumes indeterminate/garbage memory contents (CWE-908, CWE-909)."
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
