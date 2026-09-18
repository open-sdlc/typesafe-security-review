"""C-Based Toolchain Hardening Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"C-Based Toolchain Hardening Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/C-Based_Toolchain_Hardening_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python c_based_toolchain_hardening_classifier.py "some text to classify"
    python c_based_toolchain_hardening_classifier.py --file path/to/content.txt
    echo "some text" | python c_based_toolchain_hardening_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "C-Based Toolchain Hardening Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "C-Based_Toolchain_Hardening_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "debug_release_configuration_mixing": (
        "Debug and Release build configurations are not properly separated, e.g. "
        "shipping a build with both DEBUG and NDEBUG defined, or a production "
        "build that retains full assertions, mudflaps, or verbose diagnostics "
        "intended only for a debug session."
    ),
    "missing_compiler_warnings_static_analysis": (
        "The toolchain does not enable strong compiler warnings and static "
        "analysis flags such as -Wall, -Wextra, -Wconversion, or -Wformat=2, "
        "leaving classes of bugs (bad casts, format string issues, unsafe "
        "conversions) undetected at compile time."
    ),
    "missing_stack_protection": (
        "The build does not enable stack-smashing protection such as "
        "-fstack-protector-all or equivalent /GS compiler switch, leaving stack "
        "buffer overflows unmitigated at runtime."
    ),
    "missing_aslr_pie": (
        "Executables or shared objects are built without Position Independent "
        "Executable/Code support (-fPIE/-pie or /DYNAMICBASE), undermining "
        "Address Space Layout Randomization protections against memory "
        "corruption exploits."
    ),
    "missing_fortify_source": (
        "The build does not use _FORTIFY_SOURCE or equivalent buffer-overflow "
        "detecting wrappers around unsafe libc functions like memcpy, strcpy, "
        "or sprintf."
    ),
    "missing_linker_hardening": (
        "Linker flags that harden the resulting binary are absent, such as "
        "-z,noexecstack, -z,noexecheap, -z,relro, -z,now (RELRO/GOT "
        "protection), or the Retpoline mitigations for speculative execution "
        "attacks like Spectre/Meltcheck."
    ),
    "insecure_autotools_makefile_config": (
        "The project's configuration tooling (Autoconf, Automake, hand-written "
        "Makefiles, or IDE project files) silently drops or ignores requested "
        "security-relevant CFLAGS/CXXFLAGS/LDFLAGS, or ships an insecure "
        "out-of-the-box default configuration."
    ),
    "improper_assert_ndebug_usage": (
        "Program diagnostics via assert()/abort() are misused as a production "
        "error-handling mechanism, or NDEBUG/DEBUG macros are defined "
        "inconsistently across the program and the libraries it links against."
    ),
    "test_build_overexposure": (
        "A Test build configuration that makes private/protected members or "
        "hidden-visibility symbols public for testing purposes is shipped or "
        "left enabled outside of the isolated test harness."
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
