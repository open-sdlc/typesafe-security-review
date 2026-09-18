"""Race Condition Weaknesses (CWE-362) classifier built on the TypeSafe
System One API.

Classifies input text against sub-categories drawn from CWE (Common
Weakness Enumeration) entries for general systems/concurrency-level race
conditions, rooted in:
https://cwe.mitre.org/data/definitions/362.html

This is a general-purpose concurrency-race classifier covering any language
or runtime, distinct from the narrower `race_condition_check_then_act`
category inside `business_logic_security_classifier` (which only covers
business-logic check-then-act abuse such as double-spending a coupon) and
`callback_ordering_race_condition` inside `nodejs_security_classifier`.
Categories here are grounded in CWE-362 (Race Condition), CWE-367
(Time-of-check Time-of-use / TOCTOU), CWE-366 (Race Condition within a
Thread), CWE-364 (Signal Handler Race Condition), CWE-412/413
(Unrestricted/Improper Resource Locking), CWE-414 (Missing Lock Check),
CWE-609 (Double-Checked Locking), CWE-663 (Use of a Non-reentrant Function
in a Concurrent Context), CWE-764/765 (Multiple Locks/Unlocks of a Critical
Resource), CWE-820/821 (Missing/Incorrect Synchronization), CWE-832 (Unlock
of a Resource that is not Locked), CWE-833 (Deadlock), CWE-1265 (Unintended
Reentrant Invocation via Nested Calls), and CWE-1322 (Use of Blocking Code
in a Single-threaded/Non-blocking Context).

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python race_condition_classifier.py "some text to classify"
    python race_condition_classifier.py --file path/to/content.txt
    echo "some text" | python race_condition_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Race Condition Weaknesses (CWE-362)"
CHEATSHEET_URL = "https://cwe.mitre.org/data/definitions/362.html"

# Sub-categories drawn from CWE-362 and its closely related concurrency CWE
# entries. Each description is written so Jev (the TypeSafe model) can
# distinguish it from neighboring categories -- be specific about what does
# and does not count.
CATEGORIES = {
    "filesystem_toctou_check_then_use": (
        "Code checks a property of a file or path (existence, permissions, "
        "ownership, type) and then performs a separate later operation on "
        "that same file or path (open, write, chmod, delete), leaving a "
        "window where an attacker can swap or replace the file between the "
        "check and the use (Time-of-check Time-of-use / TOCTOU, CWE-367)."
    ),
    "double_checked_locking_without_synchronization": (
        "A lazily-initialized shared value is checked, then locked, then "
        "checked again before initializing it (the double-checked locking "
        "pattern), but without the memory barriers, volatile/atomic "
        "qualifiers, or language guarantees needed to make the pattern safe, "
        "so another thread can observe a partially-constructed object "
        "(CWE-609)."
    ),
    "missing_or_incorrect_lock_around_shared_state": (
        "Shared/global mutable state is read or written from multiple "
        "threads, goroutines, or processes without acquiring an appropriate "
        "mutex, semaphore, or other lock, or the lock used does not actually "
        "cover the critical section it is meant to protect (missing or "
        "incorrect synchronization, CWE-412, CWE-413, CWE-414, CWE-820, "
        "CWE-821)."
    ),
    "deadlock_from_inconsistent_lock_ordering": (
        "Two or more locks are acquired in an inconsistent order across "
        "different code paths or threads (e.g. thread A locks X then Y while "
        "thread B locks Y then X), creating the potential for a circular "
        "wait where none of the threads can make progress (deadlock, "
        "CWE-833)."
    ),
    "signal_handler_race_condition": (
        "A signal handler (SIGINT, SIGTERM, SIGCHLD, etc.) calls functions "
        "that are not async-signal-safe -- such as malloc/free, non-reentrant "
        "library calls, or complex I/O -- or shares mutable state with the "
        "main program flow without proper synchronization, creating a race "
        "between the handler and the interrupted code (CWE-364)."
    ),
    "non_reentrant_function_use_in_concurrent_context": (
        "A function known to be non-reentrant (relying on static/global "
        "buffers or state, such as classic strtok, gmtime, or rand) is "
        "called concurrently from multiple threads or is re-entered before a "
        "prior invocation completes, causing one call's internal state to "
        "corrupt another's (CWE-663)."
    ),
    "unintended_reentrant_invocation_via_nested_calls": (
        "A function, callback, or external call (e.g. invoking untrusted "
        "code, a smart-contract external call, or a re-entrant callback) can "
        "trigger a nested call back into the same function or contract "
        "before its first invocation has finished updating its internal "
        "state, letting the reentrant call observe or act on stale/"
        "inconsistent state (CWE-1265)."
    ),
    "unsynchronized_shared_state_read_modify_write": (
        "A shared variable, counter, cache entry, or other in-memory state "
        "is updated via a non-atomic read-modify-write sequence (such as "
        "'value = value + 1' without an atomic operation or lock) from "
        "multiple concurrent execution contexts, risking lost updates or "
        "inconsistent state (CWE-362, CWE-366)."
    ),
    "blocking_call_in_nonblocking_context": (
        "A blocking or long-running synchronous call (synchronous file/"
        "network I/O, a busy-wait, or a heavy CPU-bound computation) is "
        "invoked directly inside a single-threaded event loop or an "
        "otherwise non-blocking/async execution context, stalling all other "
        "concurrent work on that loop until the call returns (CWE-1322)."
    ),
    "improper_lock_release": (
        "A lock or critical resource is unlocked more than once, unlocked "
        "along a code path (such as an error/exception path) where it was "
        "never acquired, or released by a thread that does not currently "
        "hold it, corrupting the locking state for subsequent callers "
        "(CWE-764, CWE-765, CWE-832)."
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
