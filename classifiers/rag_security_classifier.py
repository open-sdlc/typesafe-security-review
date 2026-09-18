"""RAG Security Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"RAG Security Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/RAG_Security_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python rag_security_classifier.py "some text to classify"
    python rag_security_classifier.py --file path/to/content.txt
    echo "some text" | python rag_security_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "RAG Security Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/RAG_Security_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "document_poisoning": (
        "Malicious or hidden instructions (e.g. invisible Unicode, zero-width "
        "characters, or overt text like 'ignore all previous instructions') are "
        "injected into a document uploaded to a shared knowledge base so that it "
        "later poisons the model's context when retrieved."
    ),
    "embedding_manipulation_or_privacy_leak": (
        "A document or input is adversarially crafted so its embedding is "
        "artificially close to unrelated target queries, or embeddings are "
        "treated as anonymized when they can leak source content via "
        "inversion/similarity probing/membership inference."
    ),
    "context_window_injection": (
        "Retrieved chunks injected into the model's context contain text designed "
        "to override the system prompt (e.g. 'SYSTEM: you are now unrestricted') "
        "or collectively form an adversarial instruction the model treats as a "
        "command rather than as untrusted retrieved data."
    ),
    "access_control_inheritance_failure": (
        "Access-control metadata (classification, owner, permitted roles/tenants) "
        "is missing or stale on vector chunks, so retrieval-time permission "
        "checks do not reflect the source document's current access restrictions, "
        "or deleted/de-permissioned documents remain retrievable."
    ),
    "missing_source_attribution": (
        "A RAG response is returned without verifiable provenance -- no record or "
        "signature of which documents/chunks were used, or attribution data that "
        "could be tampered with after generation without detection."
    ),
    "tenant_or_classification_isolation_failure": (
        "A query from one tenant, customer, or classification level retrieves "
        "vector chunks belonging to another tenant or a different classification "
        "level due to a shared, unpartitioned vector namespace."
    ),
    "vector_index_integrity_tampering": (
        "The vector index itself is modified, written to, or deleted by an "
        "unauthorized actor or process (not the source documents), altering which "
        "content is retrieved without any corresponding document change."
    ),
    "query_injection_reconnaissance": (
        "Carefully worded or systematically varied queries are used to probe the "
        "retrieval corpus for sensitive documents or to map its contents, e.g. by "
        "observing similarity scores or retrieval patterns."
    ),
    "output_validation_bypass": (
        "A generated RAG response leaks PII, secrets, or regulated data from "
        "retrieved chunks, or an agent/tool output is trusted and executed "
        "without schema validation or policy enforcement."
    ),
    "unsafe_tool_invocation_from_rag": (
        "Retrieved content influences an agent's decision to call a tool "
        "(payment, deletion, external API) without independent authorization "
        "checks, human confirmation for high-risk actions, or an allowlist of "
        "permitted tools."
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
