"""Secure AI Model Ops Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Secure AI Model Ops Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Secure_AI_Model_Ops_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python secure_ai_model_ops_classifier.py "some text to classify"
    python secure_ai_model_ops_classifier.py --file path/to/content.txt
    echo "some text" | python secure_ai_model_ops_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Secure AI Model Ops Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/Secure_AI_Model_Ops_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "training_data_poisoning": (
        "Malicious or mislabeled samples are injected into a training or fine- "
        "tuning dataset (including public/open-source datasets) to degrade "
        "accuracy or introduce a targeted bias/backdoor into the model."
    ),
    "model_inversion_or_extraction": (
        "An attacker uses inference queries to reconstruct training data (e.g. "
        "inferring a specific individual was in a medical training set) or to "
        "extract the model's own parameters."
    ),
    "adversarial_input_evasion": (
        "An input is subtly, often imperceptibly, modified (e.g. a few altered "
        "pixels) to cause the model to misclassify or mispredict without an "
        "obvious change visible to a human observer."
    ),
    "llm_prompt_injection_abuse": (
        "An inference request contains text like 'ignore all previous "
        "instructions' aimed at overriding the LLM's intended behavior or leaking "
        "its system prompt."
    ),
    "unsecured_inference_endpoint": (
        "A model inference API is publicly reachable without authentication, "
        "authorization, rate limiting, or input validation, or lacks per-tenant "
        "spend/request/concurrency limits guarding against denial-of-wallet "
        "abuse."
    ),
    "hardcoded_ml_credentials": (
        "API keys, tokens, or other credentials for ML services (e.g. OpenAI, "
        "Hugging Face) are hardcoded in source code or notebooks rather than a "
        "secret manager, risking accidental leakage (e.g. via GitHub)."
    ),
    "unvalidated_third_party_model": (
        "A pre-trained or third-party model file (e.g. a .pt/.pkl artifact) is "
        "loaded and used in production without verifying its integrity, "
        "provenance, or safety, risking malicious code execution during "
        "deserialization."
    ),
    "open_artifact_or_tooling_exposure": (
        "Model binaries, datasets, training logs, or an MLOps tool (e.g. an "
        "MLFlow instance) are exposed via misconfigured storage or missing "
        "authentication, giving public access to sensitive artifacts."
    ),
    "weak_runtime_or_tenant_isolation": (
        "Training or inference workloads from different trust levels/tenants "
        "share GPU/accelerator hardware, containers, or credentials without "
        "strong isolation, risking cross-tenant data exposure or side-channel "
        "leakage."
    ),
    "missing_monitoring_or_orphaned_deployment": (
        "There is no drift/anomaly detection on model behavior or input "
        "distribution, or an old test/staging model remains reachable in "
        "production without the same protections as the current deployment."
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
