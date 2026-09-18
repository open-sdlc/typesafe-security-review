"""AI-Powered Advertising Systems Security Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"AI-Powered Advertising Systems Security Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/AI-Powered_Advertising_Systems_Security_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python ai_powered_advertising_systems_security_classifier.py "some text to classify"
    python ai_powered_advertising_systems_security_classifier.py --file path/to/content.txt
    echo "some text" | python ai_powered_advertising_systems_security_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "AI-Powered Advertising Systems Security Cheat Sheet"
CHEATSHEET_URL = "https://cheatsheetseries.owasp.org/cheatsheets/AI-Powered_Advertising_Systems_Security_Cheat_Sheet.html"

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "consent_bypass_ai_targeting": (
        "An AI/ML/LLM-driven personalization, targeting, ranking, or lookalike "
        "model runs on personal data (profiling) without valid, scoped consent, "
        "or consent is checked only at data collection while the later "
        "model-invocation or identifier-join step -- the actual point where "
        "profiling attaches -- is left ungated, or real-time opt-outs (Sec-GPC, "
        "GPP, ATT, Ad ID reset) are not honored downstream in caches, segments, "
        "or adapters."
    ),
    "protected_category_ad_targeting": (
        "Ad targeting or delivery infers or targets a special/protected category "
        "(health, political belief, employment, housing, credit) from generic "
        "signals, or routes regulated verticals like employment, housing, or "
        "credit ads through the standard targeting path instead of a stricter, "
        "compliance-reviewed path."
    ),
    "corpus_rag_poisoning": (
        "Training data or a Retrieval-Augmented Generation (RAG) index used by "
        "the ad-serving model is written or manipulated by an adversarial "
        "participant -- an unsigned dataset manifest, an unpinned/displaced "
        "policy anchor chunk, a seeded near-neighbor embedding attack, or a "
        "fine-tune trigger/backdoor meant to persist through safety training."
    ),
    "model_extraction_via_scoring": (
        "A partner or advertiser repeatedly queries a scoring/bidding surface "
        "(raw scores, ad-rank, sponsored-rank) to reconstruct or extract the "
        "underlying proprietary model, or attempts to exceed a contractual query "
        "budget to enable such extraction."
    ),
    "prompt_injection_ad_pipeline": (
        "Attacker-controlled text -- publisher HTML, an advertiser landing page, "
        "or a creative brief field -- contains instructions intended to hijack "
        "the behavior of an LLM/VLM used in the ad-serving or brand-safety review "
        "pipeline, attempting to bypass a dual-LLM structural handoff or a "
        "non-LLM rules baseline."
    ),
    "forged_outcome_event_fraud": (
        "An ad outcome/conversion callback (impression, click, or conversion "
        "event) is forged, replayed, or re-signed with a fresh timestamp to "
        "fraudulently claim payment credit or to inject a poisoned label into the "
        "training corpus, including reuse of the same event ID across event types "
        "or bypassing HMAC/message-signature verification."
    ),
    "cross_tenant_cache_leak": (
        "Data or state belonging to one tenant/advertiser leaks to another "
        "through a shared serving-stack resource -- a paged-attention KV cache, a "
        "RAG index namespace, a plan cache, or a LoRA/fine-tune adapter pool -- "
        "that is not properly isolated by tenant ID."
    ),
    "adversarial_creative_evasion": (
        "A submitted ad creative (image, video, or audio) contains an adversarial "
        "patch, perturbation, or voice clone specifically crafted to flip an "
        "automated brand-safety, content-policy, or toxicity classifier's verdict "
        "while looking benign to a human reviewer."
    ),
    "supply_chain_model_provenance": (
        "A model artifact, fine-tune adapter, or creative asset is deployed "
        "without a verifiable signature, ML-BOM entry, or participant-provenance "
        "record (e.g. ads.txt, OpenRTB SupplyChain object, device attestation), "
        "or a VPAID creative with embedded JavaScript is accepted into the "
        "programmatic/CTV pipeline."
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
