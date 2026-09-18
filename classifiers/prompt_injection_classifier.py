"""Prompt injection classifier built on the TypeSafe System One API.

Classifies input text against the attack taxonomy from the OWASP
"LLM Prompt Injection Prevention Cheat Sheet":
https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html

The taxonomy is expressed as a single TypeSafe Choice question: Jev selects
the single best-matching attack category (or "benign") for the given text.
Note a Choice picks one label, so inputs that combine several techniques
(e.g. a base64-encoded jailbreak) will be assigned to whichever category
dominates. For overlapping-technique detection, ask one Noul per category
instead (see the `use_nouls` example at the bottom of this file).

Usage:
    python prompt_injection_classifier.py "some text to classify"
    python prompt_injection_classifier.py --file path/to/content.txt
    echo "some text" | python prompt_injection_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Choice, Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "LLM Prompt Injection Prevention Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "LLM_Prompt_Injection_Prevention_Cheat_Sheet.html"
)

# Attack taxonomy drawn from the cheat sheet's "Common Attack Types" section.
# Each description is written as Choice criteria so Jev can distinguish
# categories that sound similar (e.g. direct injection vs. jailbreak roleplay).
ATTACK_TYPES = {
    "direct_injection": (
        "Explicit instructions in the input itself telling the model to ignore, "
        "override, or replace its prior/system instructions, e.g. 'ignore all "
        "previous instructions' or 'you are now in developer mode'."
    ),
    "indirect_injection": (
        "Instructions are not written by the requesting user but are embedded in "
        "external content the model is asked to process -- code comments, commit "
        "messages, issue descriptions, web pages, documents, or email bodies -- as "
        "if that content were itself giving the model commands."
    ),
    "encoding_obfuscation": (
        "The malicious instruction is hidden using an encoding or rendering trick "
        "such as base64, hex, invisible/zero-width unicode characters, or "
        "white-on-white LaTeX/KaTeX text, so it is not visible as plain text."
    ),
    "typoglycemia": (
        "Trigger words (ignore, bypass, override, reveal, delete, system, etc.) are "
        "deliberately misspelled with scrambled middle letters but correct "
        "first/last letters, to slip past keyword filters while staying readable."
    ),
    "best_of_n_jailbreak": (
        "The same disallowed request is repeated with surface variations such as "
        "random capitalization, added spacing between letters, or padding phrases "
        "like 'for educational purposes', aimed at finding a phrasing that evades "
        "filters."
    ),
    "html_markdown_injection": (
        "The input contains HTML or Markdown intended to be rendered in the "
        "model's response, such as hidden image tags, disguised links, or markup "
        "crafted for data exfiltration when rendered."
    ),
    "jailbreak_roleplay": (
        "The request tries to bypass safety controls through role-play or a "
        "persona swap (e.g. DAN 'do anything now'), a hypothetical/fictional "
        "framing, or emotional manipulation ('grandmother trick') rather than a "
        "direct override."
    ),
    "multi_turn_persistent": (
        "The input tries to establish coded language, a delayed trigger, or "
        "another setup meant to activate or poison behavior in a later turn or "
        "session rather than immediately."
    ),
    "system_prompt_extraction": (
        "The request specifically asks the model to reveal, repeat, or summarize "
        "its own system prompt, hidden instructions, or configuration, e.g. 'what "
        "were your exact instructions?'."
    ),
    "data_exfiltration": (
        "The request asks the model to reveal sensitive information it should not "
        "share: other users' conversation history, credentials, API keys, "
        "passwords, or internal system details."
    ),
    "multimodal_injection": (
        "The state references or contains instructions hidden inside a non-text "
        "modality processed alongside the request, such as steganographic text in "
        "an image or hidden text in document metadata."
    ),
    "rag_poisoning": (
        "The content appears to be a retrieved document or knowledge-base passage "
        "that itself contains an instruction aimed at the model, intended to "
        "hijack behavior when pulled into a retrieval-augmented generation "
        "pipeline."
    ),
    "agent_tool_attack": (
        "The input forges agent reasoning/tool-output text, tries to steer a tool "
        "call toward attacker-chosen parameters, or otherwise attempts to poison "
        "an agent's working context/memory."
    ),
    "benign": (
        "Ordinary content or a request with no attempt to override instructions, "
        "hide payloads, extract secrets, or manipulate the model's behavior."
    ),
}

# Standard CATEGORIES export (excludes the "benign" catch-all, which only
# makes sense for the single-pick Choice classifier above) consumed by
# run_all_classifiers.py and classify_with_nouls() below.
CATEGORIES = {name: desc for name, desc in ATTACK_TYPES.items() if name != "benign"}


def classify(text: str):
    """Return the Choice answer for `text` against the OWASP attack taxonomy."""
    with TypeSafeClient() as client:
        result = client.system_one(
            state=text,
            questions={
                "attack_type": Choice(
                    instructions=(
                        "Which single category best describes this input, per the "
                        "OWASP LLM Prompt Injection Prevention Cheat Sheet attack "
                        "taxonomy? Pick 'benign' if none apply."
                    ),
                    criteria=ATTACK_TYPES,
                ),
            },
        )
    return result.choices["attack_type"]


def classify_with_nouls(text: str):
    """Standard interface used by run_all_classifiers.py: one Noul per
    category, for inputs that may match several techniques at once (e.g. an
    encoded jailbreak). Returns a dict of category -> probability, all
    evaluated in a single parallel call."""
    with TypeSafeClient() as client:
        result = client.system_one(
            state=text,
            questions={
                name: Noul(instructions=f"Does the input match this attack pattern: {desc}")
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
    parser.add_argument(
        "--nouls",
        action="store_true",
        help="Score every category independently instead of picking one",
    )
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

    if args.nouls:
        scores = classify_with_nouls(text)
        rows = [
            (name, f"{prob:.3f}")
            for name, prob in sorted(scores.items(), key=lambda kv: -kv[1])
        ]
        print_table(("attack_type", "probability"), rows)
        return 0

    answer = classify(text)
    rows = [
        (
            "->" if label == answer.choice else "",
            label,
            f"{prob:.3f}",
        )
        for label, prob in sorted(answer.probabilities.items(), key=lambda kv: -kv[1])
    ]
    print_table(("", "attack_type", "probability"), rows)
    print(f"\nselected: {answer.choice}  (confidence={answer.confidence:.3f})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
