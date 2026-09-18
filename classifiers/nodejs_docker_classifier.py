"""NodeJS Docker Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"NodeJS Docker Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/NodeJS_Docker_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python nodejs_docker_classifier.py "some text to classify"
    python nodejs_docker_classifier.py --file path/to/content.txt
    echo "some text" | python nodejs_docker_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "NodeJS Docker Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "NodeJS_Docker_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's numbered Dockerfile
# best-practice sections. Each description is written so Jev (the TypeSafe
# model) can distinguish it from neighboring categories -- be specific about
# what does and does not count.
CATEGORIES = {
    "floating_base_image_tag": (
        "The Dockerfile's `FROM` line uses a floating/default tag such as "
        "plain `node` or `node:latest` instead of a pinned, deterministic "
        "digest (SHA256), causing non-reproducible builds that silently pull "
        "in new base image content over time."
    ),
    "oversized_base_image": (
        "The Dockerfile is built on a full-OS base image (e.g. plain `node`) "
        "instead of a minimal variant such as `node:lts-alpine`, unnecessarily "
        "increasing image size and the number of bundled libraries/tools that "
        "could carry vulnerabilities."
    ),
    "dev_dependencies_in_production_image": (
        "The image installs all dependencies including `devDependencies` "
        "(e.g. plain `npm ci` or `npm install`) instead of using `npm ci "
        "--omit=dev`, adding unnecessary packages and attack surface to the "
        "production image."
    ),
    "missing_node_env_production": (
        "The container does not set `NODE_ENV=production`, so frameworks and "
        "libraries that gate performance and security optimizations behind "
        "that environment variable run in a less secure/optimized mode."
    ),
    "container_running_as_root": (
        "The containerized Node.js process runs as the root user (no `USER` "
        "directive, or files copied without `--chown`), so a command "
        "injection or path traversal vulnerability in the app could be "
        "leveraged for full container compromise or escape."
    ),
    "improper_signal_handling": (
        "The Dockerfile invokes the app indirectly (e.g. `CMD \"npm\" "
        "\"start\"` or a shell script) or runs Node.js directly as PID 1 "
        "without an init process, so signals like SIGTERM/SIGHUP are not "
        "properly forwarded for graceful shutdown."
    ),
    "unpatched_dependency_vulnerabilities": (
        "The image bakes in outdated or known-vulnerable Node.js runtime or "
        "npm package versions without a scanning/update process to catch "
        "them before deployment."
    ),
    "missing_multistage_build": (
        "The Dockerfile does not use a multi-stage build to separate "
        "build-time tools, secrets, and source from the final runtime image, "
        "leaving unnecessary build artifacts or credentials in the shipped "
        "container."
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
