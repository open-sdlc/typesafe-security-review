"""Docker Security Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Docker Security Cheat Sheet":
https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python docker_security_classifier.py "some text to classify"
    python docker_security_classifier.py --file path/to/content.txt
    echo "some text" | python docker_security_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Docker Security Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Docker_Security_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's numbered Rules (#0-#13) covering
# daemon exposure, privilege, capabilities, networking, resources, and
# supply chain security for Docker/Kubernetes containers.
CATEGORIES = {
    "exposed_docker_daemon_socket": (
        "The Docker daemon socket (/var/run/docker.sock) is mounted into a "
        "container, or the daemon is exposed over an unauthenticated/"
        "unencrypted tcp:// socket, effectively granting unrestricted root "
        "access to the host."
    ),
    "privileged_container_execution": (
        "A container is run as root, with the --privileged flag, without a "
        "dedicated USER directive, or without --security-opt=no-new-"
        "privileges, enabling privilege escalation inside or out of the "
        "container."
    ),
    "excessive_linux_capabilities": (
        "A container is granted Linux kernel capabilities beyond what it "
        "needs (e.g. not using --cap-drop all with selective --cap-add), "
        "increasing the container's ability to affect the host."
    ),
    "unrestricted_inter_container_networking": (
        "Inter-Container Connectivity (icc) or a shared bridge network "
        "allows all containers to freely communicate, instead of using "
        "custom Docker networks or Kubernetes Network Policies to segment "
        "traffic."
    ),
    "resource_exhaustion_dos": (
        "A container is run without memory, CPU, ulimit (file descriptor / "
        "process count), or restart-count limits, allowing it to exhaust "
        "host resources and cause a Denial of Service."
    ),
    "writable_filesystem_risk": (
        "A container's root filesystem or a mounted volume is writable when "
        "it does not need to be, instead of using --read-only (with --tmpfs "
        "for scratch space) or mounting volumes with :ro."
    ),
    "runtime_security_gaps": (
        "The default seccomp, AppArmor, or SELinux profile is disabled, or "
        "there is no behavioral/anomaly monitoring (e.g. Falco, Tetragon) to "
        "detect unexpected exec calls or privilege escalation at runtime."
    ),
    "supply_chain_and_scanning_gaps": (
        "Container images are built or deployed without vulnerability "
        "scanning, SBOM generation, image signing, or verified provenance in "
        "the CI/CD pipeline, or a base image/OS package version is not "
        "pinned."
    ),
    "insecure_secrets_handling": (
        "Sensitive data such as passwords, tokens, or SSH keys is baked into "
        "a container image or passed via runtime commands/environment "
        "variables instead of using Docker Secrets or a proper secrets "
        "manager."
    ),
    "host_firewall_bypass_via_port_publishing": (
        "A container port is published with -p to all interfaces (e.g. "
        "0.0.0.0) so that Docker's own iptables/nftables rules bypass host "
        "firewalls like UFW, unintentionally exposing the service publicly."
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
