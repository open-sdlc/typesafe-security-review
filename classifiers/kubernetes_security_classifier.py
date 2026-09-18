"""Kubernetes Security Cheat Sheet classifier built on the TypeSafe System One
API.

Classifies input text against sub-categories drawn from the OWASP
"Kubernetes Security Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Kubernetes_Security_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python kubernetes_security_classifier.py "some text to classify"
    python kubernetes_security_classifier.py --file path/to/content.txt
    echo "some text" | python kubernetes_security_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Kubernetes Security Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Kubernetes_Security_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "exposed_dashboard_or_etcd": (
        "The Kubernetes dashboard or the etcd datastore is exposed without "
        "strong authentication or network restriction (e.g. reachable from "
        "the public internet), risking full cluster compromise as happened "
        "in the Tesla cryptomining incident."
    ),
    "weak_api_server_authentication": (
        "The cluster relies on a weak built-in API-server authentication "
        "mechanism (a static token CSV file, or unrevocable X509 client "
        "certificates) instead of an external OIDC/cloud-IAM authentication "
        "method combined with multi-factor authentication."
    ),
    "missing_rbac_least_privilege": (
        "Role-Based Access Control (RBAC) is missing, disabled, or defines "
        "overly broad role bindings (e.g. cluster-admin) instead of scoped, "
        "least-privilege roles for users and service accounts."
    ),
    "unrestricted_kubelet_access": (
        "A Kubelet's HTTPS API endpoint is left reachable without "
        "authentication/authorization enabled, allowing powerful control "
        "over a node and its containers."
    ),
    "untrusted_or_unscanned_container_images": (
        "Container images are built from unapproved base images, sourced "
        "from unknown/public registries, or deployed without vulnerability "
        "scanning integrated into the CI pipeline."
    ),
    "excessive_container_privileges": (
        "A pod/container is configured to run as root, allow privilege "
        "escalation, use a writable root filesystem, or retain unnecessary "
        "Linux capabilities, instead of conforming to a restrictive Pod "
        "Security Standard profile."
    ),
    "missing_network_segmentation": (
        "Workloads are not isolated using Kubernetes namespaces or "
        "NetworkPolicies, allowing unrestricted network communication "
        "between pods and services that should be segmented."
    ),
    "missing_centralized_policy_enforcement": (
        "The cluster lacks a centralized admission-control/policy-"
        "enforcement mechanism (e.g. OPA, Kyverno, or the built-in "
        "Validating Admission Policy) to consistently enforce security "
        "rules across resources."
    ),
    "service_mesh_mtls_gaps": (
        "Service-to-service traffic within the cluster is not secured with "
        "mutual TLS or a service mesh, leaving communication between "
        "microservices unauthenticated or unencrypted."
    ),
    "outdated_kubernetes_version": (
        "The cluster is running an outdated or unpatched Kubernetes version "
        "instead of staying current with the latest stable release and its "
        "backported security fixes."
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
