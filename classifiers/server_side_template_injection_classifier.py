"""Server-Side Template Injection classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the CWE (Common
Weakness Enumeration) entry for Server-Side Template Injection and its
closely related Expression Language Injection weakness:
https://cwe.mitre.org/data/definitions/1336.html
(see also CWE-917, Expression Language Injection:
https://cwe.mitre.org/data/definitions/917.html)

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python server_side_template_injection_classifier.py "some text to classify"
    python server_side_template_injection_classifier.py --file path/to/content.txt
    echo "some text" | python server_side_template_injection_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Server-Side Template Injection (CWE-1336)"
CHEATSHEET_URL = "https://cwe.mitre.org/data/definitions/1336.html"

# Sub-categories drawn from CWE-1336 (Server-Side Template Injection) and the
# closely related CWE-917 (Expression Language Injection). Each description is
# written so Jev (the TypeSafe model) can distinguish it from neighboring
# categories -- be specific about what does and does not count. This is
# distinct from injection_prevention_classifier.py's scripting/SQL/LDAP/XPath
# categories: the focus here is specifically template-engine and
# expression-language contexts.
CATEGORIES = {
    "untrusted_input_concatenated_into_template_string": (
        "Untrusted or user-controlled input (form fields, URL parameters, "
        "headers, uploaded content) is concatenated or interpolated directly "
        "into a template string before that string is passed to a template "
        "engine's render/compile function, rather than being passed only as "
        "a data value substituted into a fixed, developer-authored template."
    ),
    "python_flask_jinja2_ssti": (
        "A Python web application (commonly Flask) passes untrusted input "
        "into Jinja2's render_template_string, Template(), or an equivalent "
        "dynamic-template API, allowing an attacker-supplied payload such as "
        "{{7*7}} or {{config}} or {{self.__init__.__globals__}} to be "
        "evaluated as Jinja2 template syntax rather than literal text."
    ),
    "java_template_engine_ssti": (
        "A Java application renders untrusted input through a server-side "
        "template engine such as FreeMarker, Velocity, or Thymeleaf in a way "
        "that lets attacker-controlled template directives, expressions, or "
        "Thymeleaf SpEL preprocessing expressions (e.g. ${...}, #{...}, "
        "__${...}__) execute rather than being treated as inert text."
    ),
    "php_template_engine_ssti": (
        "A PHP application renders untrusted input through a server-side "
        "template engine such as Twig or Smarty in a way that lets "
        "attacker-controlled template syntax (e.g. {{ }}, {% %}, or Smarty "
        "{php} blocks) be evaluated by the engine instead of being escaped "
        "or treated as literal template data."
    ),
    "expression_language_injection": (
        "Untrusted input is evaluated as a Java/Spring Expression Language "
        "statement (SpEL), OGNL expression (e.g. in Struts), or similar EL "
        "construct outside of a templating context proper -- for example via "
        "SpelExpressionParser.parseExpression() or an OGNL "
        "Ognl.getValue()/setValue() call fed with attacker-controlled text -- "
        "corresponding to CWE-917 (Expression Language Injection)."
    ),
    "template_sandbox_escape": (
        "A template engine's restricted or 'sandboxed' execution mode "
        "(intended to limit templates to safe, non-code-executing "
        "constructs) is bypassed or escaped, allowing access to underlying "
        "objects, classes, or the runtime environment that the sandbox was "
        "meant to block."
    ),
    "user_controlled_template_selection": (
        "The name, path, or identifier of which template file to load and "
        "render is derived from untrusted user input (e.g. a URL parameter "
        "used to pick a template filename), allowing an attacker to select "
        "an unintended template, traverse to an arbitrary file, or trigger "
        "injection via the selection mechanism itself rather than the "
        "template's rendered content."
    ),
    "client_side_templating_confused_with_server_side": (
        "A discussion or implementation conflates lower-risk client-side "
        "templating frameworks (e.g. AngularJS expressions, client-rendered "
        "Handlebars) with server-side template rendering, leading to the "
        "server-side rendering path being under-protected because the risk "
        "was mistakenly assessed as only client-side."
    ),
    "nodejs_template_engine_ssti": (
        "A Node.js application renders untrusted input through a server-side "
        "template engine such as Handlebars, EJS, or Pug in a way that "
        "allows attacker-supplied template syntax or embedded JavaScript "
        "(e.g. EJS <%= %> tags or Handlebars helper/prototype-pollution "
        "based payloads) to execute during rendering."
    ),
    "ssti_leading_to_remote_code_execution": (
        "A server-side template injection or expression-language injection "
        "finding is escalated to demonstrate or discuss arbitrary code "
        "execution on the server, such as invoking Runtime.exec, "
        "os.popen/subprocess, or reflective class loading from within the "
        "template/expression evaluation context."
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
