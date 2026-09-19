"""Relevance router built on the TypeSafe System One API.

Given an input (source code, text, a request, etc.), decides which of the
131 classifiers under `classifiers/` are actually relevant, so callers (see
run_all_classifiers.py) don't have to run all 131 Noul classifiers on every
input -- e.g. skip the Django/Laravel/Ruby on Rails classifiers entirely for
a plain .java file. Most classifiers are sourced 1:1 from an OWASP Cheat
Sheet Series page; a smaller set is sourced from CWE (cwe.mitre.org) entries
for weakness families the OWASP series has no dedicated page for (e.g.
memory safety, path traversal, hardcoded credentials).

This follows the "speculative fan-out" pattern
(https://docs.typesafe.ai/patterns/fan-out.md): every cheat sheet's
applicability is asked as one Noul question, and all ~131 questions are sent
in a single parallel system_one() call, since parallel questions add
~no extra latency. Code (not the model) then decides which classifiers to
actually run based on each Noul's probability.

This module also owns the optional LLM-assisted second-opinion review of
"Review"-level findings (confidence_levels.py, spec 007): see
`llm_review_findings()` near the end of this file, used by `repo_scan.py`.

Usage:
    python router.py "some text to route"
    python router.py --file path/to/content.txt
    python router.py --file bad.java --threshold 0.4
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from typesafe_sdk import Noul, TypeSafeClient

import confidence_levels

# --- Registry: classifier module stem -> {name, url, applies_when} -------
# `applies_when` is a short scope description of when this classifier's
# guidance is relevant, used to build each routing Noul's instructions.
# Keys match classifiers/<stem>.py module stems exactly (see
# run_all_classifiers.py's discover_classifier_paths()). Most entries are
# sourced from an OWASP cheat sheet; entries whose `name` cites a CWE-XXXX
# ID are sourced from a CWE (cwe.mitre.org) definition instead.
ROUTES = {
    "abuse_case_classifier": {
        "name": "Abuse Case Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Abuse_Case_Cheat_Sheet.html",
        "applies_when": "any system during threat-modeling/design; used to define misuse and abuse scenarios; language-agnostic",
    },
    "access_control_classifier": {
        "name": "Access Control Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html",
        "applies_when": "any codebase implementing authorization/access-control checks; language-agnostic",
    },
    "ai_agent_security_classifier": {
        "name": "AI Agent Security Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html",
        "applies_when": "systems that build, orchestrate, or grant tool/action access to autonomous AI agents",
    },
    "ai_powered_advertising_systems_security_classifier": {
        "name": "AI-Powered Advertising Systems Security Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/AI-Powered_Advertising_Systems_Security_Cheat_Sheet.html",
        "applies_when": "ad-tech/advertising platforms that incorporate AI/ML models, bidding, or targeting",
    },
    "ajax_security_classifier": {
        "name": "AJAX Security Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/AJAX_Security_Cheat_Sheet.html",
        "applies_when": "web frontend JavaScript making asynchronous AJAX/XHR/fetch requests to a backend",
    },
    "aml_sanctions_ai_agent_payments_classifier": {
        "name": "AML Sanctions AI Agent Payments Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/AML_Sanctions_AI_Agent_Payments_Cheat_Sheet.html",
        "applies_when": "AI agents that initiate, approve, or process payments subject to AML/sanctions compliance",
    },
    "attack_surface_analysis_classifier": {
        "name": "Attack Surface Analysis Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html",
        "applies_when": "any application/system architecture being mapped or reviewed for exposed attack surface; language-agnostic",
    },
    "authentication_classifier": {
        "name": "Authentication Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
        "applies_when": "any codebase implementing login/credential-verification flows; language-agnostic",
    },
    "authorization_classifier": {
        "name": "Authorization Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html",
        "applies_when": "any codebase implementing permission/authorization checks; language-agnostic",
    },
    "authorization_regression_testing_classifier": {
        "name": "Authorization Regression Testing Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Regression_Testing_Cheat_Sheet.html",
        "applies_when": "test suites or CI pipelines that verify authorization rules have not regressed; language-agnostic",
    },
    "authorization_testing_automation_classifier": {
        "name": "Authorization Testing Automation Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Testing_Automation_Cheat_Sheet.html",
        "applies_when": "automated security test tooling (often Java) that exercises authorization checks",
    },
    "automotive_security_classifier": {
        "name": "Automotive Security Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Automotive_Security_Cheat_Sheet.html",
        "applies_when": "automotive/vehicle software, ECUs, CAN bus, or telematics systems",
    },
    "bean_validation_classifier": {
        "name": "Bean Validation Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Bean_Validation_Cheat_Sheet.html",
        "applies_when": "Java code using Bean Validation / JSR 380 (javax.validation / jakarta.validation) annotations",
    },
    "bot_management_and_anti_automation_classifier": {
        "name": "Bot Management and Anti-Automation Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Bot_Management_and_Anti-Automation_Cheat_Sheet.html",
        "applies_when": "web/app backends defending against bots, scraping, or automated credential stuffing",
    },
    "browser_extension_vulnerabilities_classifier": {
        "name": "Browser Extension Vulnerabilities Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Browser_Extension_Vulnerabilities_Cheat_Sheet.html",
        "applies_when": "browser extension code (JavaScript/manifest) for Chrome, Firefox, or Edge",
    },
    "business_logic_security_classifier": {
        "name": "Business Logic Security Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Business_Logic_Security_Cheat_Sheet.html",
        "applies_when": "any application's business/domain logic, workflows, pricing, or state transitions; language-agnostic",
    },
    "c_based_toolchain_hardening_classifier": {
        "name": "C-Based Toolchain Hardening Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/C-Based_Toolchain_Hardening_Cheat_Sheet.html",
        "applies_when": "C or C++ source code and its compiler/linker build toolchain",
    },
    "choosing_and_using_security_questions_classifier": {
        "name": "Choosing and Using Security Questions Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Choosing_and_Using_Security_Questions_Cheat_Sheet.html",
        "applies_when": "account-recovery flows that use security questions; language-agnostic",
    },
    "ci_cd_security_classifier": {
        "name": "CI CD Security Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/CI_CD_Security_Cheat_Sheet.html",
        "applies_when": "CI/CD pipeline configuration and runners (GitHub Actions, GitLab CI, Jenkins, etc.)",
    },
    "clickjacking_defense_classifier": {
        "name": "Clickjacking Defense Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html",
        "applies_when": "web frontend HTML/JS pages that could be framed in an iframe (UI redress risk)",
    },
    "content_security_policy_classifier": {
        "name": "Content Security Policy Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
        "applies_when": "web frontend HTML pages or HTTP headers configuring a Content-Security-Policy",
    },
    "cookie_theft_mitigation_classifier": {
        "name": "Cookie Theft Mitigation Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Cookie_Theft_Mitigation_Cheat_Sheet.html",
        "applies_when": "web apps issuing or handling HTTP cookies (session/auth tokens)",
    },
    "credential_stuffing_prevention_classifier": {
        "name": "Credential Stuffing Prevention Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html",
        "applies_when": "authentication endpoints/login flows facing automated credential-stuffing attacks",
    },
    "cross_site_request_forgery_prevention_classifier": {
        "name": "Cross-Site Request Forgery Prevention Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
        "applies_when": "web apps with state-changing HTTP endpoints or HTML forms (CSRF risk)",
    },
    "cross_site_scripting_prevention_classifier": {
        "name": "Cross Site Scripting Prevention Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
        "applies_when": "web frontend or server code that renders untrusted data into HTML (XSS risk)",
    },
    "cryptographic_storage_classifier": {
        "name": "Cryptographic Storage Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html",
        "applies_when": "any code that stores or encrypts sensitive data at rest; language-agnostic",
    },
    "database_security_classifier": {
        "name": "Database Security Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html",
        "applies_when": "any code or configuration that interacts with or configures a relational database",
    },
    "denial_of_service_classifier": {
        "name": "Denial of Service Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html",
        "applies_when": "any network-facing service or application susceptible to resource-exhaustion attacks",
    },
    "dependency_graph_sbom_classifier": {
        "name": "Dependency Graph SBOM Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Dependency_Graph_SBOM_Cheat_Sheet.html",
        "applies_when": "build/dependency manifests and SBOM generation tooling, for any language",
    },
    "deserialization_classifier": {
        "name": "Deserialization Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html",
        "applies_when": "code that deserializes untrusted data, in any language (Java, .NET, Python, PHP, etc.)",
    },
    "django_rest_framework_classifier": {
        "name": "Django REST Framework Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Django_REST_Framework_Cheat_Sheet.html",
        "applies_when": "Python code using Django REST Framework (DRF) to build APIs",
    },
    "django_security_classifier": {
        "name": "Django Security Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Django_Security_Cheat_Sheet.html",
        "applies_when": "Python code using the Django web framework",
    },
    "docker_security_classifier": {
        "name": "Docker Security Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html",
        "applies_when": "Dockerfiles, container images, or Docker daemon/runtime configuration",
    },
    "dom_based_xss_prevention_classifier": {
        "name": "DOM based XSS Prevention Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html",
        "applies_when": "client-side JavaScript that manipulates the DOM with untrusted data",
    },
    "dom_clobbering_prevention_classifier": {
        "name": "DOM Clobbering Prevention Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/DOM_Clobbering_Prevention_Cheat_Sheet.html",
        "applies_when": "client-side HTML/JavaScript vulnerable to DOM clobbering via named elements/id collisions",
    },
    "dotnet_security_classifier": {
        "name": "DotNet Security Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/DotNet_Security_Cheat_Sheet.html",
        "applies_when": ".NET or C# application code",
    },
    "drone_security_classifier": {
        "name": "Drone Security Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Drone_Security_Cheat_Sheet.html",
        "applies_when": "unmanned aerial vehicle (drone) firmware or control software",
    },
    "email_validation_and_verification_classifier": {
        "name": "Email Validation and Verification Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Email_Validation_and_Verification_Cheat_Sheet.html",
        "applies_when": "code that validates or verifies email addresses, or handles email-based signup",
    },
    "error_handling_classifier": {
        "name": "Error Handling Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html",
        "applies_when": "any codebase's error/exception handling and failure logging; language-agnostic",
    },
    "file_upload_classifier": {
        "name": "File Upload Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
        "applies_when": "any web app or API that accepts user-supplied file uploads",
    },
    "forgot_password_classifier": {
        "name": "Forgot Password Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html",
        "applies_when": "web app password-reset or account-recovery flows",
    },
    "github_actions_security_classifier": {
        "name": "GitHub Actions Security Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/GitHub_Actions_Security_Cheat_Sheet.html",
        "applies_when": "GitHub Actions workflow YAML files under .github/workflows",
    },
    "graphql_classifier": {
        "name": "GraphQL Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
        "applies_when": "APIs or servers implementing a GraphQL schema and resolvers",
    },
    "grpc_security_classifier": {
        "name": "gRPC Security Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/gRPC_Security_Cheat_Sheet.html",
        "applies_when": "services communicating via gRPC and Protocol Buffers",
    },
    "html5_security_classifier": {
        "name": "HTML5 Security Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html",
        "applies_when": "web frontend code using HTML5 features (Web Storage, Web Workers, postMessage, etc.)",
    },
    "http_headers_classifier": {
        "name": "HTTP Headers Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
        "applies_when": "any HTTP server or application configuring response headers",
    },
    "http_strict_transport_security_classifier": {
        "name": "HTTP Strict Transport Security Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html",
        "applies_when": "any HTTPS web server configuring the HSTS response header",
    },
    "infrastructure_as_code_security_classifier": {
        "name": "Infrastructure as Code Security Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html",
        "applies_when": "infrastructure-as-code templates (Terraform, CloudFormation, Ansible, Pulumi, etc.)",
    },
    "injection_prevention_classifier": {
        "name": "Injection Prevention Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html",
        "applies_when": "any code that builds queries or commands from untrusted input, in general; language-agnostic",
    },
    "injection_prevention_in_java_classifier": {
        "name": "Injection Prevention in Java Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_in_Java_Cheat_Sheet.html",
        "applies_when": "Java code building SQL, OS command, LDAP, or XPath queries from untrusted input",
    },
    "input_validation_classifier": {
        "name": "Input Validation Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html",
        "applies_when": "any code validating or sanitizing external input; language-agnostic",
    },
    "insecure_direct_object_reference_prevention_classifier": {
        "name": "Insecure Direct Object Reference Prevention Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html",
        "applies_when": "any API or app that exposes object references (IDs) in requests without authorization checks",
    },
    "jaas_classifier": {
        "name": "JAAS Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/JAAS_Cheat_Sheet.html",
        "applies_when": "Java code using JAAS (Java Authentication and Authorization Service)",
    },
    "java_security_classifier": {
        "name": "Java Security Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Java_Security_Cheat_Sheet.html",
        "applies_when": "general Java application code and JVM security configuration",
    },
    "json_web_token_classifier": {
        "name": "JSON Web Token Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html",
        "applies_when": "any code that issues or validates JSON Web Tokens (JWT)",
    },
    "key_management_classifier": {
        "name": "Key Management Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html",
        "applies_when": "any system that generates, stores, distributes, or rotates cryptographic keys",
    },
    "kubernetes_security_classifier": {
        "name": "Kubernetes Security Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Kubernetes_Security_Cheat_Sheet.html",
        "applies_when": "Kubernetes manifests, Helm charts, or cluster configuration",
    },
    "laravel_classifier": {
        "name": "Laravel Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Laravel_Cheat_Sheet.html",
        "applies_when": "PHP code using the Laravel framework",
    },
    "ldap_injection_prevention_classifier": {
        "name": "LDAP Injection Prevention Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html",
        "applies_when": "code that builds LDAP queries or filters from untrusted input",
    },
    "legacy_application_management_classifier": {
        "name": "Legacy Application Management Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Legacy_Application_Management_Cheat_Sheet.html",
        "applies_when": "older/legacy applications running unsupported frameworks, languages, or platforms",
    },
    "logging_classifier": {
        "name": "Logging Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html",
        "applies_when": "any code that emits application/security logs; language-agnostic",
    },
    "logging_vocabulary_classifier": {
        "name": "Logging Vocabulary Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Vocabulary_Cheat_Sheet.html",
        "applies_when": "log message schemas or taxonomies for security event logging; language-agnostic",
    },
    "mass_assignment_classifier": {
        "name": "Mass Assignment Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html",
        "applies_when": "web APIs or ORMs that bind request parameters directly onto model objects (Java, JS, PHP, etc.)",
    },
    "mcp_security_classifier": {
        "name": "MCP Security Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html",
        "applies_when": "servers or clients implementing the Model Context Protocol (MCP) for LLM tool use",
    },
    "microservices_based_security_arch_doc_classifier": {
        "name": "Microservices based Security Arch Doc Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Microservices_based_Security_Arch_Doc_Cheat_Sheet.html",
        "applies_when": "architecture documentation/design artifacts describing a microservice system",
    },
    "microservices_security_classifier": {
        "name": "Microservices Security Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Microservices_Security_Cheat_Sheet.html",
        "applies_when": "microservice architectures (service-to-service auth, API gateways, service mesh)",
    },
    "mobile_application_security_classifier": {
        "name": "Mobile Application Security Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Mobile_Application_Security_Cheat_Sheet.html",
        "applies_when": "iOS or Android mobile application code",
    },
    "multi_tenant_security_classifier": {
        "name": "Multi Tenant Security Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Multi_Tenant_Security_Cheat_Sheet.html",
        "applies_when": "SaaS applications or databases serving multiple tenants that need data isolation",
    },
    "multifactor_authentication_classifier": {
        "name": "Multifactor Authentication Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html",
        "applies_when": "authentication flows implementing MFA/2FA",
    },
    "network_segmentation_classifier": {
        "name": "Network Segmentation Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Network_Segmentation_Cheat_Sheet.html",
        "applies_when": "network architecture, firewall rules, or VLAN/subnet configuration",
    },
    "nextjs_security_classifier": {
        "name": "Nextjs Security Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Nextjs_Security_Cheat_Sheet.html",
        "applies_when": "JavaScript/TypeScript code using the Next.js framework",
    },
    "nodejs_docker_classifier": {
        "name": "NodeJS Docker Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/NodeJS_Docker_Cheat_Sheet.html",
        "applies_when": "Dockerfiles/containers that package a Node.js application",
    },
    "nodejs_security_classifier": {
        "name": "Nodejs Security Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html",
        "applies_when": "JavaScript/TypeScript server code running on Node.js",
    },
    "nosql_security_classifier": {
        "name": "NoSQL Security Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/NoSQL_Security_Cheat_Sheet.html",
        "applies_when": "code or queries interacting with a NoSQL database (MongoDB, DynamoDB, etc.)",
    },
    "npm_security_classifier": {
        "name": "NPM Security Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/NPM_Security_Cheat_Sheet.html",
        "applies_when": "package.json/npm package management and the JavaScript dependency supply chain",
    },
    "oauth2_classifier": {
        "name": "OAuth2 Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html",
        "applies_when": "any system implementing OAuth 2.0 authorization flows",
    },
    "os_command_injection_defense_classifier": {
        "name": "OS Command Injection Defense Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
        "applies_when": "any code that invokes OS shell commands with untrusted input (Java, PHP, shell scripts, etc.)",
    },
    "password_storage_classifier": {
        "name": "Password Storage Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html",
        "applies_when": "any code that stores or hashes user passwords",
    },
    "php_configuration_classifier": {
        "name": "PHP Configuration Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/PHP_Configuration_Cheat_Sheet.html",
        "applies_when": "php.ini and PHP runtime/server configuration",
    },
    "pinning_classifier": {
        "name": "Pinning Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Pinning_Cheat_Sheet.html",
        "applies_when": "mobile or client code implementing certificate or public-key pinning",
    },
    "prompt_injection_classifier": {
        "name": "LLM Prompt Injection Prevention Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html",
        "applies_when": "any system that feeds user or third-party content into an LLM prompt (chatbots, agents, RAG)",
    },
    "prototype_pollution_prevention_classifier": {
        "name": "Prototype Pollution Prevention Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html",
        "applies_when": "JavaScript/Node.js code merging or assigning untrusted object properties",
    },
    "query_parameterization_classifier": {
        "name": "Query Parameterization Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html",
        "applies_when": "any code building SQL queries, comparing parameterized queries vs. string concatenation",
    },
    "rag_security_classifier": {
        "name": "RAG Security Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/RAG_Security_Cheat_Sheet.html",
        "applies_when": "retrieval-augmented generation (RAG) pipelines combining an LLM with a knowledge base or vector store",
    },
    "rest_assessment_classifier": {
        "name": "REST Assessment Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/REST_Assessment_Cheat_Sheet.html",
        "applies_when": "REST API endpoints being manually or automatically security-tested",
    },
    "rest_security_classifier": {
        "name": "REST Security Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html",
        "applies_when": "any REST API design or implementation",
    },
    "ruby_on_rails_classifier": {
        "name": "Ruby on Rails Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Ruby_on_Rails_Cheat_Sheet.html",
        "applies_when": "Ruby code using the Ruby on Rails framework",
    },
    "saml_security_classifier": {
        "name": "SAML Security Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html",
        "applies_when": "systems implementing SAML-based single sign-on (SSO)",
    },
    "secrets_management_classifier": {
        "name": "Secrets Management Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
        "applies_when": "any system storing or distributing secrets such as API keys, passwords, or tokens; language-agnostic",
    },
    "secure_ai_model_ops_classifier": {
        "name": "Secure AI Model Ops Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Secure_AI_Model_Ops_Cheat_Sheet.html",
        "applies_when": "ML/AI model training, deployment, and serving infrastructure (MLOps)",
    },
    "secure_cloud_architecture_classifier": {
        "name": "Secure Cloud Architecture Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Secure_Cloud_Architecture_Cheat_Sheet.html",
        "applies_when": "cloud infrastructure design and architecture (AWS/Azure/GCP)",
    },
    "secure_code_review_classifier": {
        "name": "Secure Code Review Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Secure_Code_Review_Cheat_Sheet.html",
        "applies_when": "any source code undergoing a manual security code review; language-agnostic",
    },
    "secure_coding_with_ai_classifier": {
        "name": "Secure Coding with AI Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Secure_Coding_with_AI_Cheat_Sheet.html",
        "applies_when": "development workflows that use AI coding assistants/agents to generate or modify code",
    },
    "secure_product_design_classifier": {
        "name": "Secure Product Design Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Secure_Product_Design_Cheat_Sheet.html",
        "applies_when": "product or system design and architecture, prior to or independent of implementation",
    },
    "securing_cascading_style_sheets_classifier": {
        "name": "Securing Cascading Style Sheets Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Securing_Cascading_Style_Sheets_Cheat_Sheet.html",
        "applies_when": "CSS stylesheets or CSS-in-JS in web frontends",
    },
    "security_terminology_classifier": {
        "name": "Security Terminology Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Security_Terminology_Cheat_Sheet.html",
        "applies_when": "any content, used to catch misuse or confusion of security terminology; language-agnostic",
    },
    "server_side_request_forgery_prevention_classifier": {
        "name": "Server Side Request Forgery Prevention Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
        "applies_when": "any server code that fetches a URL supplied by user input",
    },
    "serverless_faas_security_classifier": {
        "name": "Serverless FaaS Security Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Serverless_FaaS_Security_Cheat_Sheet.html",
        "applies_when": "serverless/FaaS functions (AWS Lambda, Azure Functions, Google Cloud Functions, etc.)",
    },
    "session_management_classifier": {
        "name": "Session Management Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
        "applies_when": "any web app that issues or manages user sessions",
    },
    "software_supply_chain_security_classifier": {
        "name": "Software Supply Chain Security Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html",
        "applies_when": "build pipelines and third-party dependency supply chains, for any language",
    },
    "sql_injection_prevention_classifier": {
        "name": "SQL Injection Prevention Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        "applies_when": "any code that builds SQL queries from untrusted input",
    },
    "subdomain_takeover_prevention_classifier": {
        "name": "Subdomain Takeover Prevention Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Subdomain_Takeover_Prevention_Cheat_Sheet.html",
        "applies_when": "DNS records pointing at third-party services (dangling CNAME risk)",
    },
    "symfony_classifier": {
        "name": "Symfony Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Symfony_Cheat_Sheet.html",
        "applies_when": "PHP code using the Symfony framework",
    },
    "third_party_javascript_management_classifier": {
        "name": "Third Party Javascript Management Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html",
        "applies_when": "web pages loading third-party JavaScript such as analytics, ads, or widgets",
    },
    "third_party_payment_gateway_integration_classifier": {
        "name": "Third Party Payment Gateway Integration Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Payment_Gateway_Integration_Cheat_Sheet.html",
        "applies_when": "code integrating a third-party payment gateway (Stripe, PayPal, etc.)",
    },
    "threat_modeling_classifier": {
        "name": "Threat Modeling Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html",
        "applies_when": "system/architecture design documents undergoing threat modeling",
    },
    "tls_cipher_string_classifier": {
        "name": "TLS Cipher String Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/TLS_Cipher_String_Cheat_Sheet.html",
        "applies_when": "TLS/SSL server configuration, specifically cipher suite selection",
    },
    "transaction_authorization_classifier": {
        "name": "Transaction Authorization Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Transaction_Authorization_Cheat_Sheet.html",
        "applies_when": "financial/banking transaction confirmation flows (e.g. step-up authorization)",
    },
    "transport_layer_protection_classifier": {
        "name": "Transport Layer Protection Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html",
        "applies_when": "any network communication that needs transport-layer encryption",
    },
    "transport_layer_security_classifier": {
        "name": "Transport Layer Security Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
        "applies_when": "TLS configuration or implementation for any network service",
    },
    "unvalidated_redirects_and_forwards_classifier": {
        "name": "Unvalidated Redirects and Forwards Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
        "applies_when": "any web app that redirects or forwards based on a user-supplied URL parameter",
    },
    "user_privacy_protection_classifier": {
        "name": "User Privacy Protection Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/User_Privacy_Protection_Cheat_Sheet.html",
        "applies_when": "any system handling personal or user data (privacy-by-design, PII)",
    },
    "virtual_patching_classifier": {
        "name": "Virtual Patching Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Virtual_Patching_Cheat_Sheet.html",
        "applies_when": "WAF/IPS rules that mitigate a known vulnerability without changing application code",
    },
    "vulnerability_disclosure_classifier": {
        "name": "Vulnerability Disclosure Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Vulnerability_Disclosure_Cheat_Sheet.html",
        "applies_when": "an organization's vulnerability-disclosure or bug-bounty policy and process",
    },
    "vulnerable_dependency_management_classifier": {
        "name": "Vulnerable Dependency Management Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html",
        "applies_when": "any project's third-party library/dependency versions and known CVEs",
    },
    "web_service_security_classifier": {
        "name": "Web Service Security Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Web_Service_Security_Cheat_Sheet.html",
        "applies_when": "SOAP/XML-RPC or other general web service endpoints",
    },
    "websocket_security_classifier": {
        "name": "WebSocket Security Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html",
        "applies_when": "code implementing WebSocket connections or servers",
    },
    "xml_external_entity_prevention_classifier": {
        "name": "XML External Entity Prevention Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
        "applies_when": "any code that parses untrusted XML documents",
    },
    "xml_security_classifier": {
        "name": "XML Security Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/XML_Security_Cheat_Sheet.html",
        "applies_when": "any code processing XML documents or schemas",
    },
    "xs_leaks_classifier": {
        "name": "XS Leaks Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/XS_Leaks_Cheat_Sheet.html",
        "applies_when": "web browsers/pages vulnerable to cross-site leak side-channel attacks",
    },
    "xss_filter_evasion_classifier": {
        "name": "XSS Filter Evasion Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html",
        "applies_when": "web frontend output-encoding or XSS-filter implementations being tested for bypasses",
    },
    "zero_trust_architecture_classifier": {
        "name": "Zero Trust Architecture Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Zero_Trust_Architecture_Cheat_Sheet.html",
        "applies_when": "network/identity architecture implementing zero-trust principles",
    },
    # --- CWE-sourced classifiers (gap-fill additions, not from the OWASP series) ---
    "path_traversal_classifier": {
        "name": "Path Traversal (CWE-22)",
        "url": "https://cwe.mitre.org/data/definitions/22.html",
        "applies_when": "any code that accepts a user-supplied file path, filename, or archive for reading, writing, serving, or extraction",
    },
    "memory_safety_classifier": {
        "name": "Memory Safety Weaknesses (CWE Top 25)",
        "url": "https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html",
        "applies_when": "C, C++, Rust unsafe blocks, or other memory-unsafe systems-language code doing manual buffer/pointer management",
    },
    "race_condition_classifier": {
        "name": "Race Condition Weaknesses (CWE-362)",
        "url": "https://cwe.mitre.org/data/definitions/362.html",
        "applies_when": "any concurrent, multi-threaded, multi-process, or async code sharing state, files, or locks",
    },
    "server_side_template_injection_classifier": {
        "name": "Server-Side Template Injection (CWE-1336)",
        "url": "https://cwe.mitre.org/data/definitions/1336.html",
        "applies_when": "server-side code that renders a template engine (Jinja2, Twig, FreeMarker, Velocity, Thymeleaf, ERB, Handlebars) or evaluates an expression language (SpEL, OGNL) with any untrusted input",
    },
    "hardcoded_credentials_classifier": {
        "name": "Use of Hard-coded Credentials (CWE-798)",
        "url": "https://cwe.mitre.org/data/definitions/798.html",
        "applies_when": "any source code, configuration file, or script that may embed passwords, API keys, tokens, or connection strings",
    },
    "http_request_smuggling_classifier": {
        "name": "Inconsistent Interpretation of HTTP Requests (CWE-444)",
        "url": "https://cwe.mitre.org/data/definitions/444.html",
        "applies_when": "HTTP server, reverse proxy, load balancer, or gateway code/config that parses request boundaries (Content-Length, Transfer-Encoding, chunked encoding)",
    },
    "unsafe_reflection_classifier": {
        "name": "Unsafe Reflection (CWE-470)",
        "url": "https://cwe.mitre.org/data/definitions/470.html",
        "applies_when": "code using reflection, dynamic class loading, or dynamic attribute/method access (Java reflection, Python getattr/importlib, PHP dynamic instantiation) with untrusted input",
    },
    "csv_formula_injection_classifier": {
        "name": "CSV/Formula Injection (CWE-1236)",
        "url": "https://cwe.mitre.org/data/definitions/1236.html",
        "applies_when": "any feature exporting user-controlled data to CSV, XLSX, or another spreadsheet format",
    },
    "untrusted_search_path_classifier": {
        "name": "Untrusted Search Path (CWE-426)",
        "url": "https://cwe.mitre.org/data/definitions/426.html",
        "applies_when": "native applications, installers, or services that load libraries/executables via a search path (Windows DLL loading, PATH/LD_LIBRARY_PATH, service executable paths)",
    },
}


def route(text: str) -> dict:
    """Return dict of classifier module stem -> probability (0-1) that this
    cheat sheet's classifier is relevant to `text`. Sends one Noul per
    cheat sheet in a single parallel system_one() call."""
    with TypeSafeClient() as client:
        result = client.system_one(
            state=text,
            questions={
                stem: Noul(
                    instructions=(
                        f"Does '{info['name']}' apply to reviewing this "
                        f"content? It applies when the content involves: "
                        f"{info['applies_when']}."
                    )
                )
                for stem, info in ROUTES.items()
            },
        )
    return {stem: answer.noul for stem, answer in result.nouls.items()}


def select_relevant(text: str, threshold: float = 0.35) -> dict:
    """Return only the {stem: probability} entries at or above `threshold`."""
    scores = route(text)
    return {stem: prob for stem, prob in scores.items() if prob is not None and prob >= threshold}


# --- LLM-assisted review of "Review"-band findings (spec 003) ------------
#
# confidence_levels.py (spec 007) buckets every finding into "Pass" /
# "Review" / "Failed". "Review" is deliberately ambiguous -- this section
# adds an optional second-opinion pass for exactly that band: bundle every
# "Review" finding (grouped by file, referencing that file's path) into one
# prompt, save it to disk, hand it to an external coding-agent CLI the
# caller already has installed/authenticated (copilot/claude/codex), and
# parse a strict JSON verdict list back to reclassify each finding to
# "Pass" or "Failed". Unparsed/unmatched findings stay at "Review"
# (fail-soft, never raises).
#
# This deliberately shells out to a general-purpose local coding-agent CLI
# rather than asking another Noul/Choice question through the TypeSafe API:
# the point is a genuinely independent second opinion from a different
# tool/reasoning pass, not another probability score from the same
# pipeline that produced the ambiguous score in the first place.
#
# The prompt intentionally does NOT embed each flagged file's full text: it
# only lists file paths plus the candidate findings for each. The backend
# CLI is invoked with its working directory set to `repo_path` (so it's
# already "initialized"/checked out there, exactly like a normal local
# checkout) and with full tool access, so it reads each referenced file
# itself before judging it. Bundling full file text inline used to make
# the prompt balloon well past the OS's per-argument size limit (~128KB on
# Linux, `MAX_ARG_STRLEN`, well below the 2MB total `ARG_MAX`) for any
# realistically sized batch of "Review" findings, which made `--llm-review`
# fail with an "Argument list too long" OSError on essentially every real
# run -- silently, since the final summary line doesn't surface
# `stats["error"]`. To make doubly sure this class of bug can't recur even
# as prompts grow with larger batches, the prompt is also always sent to
# the backend over stdin (see run_llm_review_backend) rather than as a CLI
# argument, so its size is no longer bounded by OS argv limits at all.
#
# Security note: these backends are agentic CLIs with real tool access
# (file reads/edits, shell commands, etc), and this design deliberately
# relies on that tool access to read the flagged files. Running one against
# a possibly untrusted third-party repository carries some inherent
# prompt-injection / unintended-action risk. Mitigations: this feature is
# opt-in (off by default), the prompt instructs the backend to only read
# the specific files listed and make a pass/fail judgement (not to edit
# anything), Codex's `exec` defaults to a read-only sandbox, and
# `--llm-review-arg` lets callers pass each backend's own stricter
# permission flags (e.g. Claude's `--permission-mode`) if desired.

# Short, fixed, argv-safe instruction used for backends (claude/codex) that
# treat "piped stdin + an argv prompt" as "argv is the instruction, stdin is
# additional context" rather than reading the whole prompt from stdin.
_LLM_REVIEW_ARGV_INSTRUCTION = (
    "Follow the security code review task and finding list piped to you on stdin exactly. "
    "Respond with ONLY the JSON verdict block it asks for."
)

LLM_REVIEW_BACKENDS = {
    # copilot ignores piped stdin whenever `-p` is also given (it treats
    # `-p` as the entire prompt and stdin as absent), so the full prompt is
    # sent purely over stdin -- no `-p`/argv prompt at all -- for this one.
    "copilot": ["copilot", "-s", "--allow-all-tools"],
    # claude/codex both support "cat context | backend -p/exec 'instruction'"
    # (stdin becomes additional context for the argv instruction), so give
    # them a short fixed argv instruction and send the real prompt via
    # stdin instead.
    "claude": ["claude", "-p", _LLM_REVIEW_ARGV_INSTRUCTION],
    "codex": ["codex", "exec", _LLM_REVIEW_ARGV_INSTRUCTION],
}
DEFAULT_LLM_REVIEW_BACKEND = "copilot"
DEFAULT_LLM_REVIEW_TIMEOUT = 300  # seconds

_JSON_BLOCK_RE = re.compile(r"```(?:json)?\s*(\[.*?\])\s*```", re.DOTALL)


def build_llm_review_prompt(review_findings: list, repo_path) -> str:
    """Build one prompt covering every entry in `review_findings` (each a
    finding dict with a "file" key), grouped by file, plus a stable numeric
    id per finding (its position in `review_findings`) so the response can
    be matched back exactly, without fuzzy string matching.

    Deliberately does NOT embed each file's on-disk text inline (that used
    to make the prompt too large to pass safely to a CLI -- see the module
    docstring above `LLM_REVIEW_BACKENDS`). Instead this tells the backend
    to read each file itself: it's invoked with its working directory set
    to `repo_path` (see run_llm_review_backend), so paths below resolve
    exactly like a normal local checkout. `repo_path` is accepted for
    interface symmetry / future use but isn't read from here directly.
    """
    by_file = {}
    for idx, finding in enumerate(review_findings):
        by_file.setdefault(finding["file"], []).append((idx, finding))

    sections = []
    for rel_path, entries in by_file.items():
        findings_desc = "\n".join(
            f"  - id {idx}: {finding['cheatsheet']} / {finding['category']} "
            f"(confidence {finding['confidence']:.3f}): {finding.get('description', '')}"
            for idx, finding in entries
        )
        sections.append(
            f"### File: {rel_path}\nCandidate finding(s) flagged for review in this file:\n"
            f"{findings_desc}"
        )

    sections_text = "\n\n".join(sections)
    all_ids = list(range(len(review_findings)))
    return (
        "You are doing a focused security code review. Below is a list of one or more files, "
        "each with candidate security findings that an automated scanner scored as ambiguous "
        "(neither a clear pass nor a clear fail) and that need a second opinion.\n\n"
        "The repository is already checked out at your current working directory. For each file "
        "listed below, read its current on-disk contents yourself (the path is relative to your "
        "working directory) before judging the findings in it -- do not guess from the file name "
        "or description alone, and don't edit anything, just read and judge.\n\n"
        "For EVERY finding id listed below (not just some), decide whether it is a genuine issue "
        "worth failing the scan for (\"fail\") or a false positive / non-issue given the actual "
        "code (\"pass\").\n\n"
        f"{sections_text}\n\n"
        "Respond with ONLY a single fenced ```json code block and nothing else (no other text "
        "before or after it), containing a JSON array with exactly one object per finding id, in "
        "this exact shape:\n"
        '```json\n[{"id": 0, "verdict": "pass", "reason": "short reason"}, '
        '{"id": 1, "verdict": "fail", "reason": "short reason"}]\n```\n\n'
        f"All finding ids to cover: {all_ids}"
    )


def run_llm_review_backend(prompt: str, backend: str, repo_path, timeout: int, extra_args=None):
    """Invoke `backend`'s CLI non-interactively with `prompt`, run with its
    working directory set to `repo_path` (so it can read repo files itself
    exactly like a normal local checkout) and `prompt` always sent over
    stdin -- never as a CLI argument, since OS argv-length limits (e.g.
    Linux's ~128KB per-argument `MAX_ARG_STRLEN`) made that fail on
    essentially every real (multi-finding) review batch. Returns
    (stdout: str, error: str | None) -- never raises; a missing binary,
    non-zero exit, timeout, or other OS-level launch failure is reported as
    an error string so the caller can fail soft (leave findings at
    "Review") instead of crashing."""
    template = LLM_REVIEW_BACKENDS.get(backend)
    if template is None:
        return "", f"unknown LLM review backend '{backend}' (known: {', '.join(sorted(LLM_REVIEW_BACKENDS))})"

    cmd = list(template)
    if extra_args:
        cmd = cmd + list(extra_args)

    try:
        result = subprocess.run(
            cmd, cwd=str(repo_path), input=prompt, capture_output=True, text=True, timeout=timeout,
        )
    except FileNotFoundError:
        return "", f"'{cmd[0]}' executable not found on PATH"
    except subprocess.TimeoutExpired:
        return "", f"'{cmd[0]}' timed out after {timeout}s"
    except OSError as exc:
        return "", f"failed to launch '{cmd[0]}': {exc}"

    if result.returncode != 0:
        return result.stdout, f"'{cmd[0]}' exited {result.returncode}: {result.stderr.strip()[:500]}"
    return result.stdout, None


def parse_llm_review_response(raw: str) -> dict:
    """Extract a {id: {"verdict": "pass"|"fail", "reason": str}} mapping
    from a backend's raw stdout. Returns {} (never raises) if no valid
    JSON verdict array can be found, so the caller can fail soft."""
    if not raw:
        return {}

    candidates = _JSON_BLOCK_RE.findall(raw)
    if not candidates:
        # Fall back to the last top-level '[' ... ']' span in the text, in
        # case the CLI didn't use a fenced code block despite being asked to.
        start, end = raw.rfind("["), raw.rfind("]")
        if start != -1 and end != -1 and end > start:
            candidates = [raw[start:end + 1]]

    for candidate in reversed(candidates):
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if not isinstance(parsed, list):
            continue

        verdicts = {}
        for entry in parsed:
            if not isinstance(entry, dict) or "id" not in entry or "verdict" not in entry:
                continue
            try:
                finding_id = int(entry["id"])
            except (TypeError, ValueError):
                continue
            verdict = str(entry["verdict"]).strip().lower()
            if verdict not in ("pass", "fail"):
                continue
            verdicts[finding_id] = {"verdict": verdict, "reason": str(entry.get("reason", ""))}
        if verdicts:
            return verdicts
    return {}


def llm_review_findings(findings: list, repo_path, *, backend: str = DEFAULT_LLM_REVIEW_BACKEND,
                         timeout: int = DEFAULT_LLM_REVIEW_TIMEOUT, prompt_path=None,
                         response_path=None, keep_artifacts: bool = False, extra_args=None,
                         quiet: bool = False):
    """Send every "Review"-level entry of `findings` to `backend` for a
    second opinion, mutating and reclassifying each to "Pass"/"Failed"
    based on the parsed verdict (findings with no/unparseable verdict stay
    "Review"). Returns (findings, stats) -- `findings` is mutated in place
    and also returned for convenience; `stats` is a dict of counts.

    Genuinely never raises, by design: whatever goes wrong (missing
    binary, timeout, non-zero exit, unparseable response, or any other
    unexpected error e.g. disk I/O while writing the prompt/response
    files) is recorded in `stats["error"]` and leaves the affected
    findings at their current level ("Review" for anything not resolved
    by a verdict). This guarantees the caller can always go on to print a
    Failed/Review report reflecting the post-LLM-review state, even when
    the LLM step itself fails outright.
    """
    review_idx = [i for i, f in enumerate(findings) if f.get("level") == confidence_levels.LEVEL_REVIEW]
    stats = {
        "reviewed": len(review_idx),
        "reclassified": 0,
        "to_pass": 0,
        "to_failed": 0,
        "unresolved": len(review_idx),
        "error": None,
    }
    if not review_idx:
        return findings, stats

    try:
        review_findings = [findings[i] for i in review_idx]
        prompt = build_llm_review_prompt(review_findings, repo_path)

        if prompt_path:
            prompt_file = Path(prompt_path)
        else:
            fd, tmp_name = tempfile.mkstemp(prefix="repo_scan_llm_review_", suffix=".prompt.txt")
            os.close(fd)
            prompt_file = Path(tmp_name)
        prompt_file.write_text(prompt, encoding="utf-8")

        if not quiet:
            print(
                f"LLM review: {len(review_idx)} 'Review'-level finding(s) -> prompt saved to "
                f"{prompt_file}; invoking '{backend}' (timeout {timeout}s)...",
                file=sys.stderr,
            )

        raw, error = run_llm_review_backend(prompt, backend, repo_path, timeout, extra_args)

        if response_path:
            Path(response_path).write_text(raw or "", encoding="utf-8")

        if error:
            stats["error"] = error
            if not quiet:
                print(f"WARNING: LLM review failed ({error}); leaving reviewed findings at 'Review'.", file=sys.stderr)
        else:
            verdicts = parse_llm_review_response(raw)
            if not verdicts and not quiet:
                print("WARNING: LLM review response could not be parsed; leaving findings at 'Review'.", file=sys.stderr)
            for local_id, finding_idx in enumerate(review_idx):
                verdict = verdicts.get(local_id)
                if not verdict:
                    continue
                findings[finding_idx]["llm_verdict"] = verdict["verdict"]
                findings[finding_idx]["llm_reason"] = verdict["reason"]
                findings[finding_idx]["level"] = (
                    confidence_levels.LEVEL_PASS if verdict["verdict"] == "pass" else confidence_levels.LEVEL_FAILED
                )
                stats["reclassified"] += 1
                stats["unresolved"] -= 1
                if verdict["verdict"] == "pass":
                    stats["to_pass"] += 1
                else:
                    stats["to_failed"] += 1

        if not keep_artifacts and not prompt_path:
            prompt_file.unlink(missing_ok=True)
    except Exception as exc:
        # Belt-and-suspenders: anything not already handled above (e.g. an
        # OSError writing the prompt/response file) still must not prevent
        # the caller from reporting findings -- unresolved ones simply stay
        # at "Review", exactly like a handled backend failure would.
        stats["error"] = f"unexpected LLM review failure: {exc}"
        if not quiet:
            print(f"WARNING: LLM review failed unexpectedly ({exc}); leaving unresolved findings at 'Review'.", file=sys.stderr)

    return findings, stats


def add_llm_review_args(parser) -> None:
    """Add the shared --llm-review* CLI flags to an argparse parser."""
    parser.add_argument(
        "--llm-review", action="store_true",
        help="Send 'Review'-level findings to an external coding-agent CLI for a second opinion (off by default)",
    )
    parser.add_argument(
        "--llm-review-backend", choices=sorted(LLM_REVIEW_BACKENDS), default=DEFAULT_LLM_REVIEW_BACKEND,
        help=f"Which CLI to use for LLM review (default: {DEFAULT_LLM_REVIEW_BACKEND})",
    )
    parser.add_argument(
        "--llm-review-timeout", type=int, default=DEFAULT_LLM_REVIEW_TIMEOUT,
        help=f"Timeout in seconds for the LLM review CLI call (default: {DEFAULT_LLM_REVIEW_TIMEOUT})",
    )
    parser.add_argument(
        "--llm-review-prompt-path", default=None,
        help="Save the LLM review prompt to this path instead of an auto-cleaned temp file",
    )
    parser.add_argument(
        "--llm-review-response-path", default=None,
        help="Save the LLM review CLI's raw response to this path",
    )
    parser.add_argument(
        "--llm-review-arg", action="append", default=[],
        help="Extra raw argument to append to the LLM review CLI invocation (repeatable)",
    )
    parser.add_argument(
        "--keep-llm-review-artifacts", action="store_true",
        help="Don't delete the auto-generated prompt file afterward",
    )


def print_table(headers, rows) -> None:
    """Print `rows` (each a tuple of column values) as a simple aligned table."""
    if not rows:
        print("(no rows)")
        return
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
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("text", nargs="?", help="Text to route")
    parser.add_argument("--file", help="Read text to route from a file")
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.35,
        help="Minimum relevance probability to mark a cheat sheet as selected (default: 0.35)",
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

    scores = route(text)
    rows = [
        (
            ROUTES[stem]["name"],
            f"{prob:.3f}",
            "yes" if prob >= args.threshold else "",
        )
        for stem, prob in sorted(scores.items(), key=lambda kv: -kv[1])
    ]
    print_table(("cheat_sheet", "relevance", "selected"), rows)

    selected = [stem for stem, prob in scores.items() if prob >= args.threshold]
    print(
        f"\n{len(selected)}/{len(scores)} cheat sheet classifier(s) selected "
        f"at threshold {args.threshold}."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
