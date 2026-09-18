"""Cheat sheet relevance router built on the TypeSafe System One API.

Given an input (source code, text, a request, etc.), decides which of the
122 per-cheat-sheet classifiers under `classifiers/` are actually relevant,
so callers (see run_all_classifiers.py) don't have to run all 122 Noul
classifiers on every input -- e.g. skip the Django/Laravel/Ruby on Rails
classifiers entirely for a plain .java file.

This follows the "speculative fan-out" pattern
(https://docs.typesafe.ai/patterns/fan-out.md): every cheat sheet's
applicability is asked as one Noul question, and all ~122 questions are sent
in a single parallel system_one() call, since parallel questions add
~no extra latency. Code (not the model) then decides which classifiers to
actually run based on each Noul's probability.

Usage:
    python router.py "some text to route"
    python router.py --file path/to/content.txt
    python router.py --file bad.java --threshold 0.4
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Registry: classifier module stem -> {name, url, applies_when} -------
# `applies_when` is a short scope description of when this cheat sheet's
# guidance is relevant, used to build each routing Noul's instructions.
# Keys match classifiers/<stem>.py module stems exactly (see
# run_all_classifiers.py's discover_classifier_paths()).
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
                        f"Does the '{info['name']}' OWASP cheat sheet apply to "
                        f"reviewing this content? It applies when the content "
                        f"involves: {info['applies_when']}."
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
