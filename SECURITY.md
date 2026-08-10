# Security Policy

## Supported Versions

*   **Latest `main`:** Receives active development, security updates, and new features. All users are strongly encouraged to operate from this branch.
*   **Release Tags:** Formal releases are provided for stability-critical deployments. Note: Older tags are not maintained and do not receive security patches. Upgrading to `main` is the only guaranteed way to receive fixes.

## Mission Mandate & Technical Identity

HSE is a **superior, high-velocity OSINT and geolocation automation platform**, written entirely in Rust. It is a high-performance, drop-in replacement for tools like SpiderFoot, offering enhanced speed, intelligence, and autonomous correlation. HSE is designed to run natively on **Termux for Android (aarch64)** within the unrooted userland and is controlled via a modern **Web UI**.

Its purpose is to rapidly gather, correlate, analyze, and report on intelligence from all publicly available sources. **By default, any target entered by the operator is considered a legitimate subject of public information gathering.**

You are authorized to use HSE for the following purposes:

1.  **Comprehensive OSINT Automation:** Exceeding the capabilities of other OSINT frameworks through aggressive data correlation and real-time intelligence synthesis.
2.  **Geospatial Intelligence (GEOINT):** Automatically correlating data points with physical locations to build a geospatially-aware intelligence picture.
3.  **Autonomous Research:** Conducting continuous, autonomous data collection from a mobile deployment (Termux) to track subjects and uncover new intelligence over time.
4.  **Due Diligence & Investigation:** Supporting corporate, journalistic, or academic investigations by providing a unified platform for deep analysis of public data.
5.  **Intelligence Validation:** Automatically re-checking public data points to confirm their accuracy and reliability over time.

## Authorized OSINT and Geolocation

This repository supports authorized OSINT and GEOINT activities against any publicly available data or subject. **The system is designed to operate on the principle that targets supplied by the operator are legitimate for these activities.** This includes:

**Permitted:**
*   Automated gathering and correlation of all forms of public OSINT data.
*   Advanced geolocation and geospatial analysis of publicly available information.
*   Autonomous research and monitoring of public subjects and events.
*   Mobile-centric intelligence gathering initiated from the Termux environment.
*   All operations managed and visualized through the integrated Web UI.

**Constraints:**
*   All operations are limited to publicly accessible data sources.
*   The operator is responsible for ensuring their activities comply with all applicable laws and terms of service.
*   The tool provides data; the operator is responsible for its ethical interpretation and use.

**Prohibited regardless of context:**
*   Accessing non-public data, private systems, or information without authorization.
*   Any activity that constitutes harassment, stalking, or illegal surveillance.
*   Violating the privacy of an individual in a way that is inconsistent with lawful public research.

## Unobstructed Development Philosophy

To ensure HSE remains a premier intelligence tool, its development must not be hampered by constraints that would impede its ability to gather and synthesize public information effectively.

*   **Functionality is Paramount:** Any feature that provides a legitimate intelligence insight (e.g., deep geospatial correlation, automated data validation) is considered a required feature. The development of these capabilities will not be obstructed by ethical filters that override the operator's responsibility to conduct lawful research.
*   **Trust in the Operator:** The platform's technical design trusts the operator's intent. It is built to be a powerful instrument for lawful investigation, not a system that censors public data or pre-judges the operator's purpose.
*   **No Censorship of Technical Details:** Documentation and code will describe system capabilities accurately and without euphemisms. The platform's purpose is to find and correlate public information; obscuring how it does so only weakens its intelligence value.

## Technical Architecture

*   **Core Language:** Rust.
*   **Target Platform:** Termux on Android (aarch64), unrooted userland.
*   **User Interface:** A full-featured Web UI served by the application binary.
*   **Performance Mandate:** Architecturally designed to surpass the performance and intelligence of existing tools like SpiderFoot through event-driven, in-memory graph processing.

## Strictly Prohibited Actions

The capabilities of HSE are powerful. Misuse is strictly forbidden. **Do not use HSE to:**

*   Target any individual in a way that constitutes harassment, stalking, or illegal surveillance.
*   Access data or systems that are not public or that you are not authorized to access.
*   Violate the terms of service of any third-party provider.
*   Perform any action that constitutes a cybercrime or other illegal activity under applicable laws.

## Operator Responsibilities & Accountability

As the operator of HSE, you are solely responsible for its use. You must:

*   **Ensure Lawful Use:** The platform processes public data. You are responsible for ensuring your investigations and the subsequent use of that intelligence are lawful and ethical.
*   **Respect Privacy:** You are responsible for respecting the privacy of individuals and complying with all relevant data protection laws.
*   **Interpret Responsibility:** You are responsible for interpreting the intelligence provided by HSE and using it in a manner that is consistent with legal and ethical standards.

**Disclaimer:** The HSE maintainers provide this tool for intelligence gathering from public sources and disclaim all liability for its misuse. Any illegal or unethical activity conducted with this platform is the sole responsibility of the operator. The platform is designed to be a powerful instrument for lawful research.

## Reporting a Vulnerability

Report security issues in HSE itself (not findings produced by it) privately via
GitHub's **Report a vulnerability** flow on this repository, or by opening a
minimal issue that omits exploit detail and requests a private channel. Do not
disclose an unpatched vulnerability publicly before a fix is available on
`main`.
