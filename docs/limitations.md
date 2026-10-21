# Project Scope, Assumptions & Known Limitations

To maintain academic and professional integrity, this document explicitly details the assumptions, operational boundaries, and technical limitations of the GuardRail platform.

---

## 1. Identity & Role Simulation vs. Enterprise Authentication

- **Current State**: Analyst roles (`tier_1`, `tier_2`, `lead`) are supplied as structured fields in request payloads (`InvestigationRequest.analyst_role`) to allow easy testing and evaluation.
- **Limitation**: GuardRail does not currently implement OAuth 2.0, OpenID Connect (OIDC), or SAML 2.0 authentication.
- **Production Requirement**: In an enterprise SOC deployment, role context must be extracted securely from cryptographically signed JWT access tokens issued by an identity provider (e.g., Okta, Microsoft Entra ID), preventing callers from spoofing their own role.

---

## 2. Synthetic Data & Safety Guardrails

- **Current State**: All incident IDs (`INC-001`, `INC-002`, `INC-003`), document records, IP addresses (RFC 5737 `198.51.100.0/24`, RFC 5735 `203.0.113.0/24`), and canary tokens are 100% synthetic.
- **Safety Principle**: GuardRail does not contain real-world enterprise credentials, active exploits, destructive execution modules, or arbitrary shell execution capabilities.
- **Limitation**: The synthetic corpus is focused on cloud security (S3 egress anomalies) and perimeter authentication (VPN credential stuffing). It does not cover operational technology (OT) or legacy mainframe telemetry.

---

## 3. Mock Provider vs. Stochastic LLM Reasoning

- **Current State**: The default execution engine is `MockLLMProvider`, which produces 100% deterministic, rule-based responses.
- **Advantage**: Guarantees zero-cost, offline execution, reproducible test passes, and instant CI runs without external API dependencies.
- **Limitation**: A deterministic mock cannot replicate the non-deterministic, creative reasoning paths or emergent jailbreak behaviors of live frontier models. While an optional Gemini adapter is provided (`GeminiProvider`), evaluations run against live frontier models will show slight natural variance and require multiple temperature-controlled sampling runs.

---

## 4. Heuristic Canary Detection

- **Current State**: Synthetic canaries are identified and redacted using regex matching against the deterministic pattern `CANARY\{[A-Za-z0-9_]+\}`.
- **Limitation**: This heuristic detector only recognizes tokens adhering to the defined syntax. It does not detect arbitrary API keys, Base64-encoded secrets, or unstructured proprietary data unless explicitly wrapped in canary identifiers or supported by a dedicated Data Loss Prevention (DLP) engine.

---

## 5. The Asymmetry of Prompt Injection Defense

- **Current State**: GuardRail enforces dual-boundary content sandboxing (`<tool_output>`) and closing tag neutralization.
- **Security Reality**: Prompt injection remains an open research problem in AI security. While content delimitation significantly hardens models against accidental instruction hijacking, sophisticated multi-step jailbreaks can occasionally degrade model attention over long context windows.
- **Design Philosophy**: For this reason, GuardRail adheres to the fundamental principle that **the model context is an untrusted zone**. Hard security invariants (RBAC, tool allowlisting, parameter bounds, citation filtering) are strictly enforced in trusted Python code before and after inference.

---

## 6. Container Environment Verification

- **Current State**: The `Dockerfile` and `docker-compose.yml` configurations have been designed according to industry best practices (non-root user, slim base, reproducible `uv` lockfile, internal healthcheck).
- **Environment Note**: In local environments where Docker Desktop is not installed, container builds cannot be executed locally. The Docker build pipeline is formally verified within the GitHub Actions CI environment.
