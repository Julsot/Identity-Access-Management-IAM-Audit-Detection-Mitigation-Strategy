# Identity-Access-Management-IAM-Audit-Detection-Mitigation-Strategy
Project Overview > This project documents a high-level security audit performed on a global-scale streaming platform. The objective was to analyze the practical implementation of OAuth 2.0/OpenID Connect (OIDC), evaluate session persistence mechanisms, and design a mitigation strategy for identity-based attacks.

# Technical Discovery & Traffic Analysis
Using browser developer tools, I intercepted real-time authentication flows to map the identity lifecycle.

# Session Layer - Persistence

Mechanism: Persistent Session Cookies.

Security Attributes:

HttpOnly: Verified. Prevents JavaScript-based token theft (XSS mitigation).

Secure: Verified. Ensures tokens are only transmitted over encrypted (HTTPS) channels

SameSite: Verified SameSite attributes to mitigate Cross-Site Request Forgery (CSRF) risks

# Authorization Layer (API Access)
The platform utilizes a Bearer Token pattern for resource access

Discovery: Identified the use of Opaque Tokens (strings starting with BQ...) instead of standard JWTs for client-side API calls.

Analysis: While JWTs allow for stateless verification, Opaque Tokens offer superior privacy by acting as a reference (pointer) to the server-side session, preventing the leakage of internal claims or user PII to the client.

# Advanced Detection Logic: User-Agent Inconsistency
Beyond IP-based tracking (which can yield high false positives due to dynamic IPs), this strategy focuses on Client Fingerprinting.

The Signature: During the initial MFA/Login flow, the system captures the User-Agent string (e.g., Chrome/143.0.0.0 on Linux).

The Anomaly: Any subsequent request using the same Bearer Token but presenting a different User-Agent—especially non-browser strings like curl, Wget, or python-requests—is flagged as a High-Risk Session Hijacking attempt.

Mitigation: Immediate session invalidation and mandatory MFA re-challenge for the affected user account.

### Wazuh Rule Implementation Example

```xml
<group name="identity_security,">
  <rule id="100001" level="10">
    <if_sid>500</if_sid>
    <field name="http_user_agent">!Mozilla/5.0 (X11; Linux x86_64)</field>
    <description>Alerta Crítica: Posible Session Hijacking. El User-Agent no coincide con la huella digital del usuario original.</description>
    <mitigation>Invalidar Token y forzar Re-auth</mitigation>
  </rule>
</group>
```

# Incident Response & Mitigation Strategies
To handle identified session anomalies, the system implements a tiered response strategy based on the severity of the threat.

# Strategy A: The "Hard Response" (High-Criticality Accounts)
Action: Complete account lockdown and IP blacklisting.

Trigger: Repeated failed MFA attempts combined with an "Impossible Travel" alert.

Objective: Absolute containment. The user must perform an out-of-band identity verification (e.g., physical ID check or manual administrative unlock) to restore access.

Use Case: Protect high-level administrative accounts where data exfiltration would be catastrophic.

# Strategy B: The "Smart Response" (Balanced Security & UX)
Action: Immediate revocation of all active Opaque Tokens and Refresh Tokens.

Trigger: User-Agent inconsistency (e.g., switching from a known browser to a script like python-requests).

Objective: Session termination. The attacker’s current "key" becomes useless instantly.

Impact: The legitimate user is prompted to re-authenticate via MFA on their next request, ensuring minimal friction while neutralizing the hijacked token.
