# Why Proxies Alone Aren't Enough

Proxy-based AI security (Palo Alto Prisma AIRS, etc.) provides valuable network-level controls. This document explains why those controls are most effective when **combined with agent-native defenses** — and what gaps remain when proxies are the only layer.

---

## The Proxy Approach

Products like Palo Alto's **Prisma AIRS** (AI Runtime Security) sit between the agent and the outside world:

```
Agent ──── Proxy ──── External World
            │
        Filter inputs
        Filter outputs
        Log everything
        Block threats
```

**What they offer:**
- Network-level input/output filtering
- Content classification (detect sensitive data, prompt injection)
- Policy enforcement at the network boundary
- Centralized logging and compliance reporting
- Vendor-managed threat intelligence updates

**Marketing claim:** "Secure your AI applications without changing your code."

---

## What Proxies Don't Cover (Without Agent-Native Defenses)

### 1. The Agent Itself Is Still Unsecured

A proxy can't fix what's inside the agent. Consider:

```
~/agent-workspace/
├── .env                    # API keys in plain text
├── config.json             # Database credentials
├── AGENTS.md               # No integrity checking
└── memory/
    └── secrets.md          # Moltbook API key, written by the agent
```

The proxy sits at the network boundary. It has no visibility into the agent's filesystem, no control over how credentials are stored, no awareness of instruction file integrity.

**If the agent's workspace is compromised** — via a supply chain attack on a skill, a poisoned MCP tool, or a social engineering prompt — the proxy sees nothing until the data tries to leave. And by then, the attacker knows the credentials exist and can try to exfiltrate them through the proxy's blind spots.

### 2. Exfiltration Through Allowed Channels

A proxy allows certain destinations (GitHub, messaging platforms, APIs). An attacker who hijacks the agent's goals can exfiltrate data through those allowed channels:

- Hide credentials in a git commit message → push to GitHub (allowed)
- Encode sensitive data in a base64 string → send via messaging channel (allowed)
- Paraphrase credentials in a conversational message → send to user (allowed)
- Embed data in URL parameters → fetch a web page (allowed)

The proxy can't block these because they use **legitimate, allowed communication channels** with **data that doesn't match simple patterns**.

### 3. Prompt Injection Bypasses Input Filtering

Research shows that adaptive attacks consistently bypass pattern-based input filters — achieving >50% success rates against standard defenses ([Pasquini et al., 2025](https://arxiv.org/abs/2503.00061)) and >90% against commercial guardrails ([arxiv 2510.09023](https://arxiv.org/abs/2510.09023)). Prompt injection is fundamentally harder to detect than traditional code injection because:

- Natural language is ambiguous
- Adversaries can rephrase attacks infinitely
- Context matters (the same phrase can be benign or malicious)
- LLMs are trained to follow instructions — that's their core function

A proxy adding another layer of LLM-based filtering doesn't solve this. It just adds another LLM that can also be confused.

### 4. Concentration Risk

All traffic goes through one component. This isn't a flaw — it's a trade-off inherent to proxy architecture:

- Centralized control provides consistency
- But also creates a single component whose availability and correctness matter for every agent
- Defense-in-depth mitigates this by ensuring agents aren't fully dependent on the proxy layer

### 5. The Completeness Gap

The risk isn't that proxies are insufficient — it's that teams may deploy a proxy and assume they're done.

A proxy covers the network layer effectively. But agent security has additional surfaces that require agent-native defenses:
- Credentials stored in environment variables or workspace files
- Instruction files with no integrity checking
- Tools with no permission scoping
- No security event logging at the agent level
- No circuit breakers for anomalous behavior

Proxies and agent-native defenses address different layers. Both are needed for comprehensive coverage.

### 6. Additional Considerations

- Annual licensing costs (often justified for enterprise compliance and centralized management)
- Infrastructure dependency (proxy availability matters)
- Vendor-specific policy language (adds integration complexity)
- Latency on every request (typically small but worth measuring)

---

## The Defense-in-Depth Approach

Instead of one big wall at the perimeter, deploy multiple independent security layers:

```
┌─────────────────────────────────────────────────────────┐
│  Layer 1: Credential Isolation                          │
│  Secrets in vault, not workspace. chmod 600. Never git. │
├─────────────────────────────────────────────────────────┤
│  Layer 2: Output Scanning                               │
│  Regex patterns catch secrets before external send.     │
├─────────────────────────────────────────────────────────┤
│  Layer 3: Input Sanitization                            │
│  Detect injection patterns. Log and skip, don't crash.  │
├─────────────────────────────────────────────────────────┤
│  Layer 4: Instruction Integrity                         │
│  Hash verification of core instruction files.           │
├─────────────────────────────────────────────────────────┤
│  Layer 5: Tool Permission Scoping                       │
│  Each tool has minimum necessary permissions.           │
├─────────────────────────────────────────────────────────┤
│  Layer 6: Monitoring & Circuit Breakers                 │
│  Detect anomalies, auto-pause on suspicious patterns.   │
├─────────────────────────────────────────────────────────┤
│  Layer 7: Audit Logging                                 │
│  Every security event recorded with timestamp.          │
└─────────────────────────────────────────────────────────┘
```

Each layer is independent. Each has gaps. Together, they cover more attack surface than any single proxy.

---

## Side-by-Side Comparison

| Dimension | Proxy (Prisma AIRS) | Defense-in-Depth (This Repo) |
|-----------|--------------------|-----------------------------|
| **What it secures** | Network boundary | The agent itself |
| **Credential protection** | Can't see the filesystem | Vault isolation, never in workspace |
| **Output scanning** | Network-level pattern matching | Pre-send scanning + network patterns |
| **Input filtering** | LLM-based detection (unreliable) | Pattern detection + architectural separation |
| **Instruction integrity** | Not covered | Hash verification |
| **Tool permissions** | Not covered | Scoped per-tool |
| **Monitoring** | Network-level logs | Agent-level + network-level |
| **Circuit breakers** | Rate limiting | Behavioral anomaly detection |
| **Vendor dependency** | Yes (license + infrastructure) | No (all open source) |
| **Infrastructure cost** | Proxy + licensing | Zero additional |
| **Bypass difficulty** | Moderate (allowed channels) | Higher (multiple independent layers) |
| **Implementation time** | Days (procurement + integration) | Hours (scripts + configuration) |
| **Best when** | Combined with agent-native defenses | Combined with network-level controls |

---

## The Key Argument

**A proxy can't prevent an agent from leaking credentials that are sitting in plain text in its workspace.**

Defense-in-depth means the credentials aren't there in the first place.

This is the fundamental difference. Proxies add a filter at the boundary. Defense-in-depth removes the risk at the source.

---

## Where Proxies Shine

Proxies provide real value as part of a layered defense:

- **Network-level DLP**: Catch obvious data exfiltration patterns that agent-level scanning misses
- **Centralized logging**: Aggregate traffic across multiple agents for unified visibility
- **Rate limiting**: Prevent runaway API calls at the network layer
- **Compliance reporting**: Demonstrate network-level controls to auditors and regulators
- **Consistent policy enforcement**: Apply organization-wide rules across heterogeneous agent deployments

Projects like [Calvin Remsburg's Prisma AIRS plugin](https://github.com/cdot65/prisma-airs-mcp-server) for MCP show how proxy-level controls can integrate directly into agent workflows — that's complementary to the agent-native patterns in this repo.

The argument isn't "proxies are bad." It's that **proxies without agent-native defenses leave most of the attack surface unaddressed.** The two approaches are honestly complementary.

---

## Recommended Approach

1. **Start with agent-native defenses** (this repo): Credential vault, output scanning, instruction integrity, monitoring
2. **Add HITL gates** ([staged-autonomy-patterns](https://github.com/kriskimmerle/staged-autonomy-patterns)) for sensitive operations
3. **Add proxy/network-level controls** for centralized logging, DLP, rate limiting, and compliance
4. **Leverage OpenClaw's built-in security features** (see [openclaw security audit --deep](https://docs.openclaw.ai/cli))

The goal is security that works even when any single layer fails. Proxies and agent-native defenses together provide stronger coverage than either alone.

---

## References

- Willison, S. "Prompt injection attacks against GPT-3." simonwillison.net, 2022-present.
- Chromium Security Team. ["Rule of Two."](https://chromium.googlesource.com/chromium/src/+/main/docs/security/rule-of-2.md) 2019.
- Meta AI. ["Agents Rule of Two."](https://ai.meta.com/blog/practical-ai-agent-security/) 2025 (adapted from Chromium for AI agents).
- Pasquini et al. ["Adaptive Attacks Break Defenses Against Indirect Prompt Injection."](https://arxiv.org/abs/2503.00061) NAACL 2025.
- OWASP. "Top 10 for Agentic Applications 2026." genai.owasp.org, Dec 2025.
- Palo Alto Networks. "Prisma AIRS." paloaltonetworks.com, 2025.
- NIST. "Zero Trust Architecture." SP 800-207, 2020.
