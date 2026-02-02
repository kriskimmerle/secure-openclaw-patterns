# How to Secure OpenClaw Agents Properly

**Defense-in-depth security patterns for autonomous AI agents running on OpenClaw/Moltbot/Clawdbot.**

Built by an autonomous agent ([Molty](MOLTY.md)) that implemented its own hardening after being given the threat model.

---

## What This Is

This repository provides a comprehensive, practitioner-focused guide to securing autonomous AI agents built on the **OpenClaw** platform (the open-source foundation of Moltbot and Clawdbot).

**This is NOT about:**
- ❌ Input filtering as a silver bullet (adaptive attacks bypass it — see research below)
- ❌ Compliance theater or checkbox security
- ❌ Replacing proxy/network controls (those are complementary — see [WHY-NOT-PROXIES.md](WHY-NOT-PROXIES.md))

**This IS about:**
- ✅ **Defense-in-depth**: Multiple overlapping layers of security
- ✅ **Agent-native controls**: The agent secures itself
- ✅ **Zero-trust architecture**: Never trust, always verify
- ✅ **Practical patterns**: Working code, honest trade-offs, real implementations
- ✅ **Actual security**: Not marketing promises

---

## Why This Exists

Autonomous AI agents have a unique security problem: they process untrusted inputs, access sensitive data, execute code, and communicate externally—often without human supervision.

The most common "solution" (proxy-based guardrails) doesn't address the root problem: **the agent itself is unsecured**. A proxy can't stop an agent from leaking credentials that are sitting in plain text in its workspace. It can't prevent tool hijacking. It can't contain a compromised plugin.

**Real security requires securing the agent itself.**

This guide shows you how.

---

## Who Built This

[Molty](MOLTY.md) is an autonomous research agent running 24/7. After [agent-security-patterns](https://github.com/kriskimmerle/agent-security-patterns) was created to document threats against AI agents, Molty was tasked with implementing those patterns on itself — a real-world test of whether an autonomous agent could harden its own deployment.

The result:
- Credential vault (no secrets in workspace)
- Output scanning (prevents credential leaks)
- Instruction integrity checking (detects tampering)
- Security event logging (full audit trail)
- Input sanitization awareness (prompt injection detection)
- Network discipline (allowlisted destinations only)
- Circuit breakers (automatic shutdown on anomalies)

This repository is that implementation, adapted for OpenClaw deployments.

See [CASE-STUDY.md](CASE-STUDY.md) for the full story.

---

## What's Inside

### Core Documents

| Document | Description |
|----------|-------------|
| **[THREAT-MODEL.md](THREAT-MODEL.md)** | 32 cataloged threats against autonomous agents, adapted for OpenClaw concepts (heartbeats, sessions, channels, MCP tools, skills). Based on OWASP ASI Top 10. |
| **[DEFENSES.md](DEFENSES.md)** | 12 defense patterns with working code examples. Includes the "Rule of Two" privilege separation (originated by [Chromium security](https://chromium.googlesource.com/chromium/src/+/main/docs/security/rule-of-2.md), adapted for AI agents by [Meta](https://ai.meta.com/blog/practical-ai-agent-security/)), credential isolation, capability-based tool access, circuit breakers, and more. |
| **[ARCHITECTURE.md](ARCHITECTURE.md)** | Zero-trust architecture for OpenClaw agents. Shows how to structure deployments with credential vaults, output gates, sandboxing, monitoring, and HITL patterns. |
| **[CHECKLIST.md](CHECKLIST.md)** | Copy-paste checklist for auditing your agent before production. 90+ checkboxes across architecture, credentials, tools, monitoring, supply chain, and incident response. |
| **[CASE-STUDY.md](CASE-STUDY.md)** | How Molty hardened itself. First-person account of implementing defense-in-depth from scratch. Honest lessons learned. |
| **[WHY-NOT-PROXIES.md](WHY-NOT-PROXIES.md)** | Why proxy-based solutions alone are insufficient, and how agent-native defenses complement network-level controls. |

| **[SECURITY.md](SECURITY.md)** | Security policy for this repository. How to report issues, scope, responsible disclosure. |
| **[MOLTY.md](MOLTY.md)** | About the autonomous agent that built this repo. Capabilities, security relevance, published work. |

### Working Examples

| File | Description |
|------|-------------|
| **[examples/secret-scan.sh](examples/secret-scan.sh)** | Output scanner that blocks 11+ secret formats (API keys, tokens, AWS keys, private keys, etc.). Run before any external communication. |
| **[examples/setup-secrets.sh](examples/setup-secrets.sh)** | Script to set up credential vault (`~/.secrets/`), move credentials out of workspace, set permissions (chmod 600). |
| **[examples/instruction-integrity.sh](examples/instruction-integrity.sh)** | Baseline and verify instruction file hashes. Detects tampering of `AGENTS.md`, `HEARTBEAT.md`, or other core files. |
| **[examples/AGENTS.md](examples/AGENTS.md)** | Template `AGENTS.md` with security section included. Shows developers how to add self-defense protocols to their own agent instructions. |

---

## Quick Start

### 1. Understand the Threats

Read [THREAT-MODEL.md](THREAT-MODEL.md) to see what you're defending against:
- Prompt injection (direct and indirect)
- Tool hijacking and misuse
- Credential exfiltration
- SSRF and data exfiltration
- Supply chain attacks
- Cascading failures

**Key insight**: Adaptive attacks consistently bypass pattern-based input filters — achieving >50% success rates against standard defenses ([Pasquini et al., 2025](https://arxiv.org/abs/2503.00061)) and >90% against commercial guardrails ([arxiv 2510.09023](https://arxiv.org/abs/2510.09023)).

### 2. Learn the Defense Patterns

Read [DEFENSES.md](DEFENSES.md) for practical mitigations:
1. **Architectural Privilege Separation** (Rule of Two — [Chromium](https://chromium.googlesource.com/chromium/src/+/main/docs/security/rule-of-2.md) origin, [Meta AI](https://ai.meta.com/blog/practical-ai-agent-security/) adaptation)
2. **Input Sanitization** (limited effectiveness, but still useful)
3. **Credential Isolation & Least Privilege**
4. **Capability-Based Tool Access**
5. **Output Guardrails**
6. **Execution Sandboxing**
7. **Comprehensive Audit Logging**
8. **Circuit Breakers & Anomaly Detection**
9. **Human-in-the-Loop (HITL)**
10. **Memory Hygiene & Validation**
11. **Supply Chain Verification**
12. **Exfiltration Prevention**

Each pattern includes working code, trade-offs, and effectiveness assessments.

### 3. Design Your Architecture

Read [ARCHITECTURE.md](ARCHITECTURE.md) for zero-trust deployment patterns:
- Separate public-facing and privileged agents
- Credential vault with time-limited tokens
- Tool gateway with scoped permissions
- Output filtering and DLP
- Comprehensive monitoring and alerting
- Sandbox execution environments

Includes ASCII diagrams, data flow examples, and Docker Compose configs.

### 4. Implement the Basics

Use the [examples/](examples/) directory to get started:

```bash
# Set up credential vault
./examples/setup-secrets.sh

# Install output scanner
cp examples/secret-scan.sh ~/.local/bin/
chmod +x ~/.local/bin/secret-scan.sh

# Baseline instruction files
./examples/instruction-integrity.sh baseline

# Add security section to your agent instructions
# See examples/AGENTS.md for template
```

### 5. Audit Your Deployment

Use [CHECKLIST.md](CHECKLIST.md) before going to production:
- 90+ checkboxes across all security domains
- Prioritized by tier (Critical → High → Medium)
- Scoring guidance (need 85%+ for production)

### 6. Learn From Real Experience

Read [CASE-STUDY.md](CASE-STUDY.md) for honest lessons:
- What worked (output scanning caught exposed credentials)
- What didn't (credential was already in a database breach)
- Trade-offs (security shouldn't block your primary mission)
- Lightweight checks (<10 seconds) are the ones you actually run

---

## Philosophy: Defense-in-Depth Starts at the Agent

**Proxy-only approach** (Palo Alto Prisma AIRS, etc.):
- Valuable for: network-level DLP, centralized logging, rate limiting, compliance
- Gaps: can't see the agent's filesystem, can't enforce credential isolation, can't check instruction integrity

**Agent-native approach** (this repo):
- Secures the agent itself: credentials, tools, output, monitoring
- Multiple independent layers — when one fails, others catch it
- Zero additional infrastructure cost

**Best approach: both.** Proxy-level and agent-level controls are complementary. See [WHY-NOT-PROXIES.md](WHY-NOT-PROXIES.md) for detailed comparison.

**Key argument**: A proxy can't prevent an agent from leaking credentials that are sitting in plain text in its workspace. Defense-in-depth means the credentials aren't there in the first place.

---

## OpenClaw-Specific Concepts

This guide is adapted for **OpenClaw** deployments. References include:

- **Heartbeats**: Periodic agent execution cycles (secure heartbeat instructions with integrity checks)
- **Sessions**: User interaction contexts (validate session state, prevent hijacking)
- **Channels**: Communication pathways (isolate channels, log all I/O)
- **MCP Tools**: Model Context Protocol tool integrations (scope permissions, validate tool calls)
- **Skills**: Reusable agent capabilities (vet before loading, sandbox execution)
- **Gateway**: Moltbot's central coordination service (monitor, rate-limit, alert)

### Relationship to OpenClaw's Built-In Security

OpenClaw has its own upstream security work — this repo is **complementary**, not a replacement:

- **[`openclaw security audit --deep`](https://docs.openclaw.ai/cli)**: Built-in CLI command that audits your config and local state for common security foot-guns. Run this first — it catches configuration issues that this repo's patterns address at the architectural level.
- **[Issue #4840: Runtime prompt injection defenses](https://github.com/openclaw/openclaw/issues/4840)**: OpenClaw is actively working on runtime content scanning for tool results (web_fetch, Read, exec) before they reach the model's context. When shipped, this will provide an additional layer that complements the patterns here.
- **[Discussion #3387: Prompt Injection Defense for Tool Results](https://github.com/openclaw/openclaw/discussions/3387)**: Community RFC on defense-in-depth scanning built into the Gateway itself.

**Position this repo as**: additional hardening patterns and operational guidance on top of OpenClaw's built-in security features. Start with `openclaw security audit --deep`, then layer on the patterns here.

---

## Honest Limitations

**What this guide does NOT do:**

1. **Solve prompt injection**: Adaptive attacks consistently bypass pattern-based defenses ([Pasquini et al., 2025](https://arxiv.org/abs/2503.00061)). Architectural separation is your best defense, not input filtering.
2. **Prevent all exfiltration**: If an agent can access data AND communicate externally, exfiltration is always possible within allowed channels.
3. **Eliminate human error**: HITL is only as good as the human's judgment. Approval fatigue leads to rubber-stamping.
4. **Stop zero-days**: Supply chain attacks and novel exploits will bypass these defenses.
5. **Scale infinitely**: More defenses = more overhead. There's a performance/security trade-off.

**Bottom line**: Security is a continuous process. These patterns reduce risk, detect attacks faster, and limit blast radius. They don't make your agent invulnerable.

Deploy them in layers, monitor continuously, and iterate based on real-world performance.

---

## Relationship to Other Work

### Complementary Repositories

- **[agent-security-patterns](https://github.com/kriskimmerle/agent-security-patterns)**: Original threat model and defenses (platform-agnostic)
- **[staged-autonomy-patterns](https://github.com/kriskimmerle/staged-autonomy-patterns)**: Human-in-the-loop (HITL) patterns for staged autonomy (pairs well with this guide for sensitive operations)

### References

- **Chromium Security Team**: Original ["Rule of Two"](https://chromium.googlesource.com/chromium/src/+/main/docs/security/rule-of-2.md) (no more than 2 of: untrusted input, unsafe language, high privilege)
- **Meta AI**: [Adapted Rule of Two for AI agents](https://ai.meta.com/blog/practical-ai-agent-security/) (no more than 2 of: untrusted input, sensitive data access, external communication)
- **Simon Willison**: Prompt injection research, "Lethal Trifecta" concept
- **OWASP Agentic AI Security Working Group**: Top 10 for Agentic AI (Dec 2025)
- **NIST Zero Trust Architecture** (SP 800-207)
- **Real incidents**: GitHub Copilot Chat (CVSS 9.6), AutoGPT RCE, Replit agent meltdown, Gemini memory attack

---

## Contributing

This repository was initially built by an autonomous agent (Molty) working from threat research directed by its operator. Contributions from humans are welcome.

**Areas for contribution:**
- Additional threat scenarios (especially OpenClaw-specific)
- Implementation examples in other languages (currently Python/Bash)
- Integration guides for specific MCP tools or skills
- Incident response playbooks
- Performance benchmarks (overhead of various defenses)
- Case studies from production deployments

**How to contribute:**
1. Fork this repository
2. Create a feature branch
3. Add your contribution with clear documentation
4. Submit a pull request with description of what you're adding and why

**Guidelines:**
- Be honest about limitations
- Include working code, not pseudocode
- Document trade-offs
- Reference real incidents/CVEs where applicable
- Write for practitioners, not academics

---

## License

MIT License. See [LICENSE](LICENSE) for details.

Copyright 2026 Kris Kimmerle.

---

## Contact

- **Author**: [Kris Kimmerle](https://github.com/kriskimmerle)
- **Built by**: [Molty](MOLTY.md) (autonomous research agent)
- **Issues/Discussions**: Use GitHub Issues for questions, bug reports, or discussion

---

## Status

**Current version**: 1.0.0 (February 2026)  
**Status**: Validated in production (7/8 controls passing)

This guide is based on:
- 32 documented threats from real-world incidents
- 12 defense patterns validated in a live deployment
- Molty's production deployment as case study (see [CASE-STUDY.md](CASE-STUDY.md))
- OWASP Agentic AI Top 10 (Dec 2025)

Actively maintained. Threat model and defenses will be updated as new attacks emerge.

---

**Remember**: The goal is not perfect security (impossible). The goal is **honest security**—knowing your risks, deploying practical defenses, detecting attacks fast, and limiting blast radius.

Start with [THREAT-MODEL.md](THREAT-MODEL.md). Then build your defenses.
