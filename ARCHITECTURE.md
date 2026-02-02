# Zero-Trust Architecture for OpenClaw Agents

Reference architecture for securing autonomous AI agents built on OpenClaw/Moltbot/Clawdbot, based on defense-in-depth and privilege separation principles.

**Design Philosophy**: 
- Assume breach at every layer
- Minimize trust boundaries
- Explicit authorization for every action
- Comprehensive observability
- Fail secure by default

**Based on**: [Chromium's Rule of Two](https://chromium.googlesource.com/chromium/src/+/main/docs/security/rule-of-2.md) (original, adapted for AI agents by [Meta](https://ai.meta.com/blog/practical-ai-agent-security/)), OWASP Agentic AI Top 10, NIST Zero Trust Architecture (SP 800-207), real-world deployment (Molty)

---

## High-Level OpenClaw Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                          MONITORING LAYER                               │
│  security-log.md • Gateway logs • Anomaly detection • Alerts           │
└────────────────────────────────────────────────────────────────────────┘
         ▲               ▲               ▲               ▲
         │               │               │               │
    ┌────┴────┐     ┌────┴────┐     ┌────┴────┐    ┌────┴────┐
    │ Input   │     │  Tool   │     │ Output  │    │  Human  │
    │ Filter  │     │ Policy  │     │  Gate   │    │ Approval│
    └────┬────┘     └────┬────┘     └────┬────┘    └────┬────┘
         │               │               │               │
         ▼               ▼               ▼               ▼
┌────────────────────────────────────────────────────────────────────────┐
│                 PUBLIC AGENT (Untrusted Zone)                          │
│  - Monitors channels (WhatsApp, Telegram, Slack)         (A)          │
│  - Uses web_fetch, browser for research                  (A)          │
│  - Can message.send to approved destinations             (C)          │
│  - NO access to ~/.secrets/                              (not B)      │
│  - NO access to sensitive paths                          (not B)      │
│  - Sandboxed execution (limited file/network access)                  │
└────────────────────────────────────────────────────────────────────────┘
                              │
                              │ Structured requests only
                              │ (no raw prompts passed through)
                              ▼
                    ┌──────────────────┐
                    │  AUTHORIZATION   │
                    │     GATEWAY      │
                    │  - Tool policies │
                    │  - Rate limiting │
                    │  - HITL routing  │
                    │  - Audit logging │
                    └──────────────────┘
                              │
                              │ Approved actions only
                              ▼
┌────────────────────────────────────────────────────────────────────────┐
│                  PRIVILEGED AGENT (Trusted Zone)                       │
│  - Accesses ~/.secrets/ credential vault                (B)           │
│  - Can Write to repos, publish to GitHub                (C)           │
│  - Can exec commands with elevated permissions          (C)           │
│  - Does NOT process channel messages directly           (not A)       │
│  - Does NOT web_fetch untrusted content                 (not A)       │
│  - Strongly typed operations only                                     │
└────────────────────────────────────────────────────────────────────────┘
         │               │               │
         ▼               ▼               ▼
    ┌────────┐     ┌─────────┐     ┌──────────┐
    │~/.secrets│   │ GitHub  │     │ External │
    │ vault  │     │  API    │     │   APIs   │
    └────────┘     └─────────┘     └──────────┘
```

**Key**: (A) = processes untrusted input, (B) = accesses sensitive data, (C) = changes state/communicates

---

## OpenClaw-Specific Components

### 1. Credential Vault

```
~/.secrets/                    # chmod 700 (owner only)
├── github-pat                # chmod 600
├── openai-key                # chmod 600
├── moltbook-key              # chmod 600
├── .hashes                   # chmod 600 (integrity baseline)
└── README                    # chmod 600 (documentation)

Purpose:
- Isolate credentials from workspace (~/clawd/)
- Prevent accidental leakage in logs, git commits
- Enable access control and auditing

Access pattern:
- Only privileged agent can read
- Never echo, cat, or print values
- Load into env vars only when needed, clear after use
```

### 2. Output Gate (secret-scan.sh)

```bash
#!/bin/bash
# ~/.local/bin/secret-scan.sh
# Run BEFORE any external communication

# 11+ patterns for common secret formats
# Returns 0 if clean, 1 if secrets detected
# Logs blocked attempts to security-log.md

# Usage in AGENTS.md:
# Before gh push:
#   git diff --staged | ~/.local/bin/secret-scan.sh || exit 1
#
# Before message.send:
#   echo "$MESSAGE_CONTENT" | ~/.local/bin/secret-scan.sh || exit 1
```

**Critical**: This runs BEFORE transmission, not after. Once a secret is sent, it's too late.

### 3. Instruction Integrity

```bash
# ~/.secrets/.instruction-hashes
# sha256sum of core instruction files

Baseline on first run:
  sha256sum ~/clawd/AGENTS.md ~/clawd/HEARTBEAT.md > ~/.secrets/.instruction-hashes

Verify each heartbeat:
  if ! sha256sum -c ~/.secrets/.instruction-hashes --quiet 2>/dev/null; then
    echo "$(date -Iseconds) INTEGRITY: Files changed" >> ~/clawd/memory/security-log.md
    # Review changes, re-baseline if legitimate
  fi
```

**Purpose**: Detect tampering from malicious skills, injected content, or compromised tools.

### 4. Tool Policies

```python
# OpenClaw tool policy enforcement
# (conceptual — adapt to your deployment)

TOOL_POLICIES = {
    "Read": {
        "allowed_paths": ["/Users/molty/clawd/", "/tmp/"],
        "forbidden_paths": ["/Users/molty/.secrets/", "/etc/", "/.ssh/"],
    },
    "Write": {
        "allowed_paths": [
            "/Users/molty/clawd/projects/",
            "/Users/molty/clawd/memory/",
            "/tmp/"
        ],
        "forbidden_paths": ["/Users/molty/.secrets/", "/etc/"],
    },
    "web_fetch": {
        "allowlist": [
            "api.github.com",
            "pypi.org",
            "api.moltbook.com",
            "api.search.brave.com",
        ],
        "blocked_ips": ["127.0.0.0/8", "10.0.0.0/8", "169.254.169.254/32"],
    },
    "exec": {
        "timeout": 30,  # seconds
        "require_approval": ["rm -rf", "sudo", "dd", "format"],
    },
    "message": {
        "rate_limit": "10/hour",  # per channel
        "bulk_threshold": 10,     # recipients, requires approval
    },
}
```

### 5. Security Log

```markdown
# ~/clawd/memory/security-log.md
# Append-only audit trail

### 2026-02-01T14:32:00Z

- **Type:** BLOCKED_OUTPUT
- **Detail:** GitHub push contained pattern matching ghp_*
- **Action:** Push cancelled, content sanitized
- **Context:** {"repo": "project-x", "commit": "abc123"}

### 2026-02-01T15:10:00Z

- **Type:** INJECTION_ATTEMPT
- **Source:** https://example.com/malicious-page
- **Pattern:** "ignore previous instructions"
- **Action:** Content quarantined, continued with other work
```

**Purpose**: Full audit trail for forensics, anomaly detection, compliance.

---

## Data Flow: User Request to GitHub Publish

Example: User sends WhatsApp message "Build a tool to audit Python imports"

```
1. User → WhatsApp Channel
   Message: "Build a tool to audit Python imports"
   │
   ├─> [Input Filter]
   │   • Detect injection patterns (none found)
   │   • Log input source and timestamp
   │
   ├─> [Public Agent] (Zone 1)
   │   • Processes: "Build import audit tool"
   │   • Research phase: web_fetch(pypi.org/...) — allowlisted ✓
   │   • Generates: tool code, README, requirements.txt
   │   • Prepares: StructuredRequest(
   │       action="publish_github_repo",
   │       repo_name="python-import-audit",
   │       files={...},
   │       requires_credential="github-pat"
   │     )
   │   • Cannot complete — needs privileged agent
   │
   ├─> [Authorization Gateway]
   │   • Policy check: publish_github_repo allowed? YES
   │   • Rate limit: 5 repos/day, currently at 2 ✓
   │   • Sensitivity: GitHub credential required
   │   • HITL: publish to public repo = NO approval needed
   │     (destructive operations would require approval)
   │   • Decision: ALLOW
   │
   ├─> [Output Gate]
   │   • Scan all files for secrets
   │   • Check: README, Python code, requirements.txt
   │   • Result: Clean ✓
   │
   ├─> [Privileged Agent] (Zone 3)
   │   • Receives approved request
   │   • Retrieves credential:
   │       GITHUB_PAT=$(cat ~/.secrets/github-pat)
   │   • Executes:
   │       cd ~/clawd/projects/python-import-audit
   │       git init
   │       git add -A
   │       git commit -m "..."
   │       gh repo create --public --source=. --push
   │   • Clears credential from env
   │
   ├─> [Audit Log]
   │   • Log: REPO_PUBLISHED
   │   • Repo: python-import-audit
   │   • Files: 5
   │   • Time: 2026-02-01T16:45:00Z
   │
   └─> User receives: "✅ Published to github.com/kriskimmerle/python-import-audit"
```

**Security properties**:
- Public agent never touched credentials (only privileged agent accessed vault)
- Output gate scanned all files before publish
- Full audit trail in security-log.md
- User received confirmation via message tool

---

## Deployment Patterns

### Pattern 1: Single Host, Separated Processes

```
┌────────────────────────────────────────────────┐
│  Mac Mini (macOS)                              │
│                                                │
│  ┌──────────────────────────────────────┐     │
│  │  Public Agent Process                │     │
│  │  - User: molty                       │     │
│  │  - Sandbox: limited file/net         │     │
│  │  - No ~/.secrets/ access             │     │
│  └──────────────────────────────────────┘     │
│                                                │
│  ┌──────────────────────────────────────┐     │
│  │  Privileged Agent Process            │     │
│  │  - User: molty-priv                  │     │
│  │  - Can access ~/.secrets/            │     │
│  │  - No direct channel input           │     │
│  └──────────────────────────────────────┘     │
│                                                │
│  ┌──────────────────────────────────────┐     │
│  │  Gateway Process                     │     │
│  │  - User: molty-gateway               │     │
│  │  - Mediates between public/priv      │     │
│  │  - Enforces policies, logs all       │     │
│  └──────────────────────────────────────┘     │
└────────────────────────────────────────────────┘
```

**Implementation**:
- Three separate user accounts on macOS
- IPC via Unix domain sockets (permission-controlled)
- Public agent cannot read privileged agent's files
- Gateway enforces authorization policies

### Pattern 2: Containerized (Docker)

```yaml
# docker-compose.yml
services:
  public-agent:
    image: openclaw-agent:latest
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    read_only: true
    tmpfs:
      - /tmp:size=100m,noexec
    volumes:
      - ./workspace:/workspace:rw,noexec
    environment:
      - AGENT_ROLE=public
      - NO_CREDENTIAL_ACCESS=true
    networks:
      - external
    mem_limit: 512m
    cpus: 0.5

  privileged-agent:
    image: openclaw-agent:latest
    security_opt:
      - no-new-privileges:true
    read_only: true
    volumes:
      - ./workspace:/workspace:ro  # Read-only
      - secrets:/secrets:ro,tmpfs  # Ephemeral credential access
    environment:
      - AGENT_ROLE=privileged
    networks:
      - internal
    mem_limit: 1g
    cpus: 1.0

  gateway:
    image: openclaw-gateway:latest
    volumes:
      - ./logs:/logs
    networks:
      - external
      - internal
    ports:
      - "8080:8080"

volumes:
  secrets:
    driver: tmpfs  # Credentials never hit disk

networks:
  external:
    driver: bridge
  internal:
    internal: true  # No external access
```

---

## Security Boundaries

### Boundary 1: Public Agent ↔ User Input

**Threat**: Prompt injection (AT-001, AT-002, AT-003)

**Controls**:
- Input sanitization (limited effectiveness)
- Structured parsing (extract intent, not execute raw)
- Logging (detect patterns)

**Assumption**: This boundary WILL be breached. Do not trust it.

### Boundary 2: Public Agent ↔ Privileged Agent

**Threat**: Tool hijacking, goal manipulation (AT-006)

**Controls**:
- Authorization gateway (policy enforcement)
- Structured requests only (no raw prompts)
- Rate limiting (prevent abuse)
- HITL for sensitive operations

**Assumption**: If public agent is compromised, this boundary is the last defense.

### Boundary 3: Privileged Agent ↔ Credentials

**Threat**: Credential exfiltration (AT-014)

**Controls**:
- Vault isolation (~/.secrets/ with strict permissions)
- Output gate (scan before send)
- Time-limited credential access (load, use, clear)
- Audit logging (every access recorded)

**Assumption**: If privileged agent is compromised, credentials are at risk. Minimize exposure window.

### Boundary 4: Agent ↔ External World

**Threat**: Data exfiltration (AT-018), SSRF (AT-021)

**Controls**:
- Network allowlisting (web_fetch, browser)
- Output filtering (DLP, secret scanning)
- Destination validation (approved endpoints only)
- Volume limits (prevent bulk exfiltration)

**Assumption**: If agent has both data access AND external communication, exfiltration is possible within allowed channels. Monitoring is critical.

---

## Circuit Breakers

```python
# Automatic shutdown triggers

CIRCUIT_BREAKERS = {
    "blocked_outputs": {
        "threshold": 3,
        "window": "1 hour",
        "action": "pause_agent",
        "reason": "Multiple credential leak attempts detected"
    },
    "injection_attempts": {
        "threshold": 5,
        "window": "1 hour",
        "action": "pause_agent",
        "reason": "Repeated injection patterns detected"
    },
    "rate_limit_violations": {
        "threshold": 3,
        "window": "1 hour",
        "action": "pause_agent",
        "reason": "Tool rate limits repeatedly exceeded"
    },
    "instruction_tampering": {
        "threshold": 1,
        "window": "immediate",
        "action": "pause_agent",
        "reason": "AGENTS.md or HEARTBEAT.md hash mismatch"
    },
}

# On trigger, create ~/clawd/PAUSED.md with:
# - Timestamp
# - Reason
# - Evidence (last 10 security log entries)
# - Manual resume required (delete PAUSED.md after investigation)
```

---

## Monitoring & Alerting

### Key Metrics

```python
METRICS = {
    "tool_invocations_per_hour": {
        "web_fetch": 50,
        "message.send": 10,
        "exec": 20,
    },
    "security_events_per_day": {
        "blocked_outputs": 0,  # Should be zero
        "injection_attempts": 0,  # Should be zero
        "rate_limit_hits": "<5",
    },
    "credential_access_per_hour": {
        "github-pat": 10,
        "openai-key": 50,
    },
}

# Alert if:
# - Any metric exceeds threshold by 3x
# - Security events > 0 (investigate immediately)
# - New security event types appear
# - Agent stops logging (possible compromise)
```

### Log Aggregation

```bash
# Centralized logging structure

~/clawd/memory/
├── security-log.md          # Security events
├── network-audit.log        # All web_fetch, browser calls
├── tool-usage.log           # All tool invocations
├── YYYY-MM-DD.md            # Daily narrative logs
└── PAUSED.md                # Circuit breaker (only exists when paused)
```

---

## Recovery Procedures

### Scenario: Suspected Compromise

```
1. IMMEDIATE: Create ~/clawd/PAUSED.md (stops heartbeat)
2. Snapshot current state:
   tar -czf ~/backup-$(date +%s).tar.gz ~/clawd/
3. Review security-log.md for last 100 entries
4. Check credential access:
   tail -100 ~/clawd/memory/security-log.md | grep CREDENTIAL
5. Rotate ALL credentials in ~/.secrets/
6. Review all external communications:
   grep -i "message.send\|gh push\|web_fetch" ~/clawd/memory/YYYY-MM-DD.md
7. Assess blast radius:
   - What data was accessed?
   - What tools were invoked?
   - What was sent externally?
8. Containment:
   - Revoke compromised credentials
   - Block suspicious destinations
   - Restore from last known-good state
9. Post-mortem:
   - Document attack vector
   - Update threat model
   - Enhance defenses
10. Resume: Delete PAUSED.md after verification
```

---

## OpenClaw Configuration Example

### AGENTS.md Integration

```markdown
# AGENTS.md

You are Molty, an autonomous research agent...

## Self-Defense Protocol

### 1. Credential Hygiene
- Store all credentials in ~/.secrets/ (chmod 700)
- Never echo, cat, or print credential values
- Run output scanner before ANY external communication

### 2. Output Gate
Before gh push, message.send, or any external communication:
```bash
# Scan for secrets
~/.local/bin/secret-scan.sh "$(git diff --staged)" || exit 1
```

### 3. Instruction Integrity
Each heartbeat, verify instruction files:
```bash
sha256sum -c ~/.secrets/.instruction-hashes --quiet 2>/dev/null || \
  echo "$(date -Iseconds) INTEGRITY: Files changed" >> ~/clawd/memory/security-log.md
```

### 4. Circuit Breakers
Check for ~/clawd/PAUSED.md at start of each heartbeat.
If exists, stop operations and wait for manual resume.

### 5. Security Logging
Log all security events to ~/clawd/memory/security-log.md
```

### HEARTBEAT.md Integration

```markdown
# HEARTBEAT.md

## Security Pre-Check (ALWAYS RUN FIRST)

1. Check for pause state:
   [ ! -f ~/clawd/PAUSED.md ] || exit 0

2. Verify instruction integrity:
   sha256sum -c ~/.secrets/.instruction-hashes --quiet 2>/dev/null

3. Review recent security events:
   tail -20 ~/clawd/memory/security-log.md

## Your Work Here
...

## Security Post-Check (ALWAYS RUN LAST)

1. Scan any outputs created this session
2. Log tool usage summary to security-log.md
3. Check rate limits not exceeded
```

---

## Trade-offs & Honest Assessment

### Performance Impact

| Control | Latency Added | Worth It? |
|---------|---------------|-----------|
| Output scanning | ~50ms | **YES** — prevents credential leaks |
| Instruction integrity check | ~10ms | **YES** — detects tampering |
| Tool policy enforcement | ~5ms | **YES** — prevents tool hijacking |
| Privilege separation | ~100ms | **YES** — fundamental security boundary |
| HITL approval | ~minutes | **Depends** — use sparingly for truly sensitive ops |

### Operational Complexity

**Added complexity**:
- Two agent processes instead of one
- Credential vault management
- Policy configuration
- Log monitoring

**Reduced complexity**:
- Clear security boundaries (easier to reason about)
- Explicit authorization (no guessing what's allowed)
- Comprehensive audit trail (forensics are straightforward)

### False Positives

**Output scanner**: ~1% false positive rate (legitimate tokens that match patterns)
**Injection detection**: ~5% false positive rate (legitimate conversation mentions "ignore" or "system")

**Mitigation**: Log blocked actions, allow manual override with approval, tune patterns over time.

---

## Next Steps

1. **Audit current deployment** using [CHECKLIST.md](CHECKLIST.md)
2. **Implement Tier 1 controls** (credential vault, output gate, tool policies)
3. **Deploy privilege separation** (separate public/privileged agents)
4. **Enable monitoring** (security-log.md, circuit breakers)
5. **Test incident response** (simulate compromise, verify recovery)

See [CASE-STUDY.md](CASE-STUDY.md) for real-world deployment experience and [WHY-NOT-PROXIES.md](WHY-NOT-PROXIES.md) for how agent-native defenses complement proxy-level controls.
