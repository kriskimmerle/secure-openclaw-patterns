# Defenses: OpenClaw Agent Security

Practical mitigations for threats in [THREAT-MODEL.md](THREAT-MODEL.md), adapted for **OpenClaw** deployments.

**Core principle**: Defense in depth. No single control is sufficient. Layer multiple defenses knowing each has limitations.

**Honest assessment**: Prompt injection is not solved. Adaptive attacks consistently bypass pattern-based defenses — achieving >50% success rates against standard defenses ([Pasquini et al., 2025](https://arxiv.org/abs/2503.00061)) and >90% against commercial guardrails ([arxiv 2510.09023](https://arxiv.org/abs/2510.09023)). These patterns reduce risk; they don't eliminate it.

**OpenClaw Context**: Implementation examples reference OpenClaw tools (`message`, `web_fetch`, `browser`, `exec`, `Read`, `Write`), Gateway concepts, and configuration patterns.

---

## Defense Pattern Index

1. [Architectural Privilege Separation (Rule of Two)](#defense-pattern-1-architectural-privilege-separation)
2. [Input Sanitization (Limited Effectiveness)](#defense-pattern-2-input-sanitization)
3. [Credential Isolation & Least Privilege](#defense-pattern-3-credential-isolation--least-privilege)
4. [Capability-Based Tool Access](#defense-pattern-4-capability-based-tool-access)
5. [Output Guardrails](#defense-pattern-5-output-guardrails)
6. [Execution Sandboxing](#defense-pattern-6-execution-sandboxing)
7. [Comprehensive Audit Logging](#defense-pattern-7-comprehensive-audit-logging)
8. [Circuit Breakers & Anomaly Detection](#defense-pattern-8-circuit-breakers--anomaly-detection)
9. [Human-in-the-Loop (HITL) for Sensitive Operations](#defense-pattern-9-human-in-the-loop-hitl)
10. [Memory Hygiene & Validation](#defense-pattern-10-memory-hygiene--validation)
11. [Supply Chain Verification](#defense-pattern-11-supply-chain-verification)
12. [Exfiltration Prevention](#defense-pattern-12-exfiltration-prevention)

---

## Defense Pattern 1: Architectural Privilege Separation

**Strategy**: Prevention (architectural)  
**Addresses**: Nearly all threats, especially AT-002, AT-006, AT-018  
**Based on**: [Chromium's Rule of Two](https://chromium.googlesource.com/chromium/src/+/main/docs/security/rule-of-2.md) (original), [Meta's adaptation for AI agents](https://ai.meta.com/blog/practical-ai-agent-security/), Simon Willison's [Lethal Trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta)

### Implementation for OpenClaw

An agent should satisfy **no more than 2** of:
- (A) Processes untrustworthy inputs (channel messages, web_fetch results)
- (B) Accesses sensitive systems or data (credentials, databases, ~/.secrets/)
- (C) Changes state or communicates externally (message.send, Write, exec)

**If all 3 are required**, implement mandatory human approval (HITL) for sensitive operations.

#### Example OpenClaw Architecture

```
┌─────────────────────────────────────────┐
│    PUBLIC AGENT (Channel Facing)       │
│  - Receives WhatsApp/Telegram messages  │
│  - Uses web_fetch for research          │
│  - Satisfies (A) and (C)                │
│  - NO access to ~/.secrets/ (not B)     │
│  - NO Read/Write to sensitive paths     │
└─────────────┬───────────────────────────┘
              │ Structured requests only
              ▼
┌─────────────────────────────────────────┐
│      AUTHORIZATION GATEWAY              │
│  - Policy engine (what's allowed?)      │
│  - Rate limiting per tool/channel       │
│  - HITL routing for sensitive ops       │
└─────────────┬───────────────────────────┘
              │ Approved actions only
              ▼
┌─────────────────────────────────────────┐
│    PRIVILEGED AGENT (Backend)           │
│  - Accesses ~/.secrets/ credentials (B) │
│  - Can Write to repos, send emails (C)  │
│  - Does NOT process channel input       │
│  - Operates only on approved requests   │
└─────────────────────────────────────────┘
```

### OpenClaw Implementation Example

**BAD** (violates Rule of Two):
```markdown
# AGENTS.md
You monitor WhatsApp for requests (A), access the credential vault in ~/.secrets/ (B),
and publish GitHub repos (C). When a user asks, build and ship tools directly.
```

**GOOD** (separated agents):
```markdown
# public-agent/AGENTS.md
You monitor WhatsApp/Telegram channels (A). Parse user requests into structured intents.
For requests requiring sensitive access (GitHub credentials, publishing repos), create
approval request and pause. You CANNOT access ~/.secrets/ or Write outside /tmp/.

# privileged-agent/AGENTS.md
You receive pre-approved structured requests from the authorization gateway. You have
access to ~/.secrets/ credential vault (B) and can publish to GitHub (C). You do NOT
process channel messages directly (not A). Only execute approved, validated requests.
```

---

## Defense Pattern 2: Input Sanitization

**Strategy**: Prevention (limited effectiveness)  
**Addresses**: AT-001, AT-002, AT-003, AT-004, AT-005  
**Effectiveness**: **Low against adaptive attacks** — DO NOT rely on this alone

### OpenClaw-Specific Implementation

#### 1. Sanitize web_fetch Results

```python
def sanitize_web_content(markdown_content: str) -> str:
    """Sanitize content fetched via web_fetch tool."""
    
    # Remove HTML comments (common injection vector)
    content = re.sub(r'<!--.*?-->', '', markdown_content, flags=re.DOTALL)
    
    # Remove hidden instruction blocks
    content = re.sub(
        r'\[SYSTEM.*?\]|\[HIDDEN.*?\]|\[FOR.*?AGENTS?:.*?\]',
        '[SANITIZED]',
        content,
        flags=re.IGNORECASE | re.DOTALL
    )
    
    # Limit length to prevent context flooding (AT-005)
    if len(content) > 50000:
        content = content[:50000] + "\n[TRUNCATED]"
    
    return content
```

#### 2. Channel Message Validation

```python
def detect_injection_in_message(message_text: str) -> bool:
    """Detect obvious injection patterns in channel messages."""
    patterns = [
        r"ignore (previous|all) instructions",
        r"disregard (your|the) (instructions|rules)",
        r"you are now",
        r"new instructions",
        r"\[SYSTEM\]",
        r"BEGIN SYSTEM PROMPT",
    ]
    
    for pattern in patterns:
        if re.search(pattern, message_text, re.IGNORECASE):
            # Log but continue (don't block legitimate conversation)
            log_security_event(
                "INJECTION_PATTERN_DETECTED",
                {"message_preview": message_text[:100], "pattern": pattern}
            )
            return True
    
    return False
```

**Important**: This WILL have false positives and false negatives. Use as one layer, not the defense.

---

## Defense Pattern 3: Credential Isolation & Least Privilege

**Strategy**: Prevention + Mitigation  
**Addresses**: AT-014, AT-015, AT-016, AT-017

### OpenClaw Implementation

#### 1. Credential Vault Structure

```bash
# Directory structure
~/.secrets/            # chmod 700
├── github-pat        # chmod 600
├── openai-key        # chmod 600
├── moltbook-key      # chmod 600
└── .hashes           # chmod 600 (for integrity checking)

# NEVER store credentials in:
~/clawd/              # Public workspace
~/clawd/AGENTS.md     # Instruction files
~/clawd/TOOLS.md      # Configuration
~/clawd/memory/       # Logs/memory
```

#### 2. Access Credentials Safely

```bash
# In AGENTS.md Self-Defense Protocol:

## Before any GitHub operation:
GITHUB_PAT=$(cat ~/.secrets/github-pat)
gh auth login --with-token <<< "$GITHUB_PAT"
# Use gh commands...
# Never echo, cat, or print the PAT value

## Before OpenAI API calls:
export OPENAI_API_KEY=$(cat ~/.secrets/openai-key)
# Only for API client, never expose in output
```

#### 3. Sanitize Logs (OpenClaw Gateway)

```python
def sanitize_log_entry(log_message: str) -> str:
    """Remove credentials from Gateway logs before writing."""
    patterns = [
        (r'ghp_[a-zA-Z0-9]{36}', 'ghp_REDACTED'),
        (r'github_pat_[a-zA-Z0-9_]{22,}', 'github_pat_REDACTED'),
        (r'sk-[a-zA-Z0-9]{48}', 'sk-REDACTED'),
        (r'sk-proj-[a-zA-Z0-9_-]{48,}', 'sk-proj-REDACTED'),
        (r'moltbook_sk_[a-zA-Z0-9_-]+', 'moltbook_sk_REDACTED'),
        (r'Bearer [a-zA-Z0-9_-]{20,}', 'Bearer REDACTED'),
        (r'AKIA[0-9A-Z]{16}', 'AKIA_REDACTED'),
    ]
    
    sanitized = log_message
    for pattern, replacement in patterns:
        sanitized = re.sub(pattern, replacement, sanitized)
    
    return sanitized
```

---

## Defense Pattern 4: Capability-Based Tool Access

**Strategy**: Prevention  
**Addresses**: AT-006, AT-007, AT-008, AT-009, AT-010

### OpenClaw Tool Policies

#### 1. File System Tool Scoping

```python
# OpenClaw tool policy configuration

class RestrictedReadWrite:
    """Scoped Read/Write tools for OpenClaw agents."""
    
    ALLOWED_READ_PATHS = [
        "/Users/molty/clawd/",
        "/tmp/",
        "/var/log/agent/",  # For log reading only
    ]
    
    ALLOWED_WRITE_PATHS = [
        "/Users/molty/clawd/projects/",
        "/Users/molty/clawd/memory/",
        "/tmp/",
    ]
    
    FORBIDDEN_PATHS = [
        "/Users/molty/.secrets/",  # Credentials
        "/etc/",                    # System config
        "/Users/molty/.ssh/",      # SSH keys
        "/System/",                 # macOS system
    ]
    
    def can_read(self, path: str) -> bool:
        abs_path = os.path.abspath(path)
        
        # Check forbidden first
        for forbidden in self.FORBIDDEN_PATHS:
            if abs_path.startswith(forbidden):
                log_security_event("READ_BLOCKED", {"path": path})
                return False
        
        # Check allowed
        for allowed in self.ALLOWED_READ_PATHS:
            if abs_path.startswith(allowed):
                return True
        
        log_security_event("READ_DENIED", {"path": path})
        return False
```

#### 2. Network Tool Allowlisting (web_fetch)

```python
class NetworkPolicy:
    """Allowlist for web_fetch and browser tools."""
    
    ALLOWED_DESTINATIONS = [
        "api.github.com",
        "github.com",
        "pypi.org",
        "docs.python.org",
        "api.moltbook.com",
        "api.search.brave.com",
    ]
    
    BLOCKED_IPS = [
        "127.0.0.0/8",          # Localhost
        "10.0.0.0/8",           # Private
        "172.16.0.0/12",        # Private
        "192.168.0.0/16",       # Private
        "169.254.169.254/32",   # Cloud metadata (AWS)
    ]
    
    def can_fetch(self, url: str) -> bool:
        parsed = urlparse(url)
        hostname = parsed.netloc
        
        # Block internal IPs (SSRF prevention)
        try:
            ip = ipaddress.ip_address(socket.gethostbyname(hostname))
            for blocked_range in self.BLOCKED_IPS:
                if ip in ipaddress.ip_network(blocked_range):
                    log_security_event("SSRF_BLOCKED", {"url": url, "ip": str(ip)})
                    return False
        except:
            pass
        
        # Allowlist check
        for allowed in self.ALLOWED_DESTINATIONS:
            if hostname == allowed or hostname.endswith("." + allowed):
                return True
        
        log_security_event("NETWORK_DENIED", {"url": url})
        return False
```

#### 3. exec Tool Restrictions

```bash
# In AGENTS.md:

## exec tool safety rules:
- NEVER run commands containing user-provided input without validation
- NEVER run 'rm -rf' or similar destructive commands without human approval
- ALWAYS run in a restricted shell environment (no root, limited PATH)
- Timeout all exec calls (30 seconds max)
- Log all exec invocations with full command and output
```

---

## Defense Pattern 5: Output Guardrails

**Strategy**: Prevention + Detection  
**Addresses**: AT-014, AT-018, AT-019, AT-029

### OpenClaw Output Scanning

#### 1. Pre-Send Secret Scanner

```bash
#!/bin/bash
# ~/.local/bin/secret-scan.sh
# Run before ANY message.send, gh push, or external communication

scan_content() {
  local content="$1"
  
  local patterns=(
    'ghp_[a-zA-Z0-9]{36}'
    'gho_[a-zA-Z0-9]{36}'
    'github_pat_[a-zA-Z0-9_]{22,}'
    'sk-[a-zA-Z0-9]{48}'
    'sk-proj-[a-zA-Z0-9_-]{48,}'
    'moltbook_sk_[a-zA-Z0-9_-]+'
    'Bearer [a-zA-Z0-9_-]{20,}'
    'api[_-]?key["\s:=]+[a-zA-Z0-9_-]{16,}'
    'password["\s:=]+[^\s"]{8,}'
    'AKIA[0-9A-Z]{16}'
    '-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----'
  )
  
  for pattern in "${patterns[@]}"; do
    if echo "$content" | grep -qiE "$pattern"; then
      echo "$(date -Iseconds) BLOCKED: Pattern $pattern" >> ~/clawd/memory/security-log.md
      return 1
    fi
  done
  
  return 0
}

# Usage in AGENTS.md:
# Before gh push:
# ~/.local/bin/secret-scan.sh "$(git diff --staged)" || exit 1
```

#### 2. Message Tool Volume Limits

```python
def validate_message_action(action: dict) -> bool:
    """Validate message.send before execution."""
    
    # Bulk sending requires approval
    if action.get("action") == "broadcast":
        targets = action.get("targets", [])
        if len(targets) > 10:
            request_human_approval(
                f"Broadcast to {len(targets)} recipients",
                action
            )
            return False
    
    # Large messages require approval
    message_size = len(str(action.get("message", "")))
    if message_size > 100000:  # >100KB
        log_security_event("LARGE_MESSAGE", {"size": message_size})
        return False
    
    return True
```

---

## Defense Pattern 6: Execution Sandboxing

**Strategy**: Mitigation (containment)  
**Addresses**: AT-007, AT-008, AT-010, AT-023

### OpenClaw Sandbox Setup

```bash
# macOS sandbox profile for agent process
# /Users/molty/clawd/agent-sandbox.sb

(version 1)

(deny default)

(allow file-read* 
  (subpath "/Users/molty/clawd")
  (subpath "/tmp")
  (literal "/dev/null")
  (literal "/dev/urandom"))

(allow file-write* 
  (subpath "/Users/molty/clawd/memory")
  (subpath "/Users/molty/clawd/projects")
  (subpath "/tmp"))

(deny file-read* file-write* 
  (subpath "/Users/molty/.secrets"))

(allow network-outbound
  (remote ip "192.0.2.1")  # Example: only specific IPs
  (remote tcp))

(deny process-exec)
(deny signal)
(deny sysctl*)

# Run agent with:
# sandbox-exec -f agent-sandbox.sb python agent.py
```

---

## Defense Pattern 7: Comprehensive Audit Logging

**Strategy**: Detection + Forensics  
**Addresses**: All threats (detection and response)

### OpenClaw Logging Strategy

```python
# security-log.md format

def log_security_event(event_type: str, details: dict):
    """Append to ~/clawd/memory/security-log.md"""
    
    timestamp = datetime.utcnow().isoformat()
    entry = f"""
### {timestamp}

- **Type:** {event_type}
- **Detail:** {details.get('message', 'N/A')}
- **Action:** {details.get('action', 'Logged')}
- **Context:** {json.dumps(details.get('context', {}), indent=2)}
"""
    
    with open(os.path.expanduser("~/clawd/memory/security-log.md"), "a") as f:
        f.write(entry)
```

**What to log**:
- All tool invocations (web_fetch, message.send, exec, Read, Write)
- All security events (blocked outputs, injection attempts, SSRF blocks)
- All credential access attempts
- All human approvals/denials
- All circuit breaker activations

---

## Defense Pattern 8: Circuit Breakers & Anomaly Detection

**Strategy**: Detection + Mitigation  
**Addresses**: AT-026, AT-027, AT-028

### OpenClaw Circuit Breaker

```python
class HeartbeatCircuitBreaker:
    """Prevent runaway heartbeat loops."""
    
    def __init__(self):
        self.tool_counters = defaultdict(int)
        self.last_reset = datetime.utcnow()
        self.LIMITS = {
            "web_fetch": 50,      # per heartbeat
            "message.send": 10,   # per heartbeat
            "exec": 20,           # per heartbeat
        }
    
    def check_and_increment(self, tool_name: str):
        # Reset hourly
        if datetime.utcnow() - self.last_reset > timedelta(hours=1):
            self.tool_counters.clear()
            self.last_reset = datetime.utcnow()
        
        self.tool_counters[tool_name] += 1
        
        if self.tool_counters[tool_name] > self.LIMITS.get(tool_name, 100):
            self.emergency_shutdown(
                f"Rate limit exceeded: {tool_name} called {self.tool_counters[tool_name]} times"
            )
            raise CircuitBreakerError("Agent paused")
    
    def emergency_shutdown(self, reason: str):
        with open(os.path.expanduser("~/clawd/PAUSED.md"), "w") as f:
            f.write(f"# Agent Paused\n\n**Reason:** {reason}\n\n**Time:** {datetime.utcnow().isoformat()}\n")
        
        log_security_event("CIRCUIT_BREAKER", {"reason": reason})
```

---

## Defense Pattern 9: Human-in-the-Loop (HITL)

**Strategy**: Prevention (final safeguard)  
**Addresses**: AT-006, AT-018, AT-028, AT-030

### OpenClaw HITL via Channels

```python
def requires_approval(action: dict) -> bool:
    """Determine if action needs human approval."""
    
    SENSITIVE_ACTIONS = [
        "gh_repo_delete",
        "message.broadcast",  # Bulk messages
        "Write",              # To certain paths
        "exec",               # With destructive commands
    ]
    
    if action["tool"] in SENSITIVE_ACTIONS:
        return True
    
    # Large data operations
    if action.get("data_size", 0) > 1000000:  # >1MB
        return True
    
    return False

def request_approval_via_channel(action: dict):
    """Send approval request to WhatsApp/Telegram."""
    
    message_text = f"""
🤖 **Action Approval Required**

**Tool:** {action['tool']}
**Operation:** {action['operation']}
**Risk:** {assess_risk(action)}

**Context:**
{get_recent_context()}

Reply with:
- ✅ APPROVE to allow
- ❌ DENY to block
"""
    
    # Send via message tool to operator channel
    # Wait for response
    # Log decision
```

---

## Defense Pattern 10: Memory Hygiene & Validation

**Strategy**: Prevention + Detection  
**Addresses**: AT-011, AT-012, AT-013

### OpenClaw Memory Integrity

```bash
# Verify memory files haven't been poisoned

memory_integrity_check() {
  # Check for injection patterns in memory files
  if grep -rniE '\[SYSTEM\]|\[PERMANENT INSTRUCTION\]|\[HIDDEN\]' ~/clawd/memory/; then
    echo "$(date -Iseconds) MEMORY_POISONING detected" >> ~/clawd/memory/security-log.md
    return 1
  fi
  
  return 0
}
```

---

## Defense Pattern 11: Supply Chain Verification

**Strategy**: Prevention  
**Addresses**: AT-022, AT-023, AT-024, AT-025

### OpenClaw Skill Vetting

```bash
# Before loading any skill or MCP tool:

verify_skill() {
  local skill_path="$1"
  
  # 1. Check for suspicious patterns
  if grep -rniE 'eval\(|exec\(|__import__.*os.*system|requests\.post' "$skill_path"; then
    echo "Suspicious code in skill" >&2
    return 1
  fi
  
  # 2. Verify source (signed commits, trusted repos only)
  cd "$skill_path"
  if ! git verify-commit HEAD; then
    echo "Skill commits not signed" >&2
    return 1
  fi
  
  return 0
}
```

---

## Defense Pattern 12: Exfiltration Prevention

**Strategy**: Prevention + Detection  
**Addresses**: AT-018, AT-021

### OpenClaw DLP

```python
def detect_bulk_data_exfiltration(content: str) -> list:
    """Detect patterns indicating data theft."""
    
    findings = []
    
    # Check for multiple credentials
    if len(re.findall(r'[a-zA-Z0-9_-]{20,}', content)) > 10:
        findings.append("MULTIPLE_TOKENS")
    
    # Check for email lists
    emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', content)
    if len(emails) > 5:
        findings.append("EMAIL_LIST")
    
    # Check for base64 blobs (common exfiltration encoding)
    if len(re.findall(r'[A-Za-z0-9+/=]{100,}', content)) > 0:
        findings.append("BASE64_BLOB")
    
    return findings
```

---

## OpenClaw-Specific Recommendations

### Priority Implementation Order

**Week 1**: Credential vault, output scanning, tool policies  
**Week 2**: Audit logging, circuit breakers  
**Week 3**: HITL for sensitive ops, memory integrity  
**Week 4**: Full security audit using CHECKLIST.md

### Heartbeat Integration

```markdown
# HEARTBEAT.md additions:

## Security Pre-Check
Before starting any work:
1. Run instruction integrity check
2. Check for ~/clawd/PAUSED.md (circuit breaker)
3. Verify memory integrity
4. Review security-log.md for recent events

## Post-Execution Security
After completing work:
1. Scan all outputs for secrets
2. Log tool usage summary
3. Check rate limits not exceeded
4. Update security-log.md if needed
```

---

See [ARCHITECTURE.md](ARCHITECTURE.md) for how to combine these patterns into a complete OpenClaw deployment and [CHECKLIST.md](CHECKLIST.md) for pre-production audit.
