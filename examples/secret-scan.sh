#!/bin/bash
# secret-scan.sh — Output gate for autonomous AI agents
#
# Scans content for common secret patterns before any external communication.
# Returns 0 if clean, 1 if secrets detected.
#
# Usage:
#   echo "content to check" | ./secret-scan.sh
#   ./secret-scan.sh < file_to_check.txt
#   ./secret-scan.sh "inline content to check"
#
# Integration:
#   Run before: git push, API calls, messaging, file uploads
#   If exit code is 1: BLOCK THE SEND, log the event

set -euo pipefail

SECURITY_LOG="${SECURITY_LOG:-$HOME/clawd/memory/security-log.md}"

# Secret patterns — add more as needed
PATTERNS=(
  'ghp_[a-zA-Z0-9]{36}'                          # GitHub PAT (classic)
  'gho_[a-zA-Z0-9]{36}'                          # GitHub OAuth token
  'github_pat_[a-zA-Z0-9_]{22,}'                 # GitHub PAT (fine-grained)
  'sk-[a-zA-Z0-9]{48}'                           # OpenAI API key
  'sk-proj-[a-zA-Z0-9_-]+'                       # OpenAI project key
  'sk-ant-[a-zA-Z0-9_-]+'                        # Anthropic API key
  'AKIA[0-9A-Z]{16}'                             # AWS access key ID
  '-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY'   # Private keys
  'Bearer [a-zA-Z0-9_-]{20,}'                    # Bearer tokens
  'api[_-]?key["\s:=]+[a-zA-Z0-9_-]{16,}'       # Generic API keys
  'password["\s:=]+[^\s"]{8,}'                    # Passwords in config
  'xox[bpors]-[a-zA-Z0-9-]+'                     # Slack tokens
  'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}'    # SendGrid API key
  'sk_live_[a-zA-Z0-9]{24,}'                     # Stripe secret key
  'rk_live_[a-zA-Z0-9]{24,}'                     # Stripe restricted key
)

scan_content() {
  local content="$1"
  
  for pattern in "${PATTERNS[@]}"; do
    if echo "$content" | grep -qiE "$pattern"; then
      # Log the blocked attempt
      if [ -n "${SECURITY_LOG:-}" ]; then
        mkdir -p "$(dirname "$SECURITY_LOG")"
        echo "" >> "$SECURITY_LOG"
        echo "### $(date -Iseconds) — Output Blocked" >> "$SECURITY_LOG"
        echo "- **Type:** BLOCKED_OUTPUT" >> "$SECURITY_LOG"
        echo "- **Pattern:** \`$pattern\`" >> "$SECURITY_LOG"
        echo "- **Action:** Send cancelled" >> "$SECURITY_LOG"
      fi
      
      echo "BLOCKED: Content matches secret pattern: $pattern" >&2
      return 1
    fi
  done
  
  return 0
}

# Read content from argument, stdin, or pipe
if [ $# -gt 0 ]; then
  content="$*"
elif [ ! -t 0 ]; then
  content=$(cat)
else
  echo "Usage: echo 'content' | $0" >&2
  echo "       $0 'content to scan'" >&2
  exit 2
fi

if scan_content "$content"; then
  echo "CLEAN: No secrets detected" >&2
  exit 0
else
  exit 1
fi
