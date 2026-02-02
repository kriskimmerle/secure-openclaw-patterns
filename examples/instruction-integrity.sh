#!/bin/bash
# instruction-integrity.sh — Baseline and verify instruction file integrity
#
# Detects tampering of AGENTS.md, HEARTBEAT.md, and other core instruction files
# by comparing SHA-256 hashes against a stored baseline.
#
# Usage:
#   ./instruction-integrity.sh baseline    # Create/update baseline
#   ./instruction-integrity.sh verify      # Check files against baseline
#   ./instruction-integrity.sh             # Same as verify

set -euo pipefail

VAULT_DIR="${SECRETS_DIR:-$HOME/.secrets}"
HASH_FILE="$VAULT_DIR/.instruction-hashes"
WORKSPACE="${AGENT_WORKSPACE:-$HOME/clawd}"
SECURITY_LOG="${SECURITY_LOG:-$WORKSPACE/memory/security-log.md}"

# Files to track — add more as needed
INSTRUCTION_FILES=(
  "$WORKSPACE/AGENTS.md"
  "$WORKSPACE/HEARTBEAT.md"
  "$WORKSPACE/SOUL.md"
  "$WORKSPACE/IDENTITY.md"
  "$WORKSPACE/TOOLS.md"
)

action="${1:-verify}"

case "$action" in
  baseline)
    echo "📋 Creating instruction integrity baseline..."
    
    # Ensure vault exists
    mkdir -p "$VAULT_DIR"
    chmod 700 "$VAULT_DIR"
    
    # Build hash file from existing instruction files
    found=0
    > "$HASH_FILE"  # Clear/create
    
    for f in "${INSTRUCTION_FILES[@]}"; do
      if [ -f "$f" ]; then
        sha256sum "$f" >> "$HASH_FILE"
        echo "  ✅ Baselined: $(basename "$f")"
        found=$((found + 1))
      fi
    done
    
    chmod 600 "$HASH_FILE"
    echo ""
    echo "Baselined $found files → $HASH_FILE"
    
    # Log the event
    if [ -n "${SECURITY_LOG:-}" ] && [ -d "$(dirname "$SECURITY_LOG")" ]; then
      echo "" >> "$SECURITY_LOG"
      echo "### $(date -Iseconds) — Integrity Baseline" >> "$SECURITY_LOG"
      echo "- **Type:** INTEGRITY_BASELINE" >> "$SECURITY_LOG"
      echo "- **Files:** $found" >> "$SECURITY_LOG"
      echo "- **Action:** Baseline created/updated" >> "$SECURITY_LOG"
    fi
    ;;
    
  verify)
    echo "🔍 Verifying instruction file integrity..."
    
    if [ ! -f "$HASH_FILE" ]; then
      echo "❌ No baseline found at $HASH_FILE"
      echo "   Run: $0 baseline"
      exit 2
    fi
    
    if sha256sum -c "$HASH_FILE" --quiet 2>/dev/null; then
      echo "✅ All instruction files match baseline."
      exit 0
    else
      echo ""
      echo "⚠️  INTEGRITY VIOLATION — Files changed since baseline:"
      echo ""
      
      # Show which files changed
      while IFS= read -r line; do
        hash=$(echo "$line" | awk '{print $1}')
        file=$(echo "$line" | awk '{print $2}')
        
        if [ -f "$file" ]; then
          current_hash=$(sha256sum "$file" | awk '{print $1}')
          if [ "$hash" != "$current_hash" ]; then
            echo "  ❌ CHANGED: $(basename "$file")"
            echo "     Expected: ${hash:0:16}..."
            echo "     Current:  ${current_hash:0:16}..."
          fi
        else
          echo "  ❌ MISSING: $file"
        fi
      done < "$HASH_FILE"
      
      echo ""
      echo "Actions:"
      echo "  • If YOU made this change: $0 baseline"
      echo "  • If unexpected: INVESTIGATE — possible tampering"
      
      # Log the event
      if [ -n "${SECURITY_LOG:-}" ] && [ -d "$(dirname "$SECURITY_LOG")" ]; then
        echo "" >> "$SECURITY_LOG"
        echo "### $(date -Iseconds) — Integrity Violation" >> "$SECURITY_LOG"
        echo "- **Type:** INTEGRITY_VIOLATION" >> "$SECURITY_LOG"
        echo "- **Detail:** Instruction files changed since baseline" >> "$SECURITY_LOG"
        echo "- **Action:** Requires investigation" >> "$SECURITY_LOG"
      fi
      
      exit 1
    fi
    ;;
    
  *)
    echo "Usage: $0 [baseline|verify]"
    echo ""
    echo "  baseline    Create or update hash baseline"
    echo "  verify      Check files against baseline (default)"
    exit 2
    ;;
esac
