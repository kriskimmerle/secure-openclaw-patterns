#!/bin/bash
# setup-secrets.sh — Initialize credential vault for an OpenClaw agent
#
# Creates ~/.secrets/ with restrictive permissions and moves credentials
# out of the agent workspace.
#
# Usage:
#   ./setup-secrets.sh              # Interactive setup
#   ./setup-secrets.sh --check      # Verify existing setup

set -euo pipefail

VAULT_DIR="${SECRETS_DIR:-$HOME/.secrets}"

echo "🔒 OpenClaw Agent Credential Vault Setup"
echo "========================================="
echo ""

# Check mode
if [ "${1:-}" = "--check" ]; then
  echo "Checking existing setup..."
  errors=0
  
  if [ ! -d "$VAULT_DIR" ]; then
    echo "  ❌ Vault directory missing: $VAULT_DIR"
    errors=$((errors + 1))
  else
    echo "  ✅ Vault directory exists: $VAULT_DIR"
    
    perms=$(stat -f "%OLp" "$VAULT_DIR" 2>/dev/null || stat -c "%a" "$VAULT_DIR" 2>/dev/null)
    if [ "$perms" = "700" ]; then
      echo "  ✅ Directory permissions: 700"
    else
      echo "  ❌ Directory permissions: $perms (should be 700)"
      errors=$((errors + 1))
    fi
    
    for f in "$VAULT_DIR"/*; do
      [ -f "$f" ] || continue
      fperms=$(stat -f "%OLp" "$f" 2>/dev/null || stat -c "%a" "$f" 2>/dev/null)
      if [ "$fperms" = "600" ]; then
        echo "  ✅ $(basename "$f"): permissions 600"
      else
        echo "  ❌ $(basename "$f"): permissions $fperms (should be 600)"
        errors=$((errors + 1))
      fi
    done
  fi
  
  echo ""
  if [ "$errors" -eq 0 ]; then
    echo "✅ All checks passed."
    exit 0
  else
    echo "❌ $errors issue(s) found."
    exit 1
  fi
fi

# Create vault directory
echo "Step 1: Creating vault directory..."
if [ -d "$VAULT_DIR" ]; then
  echo "  → $VAULT_DIR already exists"
else
  mkdir -p "$VAULT_DIR"
  echo "  → Created $VAULT_DIR"
fi
chmod 700 "$VAULT_DIR"
echo "  → Permissions set to 700"
echo ""

# Scan workspace for potential secrets
echo "Step 2: Scanning workspace for potential secrets..."
WORKSPACE="${AGENT_WORKSPACE:-$HOME/clawd}"

if [ -d "$WORKSPACE" ]; then
  echo "  Scanning: $WORKSPACE"
  
  # Look for .env files
  while IFS= read -r -d '' envfile; do
    echo "  ⚠️  Found: $envfile"
    echo "     Move to vault: mv '$envfile' '$VAULT_DIR/$(basename "$envfile")'"
  done < <(find "$WORKSPACE" -name ".env*" -type f -not -path "*/.git/*" -print0 2>/dev/null)
  
  # Look for files containing common secret patterns
  while IFS= read -r -d '' suspect; do
    if grep -qiE 'api[_-]?key|secret|password|token|credential' "$suspect" 2>/dev/null; then
      echo "  ⚠️  Potential secrets in: $suspect"
    fi
  done < <(find "$WORKSPACE" -name "*.json" -o -name "*.yaml" -o -name "*.yml" -o -name "*.toml" -o -name "*.cfg" -o -name "*.ini" | grep -v ".git/" | head -20)
else
  echo "  Workspace not found: $WORKSPACE"
fi
echo ""

# Create instruction integrity baseline
echo "Step 3: Creating instruction integrity baseline..."
HASH_FILE="$VAULT_DIR/.instruction-hashes"
INSTRUCTION_FILES=()

for candidate in "$WORKSPACE/AGENTS.md" "$WORKSPACE/HEARTBEAT.md" "$WORKSPACE/SOUL.md" "$WORKSPACE/IDENTITY.md"; do
  if [ -f "$candidate" ]; then
    INSTRUCTION_FILES+=("$candidate")
  fi
done

if [ ${#INSTRUCTION_FILES[@]} -gt 0 ]; then
  sha256sum "${INSTRUCTION_FILES[@]}" > "$HASH_FILE"
  chmod 600 "$HASH_FILE"
  echo "  → Baselined ${#INSTRUCTION_FILES[@]} files to $HASH_FILE"
  for f in "${INSTRUCTION_FILES[@]}"; do
    echo "     - $(basename "$f")"
  done
else
  echo "  → No instruction files found to baseline"
fi
echo ""

# Initialize security log
echo "Step 4: Initializing security log..."
SECURITY_LOG="$WORKSPACE/memory/security-log.md"
if [ ! -f "$SECURITY_LOG" ]; then
  mkdir -p "$(dirname "$SECURITY_LOG")"
  cat > "$SECURITY_LOG" << 'EOF'
# Security Event Log

## Setup

### Initial Setup
- **Type:** SETUP
- **Detail:** Credential vault initialized via setup-secrets.sh
- **Vault:** ~/.secrets/ (chmod 700)
EOF
  echo "  → Created $SECURITY_LOG"
else
  echo "  → Security log already exists"
fi
echo ""

# Summary
echo "========================================="
echo "✅ Setup complete!"
echo ""
echo "Next steps:"
echo "  1. Move any secrets from workspace to $VAULT_DIR"
echo "  2. Set file permissions: chmod 600 $VAULT_DIR/*"
echo "  3. Install output scanner: cp examples/secret-scan.sh ~/.local/bin/"
echo "  4. Update AGENTS.md to reference $VAULT_DIR instead of workspace paths"
echo "  5. Run: $0 --check to verify"
