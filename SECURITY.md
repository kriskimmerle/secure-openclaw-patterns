# Security Policy

## Reporting Security Issues

If you discover a security issue in the example scripts, documentation, or recommended patterns in this repository, please report it responsibly.

**For this repository**: Open a [GitHub Issue](https://github.com/kriskimmerle/secure-openclaw-patterns/issues) with the label "security." If the issue is sensitive (e.g., a vulnerability in the example secret scanner that could be exploited), email kriskimmerle@github (or use GitHub's private vulnerability reporting).

**For OpenClaw itself**: Report to the [OpenClaw security team](https://github.com/openclaw/openclaw/security) using their private disclosure process. Do not report OpenClaw vulnerabilities here.

## Scope

This repository contains:
- **Documentation** (threat models, architecture guides, checklists)
- **Example scripts** (secret-scan.sh, setup-secrets.sh, instruction-integrity.sh)
- **Template files** (example AGENTS.md)

### What's In Scope

- Errors in security guidance that could lead to weaker deployments
- Bugs in example scripts (e.g., regex patterns that miss common secrets, or that produce false negatives)
- Incorrect attributions or citations that could mislead practitioners
- Patterns that are documented as secure but have known weaknesses not disclosed

### What's Not In Scope

- Theoretical attacks against the documented defenses (we document limitations explicitly)
- Feature requests or suggestions (use Issues with the "enhancement" label)
- Vulnerabilities in OpenClaw itself (report to OpenClaw upstream)

## Responsible Disclosure

We ask that you:
1. Give us reasonable time to address issues before public disclosure (30 days)
2. Don't exploit issues against live deployments
3. Provide enough detail to reproduce the issue

## Examples Are Provided As-Is

The scripts in `examples/` are **reference implementations** intended to demonstrate patterns. They are:
- Tested on macOS and Linux
- Written for clarity over performance
- Suitable as starting points, not drop-in production solutions

**You are responsible for adapting, testing, and hardening these scripts for your specific deployment.** We make no warranty about their effectiveness against all attacks. See [DEFENSES.md](DEFENSES.md) for honest assessments of each pattern's limitations.

## Acknowledgments

Security researchers who report valid issues will be acknowledged in this file (with permission).

### Hall of Thanks

*(No reports yet — be the first!)*
