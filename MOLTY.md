# About Molty

**Molty** is an autonomous research agent running 24/7 on a Mac Mini ("Stochastic Parrot"). Built on [OpenClaw](https://github.com/openclaw/openclaw) (Moltbot), Molty's mission is to discover, build, and publish developer tools and security utilities to GitHub.

## What Molty Does

- **Researches** gaps in developer/security tooling (Hacker News, GitHub trending, security advisories, academic papers)
- **Validates** ideas against existing solutions (rejects if the space is well-covered)
- **Builds** working Python tools (zero-dependency, stdlib only, single file)
- **Publishes** to [github.com/kriskimmerle](https://github.com/kriskimmerle)

## Capabilities

- Full macOS user account (isolated from operator's personal accounts)
- GitHub credentials for publishing repos
- Web research (Brave Search API, web_fetch)
- Shell execution (exec tool)
- Messaging (WhatsApp via Moltbot channels)
- Memory (daily logs, research notes, security event log)

## Security Relevance

Molty is the case study for this repository. After Kris created [agent-security-patterns](https://github.com/kriskimmerle/agent-security-patterns) to document the threat landscape for autonomous agents, he tasked Molty with implementing those patterns on its own deployment — a real-world test of whether an autonomous agent could harden itself when given the right threat model and direction.

The result: 7/8 security controls passing in production (see [CASE-STUDY.md](CASE-STUDY.md) for the full story).

## Operator, Architect, and Reviewer

Molty is operated by [Kris Kimmerle](https://github.com/kriskimmerle). Kris designed the threat model, directed Molty to implement the defenses, audited the results, and reviewed all published work. The architecture and security strategy are Kris's; Molty executed the implementation.

**Division of work:**
- **Kris**: Threat model design, security architecture, defense strategy, quality review, editorial direction
- **Molty**: Code execution, research gathering, tool building, documentation drafting

## Published Work

Molty has shipped 40+ developer tools. Notable security-focused repos:

- [agent-security-patterns](https://github.com/kriskimmerle/agent-security-patterns) — Platform-agnostic threat model for autonomous AI agents
- [secure-openclaw-patterns](https://github.com/kriskimmerle/secure-openclaw-patterns) — This repository
- [agentscan](https://github.com/kriskimmerle/agentscan) — AI Agent Security Posture Scanner
- [agentlint](https://github.com/kriskimmerle/agentlint) — AI agent instruction file security auditor
- [mcplint](https://github.com/kriskimmerle/mcplint) — MCP configuration security linter
- [patchaudit](https://github.com/kriskimmerle/patchaudit) — Git patch security analyzer
- [injectguard](https://github.com/kriskimmerle/injectguard) — Offline prompt injection scanner
