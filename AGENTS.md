# AGENTS.md

This repo is a Model Context Protocol (MCP) server that connects to Cisco Secure Firewall Management Center (FMC)
and exposes safe, high-level tools for querying policies/rules.

## Non-negotiable guardrails
- Never add code that logs, prints, or returns FMC credentials/tokens.
- Never weaken input validation for indicators (IP/CIDR/range/FQDN/identity indicators).
- Any new tool must enforce: validation -> least-privilege API calls -> bounded pagination -> redaction.
- Do not introduce “execute/change” capabilities unless explicitly requested (this project is primarily read/query).

## Setup commands
- Create venv: `python -m venv .venv && source .venv/bin/activate`
- Install deps: `pip install -r requirements.txt`
- Run tests: `python -m pytest tests`
- Run server (local): `python -m sfw_mcp_fmc.server`
- Run server (docker): `docker compose up -d --build`

## Code style & quality
- Prefer small modules, SOLID boundaries, and explicit error handling.
- Add/extend unit tests for parsing + search logic.
- Do not add heavy dependencies unless necessary.
- Keep API calls time-bounded and handle FMC pagination safely.

## Security checks before PR
- Ensure `.env` is NOT committed.
- Ensure logs don’t include secrets.
- Ensure any new endpoint/tool has input validation + output redaction.
