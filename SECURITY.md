# Security Policy

## Supported Versions
This project is intended for lab/dev use unless you harden the deployment (see "Deployment hardening").

## Reporting a Vulnerability
If you discover a security issue, please do **not** open a public GitHub issue.

Instead, report privately:
- Create a GitHub Security Advisory (preferred), or
- Contact the maintainer via the email listed on the repository profile.

Please include:
- Impact summary (what an attacker could do)
- Steps to reproduce (minimal PoC if possible)
- Affected version/commit
- Logs/sanitized configs (remove tokens/passwords)

## Sensitive Data
Never share:
- FMC usernames/passwords
- FMC access tokens
- `.env` files containing secrets
- Private IPs if they are customer/production related

Use `.env.example` and redaction when sharing configs.

## Deployment hardening (recommended)
If exposing MCP over the network:
- Put the server behind HTTPS (reverse proxy) and restrict inbound access (IP allow-list/VPN).
- Add auth at the proxy layer (mTLS / OIDC / API key) because client enforcement may vary.
- Run with least privilege FMC roles; use dedicated API users.
- Enable logging at INFO in production; avoid DEBUG unless troubleshooting.
