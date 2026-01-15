# Contributing

## Workflow
1. Fork and create a feature branch:
   - `git checkout -b feature/<short-name>`
2. Make changes with tests.
3. Run:
   - `python -m pytest tests`
4. Open a PR describing:
   - What changed
   - Why
   - Any security considerations (tokens, logging, auth, input validation)

## Guidelines
- Keep changes small and focused.
- Add tests for any new parsing/search behavior.
- Do not commit secrets; use `.env.example`.
- Prefer configuration via env/profiles; avoid hardcoding.
