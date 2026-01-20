# How to Contribute

Thanks for your interest in contributing to the Cisco Secure Firewall FMC MCP Connector! Here are a few
general guidelines on contributing and reporting bugs that we ask you to review.
Following these guidelines helps to communicate that you respect the time of the
contributors managing and developing this open source project. In return, they
should reciprocate that respect in addressing your issue, assessing changes, and
helping you finalize your pull requests. In that spirit of mutual respect, we
endeavor to review incoming issues and pull requests within 10 days, and will
close any lingering issues or pull requests after 60 days of inactivity.

Please note that all of your interactions in the project are subject to our
[Code of Conduct](/CODE_OF_CONDUCT.md). This includes creation of issues or pull
requests, commenting on issues or pull requests, and extends to all interactions
in any real-time space e.g., Slack, Discord, etc.

## Reporting Issues

Before reporting a new issue, please ensure that the issue was not already
reported or fixed by searching through our [issues
list](https://github.com/CiscoDevNet/CiscoFMC-MCP-server-community/issues).

When creating a new issue, please be sure to include a **title and clear
description**, as much relevant information as possible, and, if possible, a
test case or example demonstrating the issue. Include:

- Steps to reproduce the issue
- Expected behavior vs. actual behavior
- Version/commit information
- Relevant configuration (redact secrets!)
- Log output (sanitized)

**If you discover a security bug, please do not report it through GitHub.
Instead, please see security procedures in [SECURITY.md](/SECURITY.md).**

## Sending Pull Requests

Before sending a new pull request, take a look at existing pull requests and
issues to see if the proposed change or fix has been discussed in the past, or
if the change was already implemented but not yet released.

We expect new pull requests to include tests for any affected behavior, and, as
we follow semantic versioning, we may reserve breaking changes until the next
major version release.

### Development Workflow

1. Fork the repository and create a feature branch:
   ```bash
   git checkout -b feature/<short-name>
   ```

2. Make your changes with appropriate tests:
   - Add tests for new functionality or bug fixes
   - Ensure all tests pass: `python -m pytest tests`
   - Follow existing code style and patterns

3. Ensure your changes meet security requirements:
   - Do not commit secrets; use `.env.example` for examples
   - Do not log or expose FMC credentials/tokens
   - Validate all user inputs properly
   - Consider auth, logging, and input validation implications

4. Open a pull request describing:
   - **What changed** - clear description of the modifications
   - **Why** - the motivation or problem being solved
   - **Security considerations** - any security implications
   - **Testing** - how you tested the changes

### Guidelines

- Keep changes small and focused on a single concern
- Add tests for any new parsing/search behavior
- Prefer configuration via env/profiles; avoid hardcoding
- Follow existing code patterns and structure
- Update documentation if adding new features or changing behavior
- Ensure all existing tests continue to pass

## Other Ways to Contribute

We welcome anyone that wants to contribute to this project to triage and
reply to open issues to help troubleshoot and fix existing bugs. Here is what
you can do:

- Help ensure that existing issues follow the recommendations from the
  _[Reporting Issues](#reporting-issues)_ section, providing feedback to the
  issue's author on what might be missing.
- Review existing pull requests, and test patches against real FMC deployments
  to validate functionality.
- Write additional tests or add missing test cases to improve coverage.
- Improve documentation with clearer examples, additional use cases, or
  troubleshooting tips.
- Help answer questions from other users in issues or discussions.

Thanks again for your interest in contributing to this project!
