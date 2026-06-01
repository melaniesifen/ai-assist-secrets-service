# AGENTS.md

## Repo Purpose

`ai-assist-secrets-service` owns short-lived provider API key records for active sessions. MVP provider keys are encrypted `SessionSecrets` with an 8-hour TTL.

## Agent Instructions

- Read `README.md`, `ai-assist-platform-context.md`, and `../ai-assist-architecture/lld-auth-secrets-tenancy.md` before changing behavior.
- Never return raw provider keys from public methods, tests, examples, errors, logs, or README snippets.
- Validate expiry at read time even if database TTL cleanup has not run.
- Use injected clocks, encryption, and hashing/fingerprinting boundaries.
- Fingerprints must be non-reversible and safe for metadata display.
- Keep persistent remembered-key behavior out of MVP unless explicitly requested and designed separately.
- Keep the Python package dependency-free unless a documented repo-local dependency/tooling manifest is added.
- Add tests for create, resolve, expire, delete, decrypt failure, wrong tenant/user/provider, and metadata-only status responses.

## Commands

- Run tests with `PYTHONPATH=src python3 -m unittest discover -s tests`.
- Run compile checks with `PYTHONPATH=src python3 -m compileall src tests`.
- Do not globally install Python tools. If future work needs Python libraries or tooling beyond the current stdlib-only package, add repo-local manifests and document install/test commands.

## Review Notes

Before committing, review for fail-closed decrypt paths, no secret leakage, TTL correctness, and authorization checks before any provider-call secret resolution.

## Commit Messages

All commits in this repo must use this format:

```text
docs/feat/fix/(or another appropriate type): title of change

problem: <description of problem>
solution: <description of solution>
impact: <impact of this change>
reference: <reference to this change in the docs if applicable>
```
