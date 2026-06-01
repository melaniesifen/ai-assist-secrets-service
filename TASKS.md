# Task Breakdown

Update this file as implementation progresses. Check off completed tasks in the same change that implements or verifies them.

Sources:

- `../ai-assist-architecture/implementation-task-breakdown.md`
- `../ai-assist-architecture/lld-auth-secrets-tenancy.md`

## Completed Bootstrap

- [x] Initially bootstrap dependency-light ESM session-secret domain logic; superseded by the completed Python migration in `REPO-002`.
- [x] `AUTH-004`: Implement `SessionSecrets` lifecycle domain logic scoped by `tenantId`, `userId`, and provider.
- [x] `AUTH-004`: Store encrypted secret material behind an injected encryption boundary.
- [x] `AUTH-004`: Add non-reversible fingerprint helper.
- [x] `AUTH-004`: Enforce 8-hour default TTL and read-time expiry.
- [x] `AUTH-004`: Add metadata-only create, status, expire, and delete responses.
- [x] `AUTH-004`: Add internal decrypt-by-reference behavior for authorized provider call paths.
- [x] Initially add unit tests using `node:test`; superseded by equivalent Python `unittest` coverage in `REPO-002`.
- [x] Document current Python test commands in `README.md`.
- [x] Ignore local prompts, feedback, coverage output, dependencies, and build artifacts.

## Pending Architecture Tasks

- [ ] `REPO-001`: Decide final package structure, language, framework, package manager, and production module layout for this repo.
- [x] `REPO-002`: Migrate the secrets service from the JavaScript ESM bootstrap to Python while preserving or intentionally superseding current `SessionSecrets` lifecycle behavior.
- [x] `REPO-002`: Port or replace existing `node:test` coverage with equivalent Python tests and document the Python package layout and local test commands.
- [x] Migration gate: Do not continue broad new secrets-service feature work until the Python migration is completed or explicitly deferred.
- [ ] `AUTH-004`: Add production `SessionSecrets` persistence with partition/sort key shape from the LLD.
- [ ] `AUTH-004`: Add DynamoDB repository with TTL support.
- [ ] `AUTH-004`: Ensure expired, deleted, and missing secrets return the final typed re-enter-key error used by orchestration.
- [ ] `AUTH-004`: Add integration tests for create, status, validate, delete, TTL expiry, and decrypt-by-reference flows.
- [ ] `AUTH-005`: Add provider-key validation coordination with provider adapters before storing or activating keys.
- [ ] `AUTH-005`: Ensure failed validation returns a typed validation error without storing raw key material.
- [ ] `AUTH-005`: Add validation-attempt rate-limit integration.
- [ ] `AUTH-006`: Add KMS encrypt/decrypt adapter with tenant, user, provider, and purpose encryption context.
- [ ] `AUTH-006`: Enforce least-privilege decrypt boundary so only authorized secrets-service paths can decrypt provider `SessionSecrets`.
- [ ] `AUTH-006`: Add failure-mode validation for KMS errors, IAM deny paths, repository timeouts, and invalid provider credentials.
- [ ] `EVT-001`: Add HTTP route handlers for provider-secret create, status, validate, and delete commands.
- [ ] `EVT-001`: Add internal decrypt-by-reference endpoint restricted to orchestration/provider call paths.
- [ ] `OPS-001`: Ensure provider-secret create and validation endpoints are covered by MVP edge rate-limit configuration.
- [ ] `OPS-003`: Add metadata-only audit events for provider secret created, validated, expired, deleted, and denied access.

## Quality And Production Tasks

- [ ] Raise line coverage to at least 95%.
- [ ] Add explicit persistent remembered-key design only if product scope requires it.
- [ ] Add tenant-managed provider credential support if needed.
- [ ] Add secret rotation and deletion UX contract support.
- [ ] Add deployment-style pipeline tasks for DynamoDB TTL checks, KMS policy validation, route smoke tests, and rollback notes.
