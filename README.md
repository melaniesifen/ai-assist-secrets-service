# ai-assist-secrets-service

Domain-layer Python package for short-lived provider API key `SessionSecrets`.

This repo intentionally has no runtime dependencies beyond the Python standard library and no AWS or provider network integration yet. The current code models the security-sensitive lifecycle with injected clock, id generation, encryption, and fingerprinting interfaces.

## Current Boundary

The service owns:

- Creating encrypted `SessionSecrets` scoped by `tenantId`, `userId`, and provider.
- Non-reversible fingerprints for display, deduplication, and debugging metadata.
- Default 8-hour TTL and read-time expiry enforcement.
- Metadata-only status responses.
- Internal decrypt-by-reference for authorized provider call paths.
- Explicit expire and delete behavior.

The service does not own:

- Product authentication.
- OAuth tokens.
- Provider model request construction.
- Provider key network validation.
- HTTP routing.
- KMS or DynamoDB integrations.

## Domain Modules

- `src/ai_assist_secrets_service/errors.py`: typed `SecretError` values with stable error codes and HTTP status.
- `src/ai_assist_secrets_service/fingerprint.py`: dependency-light HMAC-SHA-256 fingerprint helper.
- `src/ai_assist_secrets_service/session_secrets.py`: in-memory repository and domain service.
- `src/ai_assist_secrets_service/__init__.py`: public exports.
- `tests/test_session_secrets.py`: stdlib `unittest` lifecycle coverage.
- `pyproject.toml`: package metadata and `src/` package discovery.

## Security Invariants

- Secret values are never returned by create, status, expire, or delete methods.
- Ciphertext is not included in public metadata outputs.
- Expired secrets are rejected at read time even if the repository row still exists.
- Delete and expiry clear ciphertext before later reads.
- Encryption context includes `tenantId`, `userId`, `provider`, and `purpose=session-secret`.

## Future Adapters

Planned AWS and provider integrations should wrap the existing domain contracts:

- KMS encryptor implementing `encrypt(plaintext, { context })` and `decrypt(ciphertext, { context })`.
- DynamoDB repository implementing the same repository shape as `InMemorySessionSecretRepository`.
- Provider validation adapter called before or after `createSessionSecret`.
- HTTP handlers for `POST /provider-secrets/session`, `GET /provider-secrets/session/{provider}/status`, and `DELETE /provider-secrets/session/{provider}`.
- Internal decrypt-by-reference handler restricted to orchestration/provider call paths.

## Task Breakdown

Implementation tasks are tracked in [TASKS.md](TASKS.md). Update the checkboxes there in the same change that implements or verifies a task.

## Testing And Coverage

Run the unit tests with:

```sh
PYTHONPATH=src python3 -m unittest discover -s tests
```

Compile the package and tests with:

```sh
PYTHONPATH=src python3 -m compileall src tests
```

No package install is required for local tests. The committed `pyproject.toml`
documents the package name and `src/` package discovery; runtime and test code
remain stdlib-only.

Coverage tooling is not committed yet because the local migration intentionally uses stdlib-only tests. If coverage tooling is added later, keep generated HTML, LCOV, XML, and cache output ignored.
