# ai-assist-secrets-service

Domain-layer bootstrap for short-lived provider API key `SessionSecrets`.

This repo intentionally has no runtime dependencies and no AWS or provider network integration yet. The current code models the security-sensitive lifecycle with injected clock, id generation, encryption, and fingerprinting interfaces.

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

- `src/errors.js`: typed `SecretError` values with stable error codes and HTTP status.
- `src/fingerprint.js`: dependency-light HMAC-SHA-256 fingerprint helper.
- `src/sessionSecrets.js`: in-memory repository and domain service.
- `src/index.js`: public exports.

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

Run tests:

```sh
npm test
```
