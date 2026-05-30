import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  DEFAULT_SESSION_SECRET_TTL_MS,
  InMemorySessionSecretRepository,
  SECRET_ERROR_CODES,
  SESSION_SECRET_STATUS,
  SESSION_SECRET_VALIDATION_STATUS,
  SessionSecretsService,
  createHmacFingerprintHasher
} from "../src/index.js";

const BASE_TIME = new Date("2026-05-29T12:00:00.000Z");
const VALIDATED_AT = new Date("2026-05-29T11:59:00.000Z");
const IDENTITY = Object.freeze({ tenantId: "tenant-1", userId: "user-1" });

describe("SessionSecretsService", () => {
  it("creates encrypted metadata-only SessionSecrets with default 8 hour TTL", () => {
    const { service, encryptor } = createFixture();

    const metadata = service.createSessionSecret({
      identity: IDENTITY,
      provider: " OpenAI ",
      secretValue: "sk-test-provider-key",
      validationStatus: SESSION_SECRET_VALIDATION_STATUS.VALID,
      lastValidatedAt: VALIDATED_AT
    });

    assert.equal(metadata.provider, "openai");
    assert.equal(metadata.status, SESSION_SECRET_STATUS.ACTIVE);
    assert.equal(metadata.validationStatus, SESSION_SECRET_VALIDATION_STATUS.VALID);
    assert.equal(metadata.expiresAt, new Date(BASE_TIME.getTime() + DEFAULT_SESSION_SECRET_TTL_MS).toISOString());
    assert.match(metadata.fingerprint, /^hmac-sha256:[a-f0-9]{16}$/);
    assert.equal(metadata.secretValue, undefined);
    assert.equal(metadata.secretCiphertext, undefined);
    assert.equal(JSON.stringify(metadata).includes("provider-key"), false);
    assert.deepEqual(encryptor.encryptCalls[0].context, {
      tenantId: "tenant-1",
      userId: "user-1",
      provider: "openai",
      purpose: "session-secret"
    });
  });

  it("decrypts only through the internal provider-call path with matching owner and provider", () => {
    const { service } = createFixture();
    const metadata = service.createSessionSecret({
      identity: IDENTITY,
      provider: "anthropic",
      secretValue: "anthropic-key"
    });

    const resolved = service.resolveSessionSecret({
      identity: IDENTITY,
      provider: "anthropic"
    });
    const decrypted = service.decryptForProviderCall({
      identity: IDENTITY,
      secretId: metadata.secretId,
      provider: "anthropic"
    });

    assert.equal(resolved.secretId, metadata.secretId);
    assert.equal(resolved.secretValue, undefined);
    assert.equal(decrypted.secretValue, "anthropic-key");
    assertAuthzDenied(() =>
      service.decryptForProviderCall({
        identity: { tenantId: "tenant-2", userId: "user-1" },
        secretId: metadata.secretId,
        provider: "anthropic"
      })
    );
  });

  it("rejects expired secrets at read time and clears ciphertext", () => {
    const mutableNow = { value: BASE_TIME };
    const { service, repository } = createFixture({ clock: () => mutableNow.value });
    const metadata = service.createSessionSecret({
      identity: IDENTITY,
      provider: "openai",
      secretValue: "sk-test-provider-key",
      ttlMs: 1
    });
    mutableNow.value = new Date(BASE_TIME.getTime() + 1);

    assertSecretError(
      () => service.resolveSessionSecret({ identity: IDENTITY, provider: "openai" }),
      SECRET_ERROR_CODES.PROVIDER_SECRET_EXPIRED,
      403
    );
    const stored = repository.getById(metadata.secretId);
    assert.equal(stored.status, SESSION_SECRET_STATUS.EXPIRED);
    assert.equal(stored.secretCiphertext, null);
  });

  it("delete and explicit expire return safe metadata and reject later use", () => {
    const { service, repository } = createFixture();
    const metadata = service.createSessionSecret({
      identity: IDENTITY,
      provider: "openai",
      secretValue: "sk-test-provider-key"
    });

    const deleted = service.deleteSessionSecret({
      identity: IDENTITY,
      provider: "openai",
      secretId: metadata.secretId
    });

    assert.equal(deleted.status, SESSION_SECRET_STATUS.DELETED);
    assert.equal(repository.getById(metadata.secretId).secretCiphertext, null);
    assertSecretError(
      () =>
        service.decryptForProviderCall({
          identity: IDENTITY,
          provider: "openai",
          secretId: metadata.secretId
        }),
      SECRET_ERROR_CODES.PROVIDER_SECRET_DELETED,
      403
    );

    const second = service.createSessionSecret({
      identity: IDENTITY,
      provider: "openai",
      secretValue: "sk-second-provider-key"
    });
    const expired = service.expireSessionSecret({
      identity: IDENTITY,
      provider: "openai",
      secretId: second.secretId
    });
    assert.equal(expired.status, SESSION_SECRET_STATUS.EXPIRED);
    assertSecretError(
      () => service.resolveSessionSecret({ identity: IDENTITY, provider: "openai" }),
      SECRET_ERROR_CODES.PROVIDER_SECRET_EXPIRED,
      403
    );
  });

  it("validates TTL and secret value on create", () => {
    const { service } = createFixture();

    assertSecretError(
      () =>
        service.createSessionSecret({
          identity: IDENTITY,
          provider: "openai",
          secretValue: "   "
        }),
      SECRET_ERROR_CODES.VALIDATION_FAILED,
      400
    );
    assertSecretError(
      () =>
        service.createSessionSecret({
          identity: IDENTITY,
          provider: "openai",
          secretValue: "sk-test-provider-key",
          ttlMs: DEFAULT_SESSION_SECRET_TTL_MS + 1
        }),
      SECRET_ERROR_CODES.VALIDATION_FAILED,
      400
    );
    assertSecretError(
      () =>
        service.createSessionSecret({
          identity: IDENTITY,
          provider: "bedrock",
          secretValue: "sk-test-provider-key"
        }),
      SECRET_ERROR_CODES.VALIDATION_FAILED,
      400
    );
    assertSecretError(
      () =>
        service.createSessionSecret({
          identity: IDENTITY,
          provider: "openai",
          secretValue: "sk-test-provider-key",
          validationStatus: "maybe_valid"
        }),
      SECRET_ERROR_CODES.VALIDATION_FAILED,
      400
    );
  });

  it("preserves validation status through status and resolve metadata", () => {
    const { service } = createFixture();
    const created = service.createSessionSecret({
      identity: IDENTITY,
      provider: "anthropic",
      secretValue: "anthropic-key",
      validationStatus: SESSION_SECRET_VALIDATION_STATUS.VALID
    });

    const status = service.getSessionSecretStatus({ identity: IDENTITY, provider: "anthropic" });
    const resolved = service.resolveSessionSecret({ identity: IDENTITY, provider: "anthropic" });

    assert.equal(created.validationStatus, SESSION_SECRET_VALIDATION_STATUS.VALID);
    assert.equal(created.lastValidatedAt, BASE_TIME.toISOString());
    assert.equal(status.validationStatus, SESSION_SECRET_VALIDATION_STATUS.VALID);
    assert.equal(resolved.validationStatus, SESSION_SECRET_VALIDATION_STATUS.VALID);
    assert.equal(JSON.stringify(status).includes("anthropic-key"), false);
  });

  it("reports missing status without leaking whether other tenants have secrets", () => {
    const { service } = createFixture();
    service.createSessionSecret({
      identity: IDENTITY,
      provider: "openai",
      secretValue: "sk-test-provider-key"
    });

    const status = service.getSessionSecretStatus({
      identity: { tenantId: "tenant-2", userId: "user-1" },
      provider: "openai"
    });

    assert.equal(status.available, false);
    assert.equal(status.status, "missing");
    assert.equal(status.secretId, undefined);
  });

  it("wraps decrypt failures as typed fail-closed errors", () => {
    const { service, encryptor } = createFixture();
    const metadata = service.createSessionSecret({
      identity: IDENTITY,
      provider: "openai",
      secretValue: "sk-test-provider-key"
    });
    encryptor.failDecrypt = true;

    assertSecretError(
      () =>
        service.decryptForProviderCall({
          identity: IDENTITY,
          provider: "openai",
          secretId: metadata.secretId
        }),
      SECRET_ERROR_CODES.SECRET_DECRYPT_FAILED,
      500
    );
  });
});

function createFixture({ clock = () => BASE_TIME } = {}) {
  const repository = new InMemorySessionSecretRepository();
  const encryptor = fakeEncryptor();
  const fingerprintHasher = createHmacFingerprintHasher({
    key: "test-fingerprint-key-material"
  });
  let idCounter = 0;
  const service = new SessionSecretsService({
    repository,
    encryptor,
    fingerprintHasher,
    clock,
    idGenerator: () => `secret-${++idCounter}`
  });
  return { service, repository, encryptor };
}

function fakeEncryptor() {
  const plaintextByCiphertext = new Map();
  return {
    encryptCalls: [],
    failDecrypt: false,
    encrypt(plaintext, { context }) {
      const ciphertext = `ciphertext:${context.provider}:${plaintext.length}:${plaintextByCiphertext.size + 1}`;
      plaintextByCiphertext.set(ciphertext, plaintext);
      this.encryptCalls.push({ plaintext, context });
      return ciphertext;
    },
    decrypt(ciphertext) {
      if (this.failDecrypt) {
        throw new Error("decrypt failed");
      }
      return plaintextByCiphertext.get(ciphertext);
    }
  };
}

function assertSecretError(fn, code, status) {
  assert.throws(
    fn,
    (error) => error?.name === "SecretError" && error.code === code && error.status === status
  );
}

function assertAuthzDenied(fn) {
  assertSecretError(fn, SECRET_ERROR_CODES.TENANT_ACCESS_DENIED, 403);
}
