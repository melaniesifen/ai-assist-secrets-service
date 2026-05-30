import {
  SECRET_ERROR_CODES,
  SecretError,
  forbidden,
  validationFailed
} from "./errors.js";

export const SESSION_SECRET_STATUS = Object.freeze({
  ACTIVE: "active",
  EXPIRED: "expired",
  DELETED: "deleted"
});

export const SUPPORTED_SECRET_PROVIDERS = Object.freeze({
  OPENAI: "openai",
  ANTHROPIC: "anthropic"
});

export const SESSION_SECRET_VALIDATION_STATUS = Object.freeze({
  NOT_VALIDATED: "not_validated",
  VALID: "valid",
  INVALID: "invalid"
});

export const DEFAULT_SESSION_SECRET_TTL_MS = 8 * 60 * 60 * 1000;
export const MAX_SESSION_SECRET_TTL_MS = DEFAULT_SESSION_SECRET_TTL_MS;
export const SESSION_SECRET_PURPOSE = "session-secret";

export class InMemorySessionSecretRepository {
  constructor() {
    this.records = new Map();
  }

  save(record) {
    this.records.set(record.secretId, cloneRecord(record));
    return cloneRecord(record);
  }

  getById(secretId) {
    const record = this.records.get(secretId);
    return record ? cloneRecord(record) : null;
  }

  findLatest({ tenantId, userId, provider }) {
    const matches = [...this.records.values()]
      .filter(
        (record) =>
          record.tenantId === tenantId && record.userId === userId && record.provider === provider
      )
      .sort((left, right) => {
        const createdAtOrder = right.createdAt.getTime() - left.createdAt.getTime();
        if (createdAtOrder !== 0) {
          return createdAtOrder;
        }
        return right.secretId.localeCompare(left.secretId);
      });
    return matches[0] ? cloneRecord(matches[0]) : null;
  }
}

export class SessionSecretsService {
  constructor({
    repository,
    encryptor,
    fingerprintHasher,
    clock = () => new Date(),
    idGenerator
  }) {
    if (!repository) {
      throw new TypeError("repository is required.");
    }
    if (!encryptor || typeof encryptor.encrypt !== "function" || typeof encryptor.decrypt !== "function") {
      throw new TypeError("encryptor with encrypt and decrypt methods is required.");
    }
    if (!fingerprintHasher || typeof fingerprintHasher.fingerprint !== "function") {
      throw new TypeError("fingerprintHasher.fingerprint is required.");
    }
    if (typeof idGenerator !== "function") {
      throw new TypeError("idGenerator is required.");
    }
    this.repository = repository;
    this.encryptor = encryptor;
    this.fingerprintHasher = fingerprintHasher;
    this.clock = clock;
    this.idGenerator = idGenerator;
  }

  createSessionSecret({
    identity,
    provider,
    secretValue,
    ttlMs = DEFAULT_SESSION_SECRET_TTL_MS,
    validationStatus = "not_validated",
    lastValidatedAt = null
  }) {
    const owner = requireIdentity(identity);
    const normalizedProvider = requireProvider(provider);
    const normalizedSecret = requireSecretValue(secretValue);
    const normalizedTtlMs = validateTtlMs(ttlMs);
    const normalizedValidationStatus = requireValidationStatus(validationStatus);
    const now = this.clock();
    const validationTimestamp =
      normalizedValidationStatus === SESSION_SECRET_VALIDATION_STATUS.NOT_VALIDATED
        ? cloneDate(lastValidatedAt)
        : cloneDate(lastValidatedAt) ?? now;
    const secretId = this.idGenerator();
    requireNonEmptyString(secretId, "secretId");
    const context = encryptionContext(owner, normalizedProvider);
    const record = {
      tenantId: owner.tenantId,
      userId: owner.userId,
      provider: normalizedProvider,
      secretId,
      secretCiphertext: this.encryptor.encrypt(normalizedSecret, { context }),
      fingerprint: this.fingerprintHasher.fingerprint(normalizedSecret),
      status: SESSION_SECRET_STATUS.ACTIVE,
      validationStatus: normalizedValidationStatus,
      createdAt: now,
      lastValidatedAt: validationTimestamp,
      expiresAt: new Date(now.getTime() + normalizedTtlMs)
    };
    return metadata(this.repository.save(record), now);
  }

  getSessionSecretStatus({ identity, provider }) {
    const owner = requireIdentity(identity);
    const normalizedProvider = requireProvider(provider);
    const record = this.repository.findLatest({
      tenantId: owner.tenantId,
      userId: owner.userId,
      provider: normalizedProvider
    });
    if (!record) {
      return {
        tenantId: owner.tenantId,
        userId: owner.userId,
        provider: normalizedProvider,
        available: false,
        status: "missing"
      };
    }
    const current = this.applyReadTimeExpiry(record);
    return {
      ...metadata(current, this.clock()),
      available: current.status === SESSION_SECRET_STATUS.ACTIVE
    };
  }

  resolveSessionSecret({ identity, provider }) {
    const owner = requireIdentity(identity);
    const normalizedProvider = requireProvider(provider);
    const record = this.repository.findLatest({
      tenantId: owner.tenantId,
      userId: owner.userId,
      provider: normalizedProvider
    });
    return metadata(this.requireReadableRecord(record, owner, normalizedProvider), this.clock());
  }

  decryptForProviderCall({ identity, secretId, provider }) {
    const owner = requireIdentity(identity);
    const normalizedProvider = requireProvider(provider);
    requireNonEmptyString(secretId, "secretId");
    const record = this.repository.getById(secretId);
    const readable = this.requireReadableRecord(record, owner, normalizedProvider);
    try {
      return {
        secretId: readable.secretId,
        tenantId: readable.tenantId,
        userId: readable.userId,
        provider: readable.provider,
        secretValue: this.encryptor.decrypt(readable.secretCiphertext, {
          context: encryptionContext(owner, normalizedProvider)
        })
      };
    } catch (cause) {
      throw new SecretError({
        code: SECRET_ERROR_CODES.SECRET_DECRYPT_FAILED,
        message: "Session secret could not be decrypted.",
        status: 500,
        details: { secretId: readable.secretId, provider: readable.provider, cause: cause.name ?? "Error" }
      });
    }
  }

  expireSessionSecret({ identity, secretId, provider, expiredAt = this.clock() }) {
    const owner = requireIdentity(identity);
    const normalizedProvider = requireProvider(provider);
    requireNonEmptyString(secretId, "secretId");
    const record = this.repository.getById(secretId);
    if (!record) {
      throw notFound();
    }
    assertOwner(record, owner, normalizedProvider);
    record.status = SESSION_SECRET_STATUS.EXPIRED;
    record.expiresAt = cloneDate(expiredAt);
    record.secretCiphertext = null;
    return metadata(this.repository.save(record), this.clock());
  }

  deleteSessionSecret({ identity, secretId, provider, deletedAt = this.clock() }) {
    const owner = requireIdentity(identity);
    const normalizedProvider = requireProvider(provider);
    requireNonEmptyString(secretId, "secretId");
    const record = this.repository.getById(secretId);
    if (!record) {
      throw notFound();
    }
    assertOwner(record, owner, normalizedProvider);
    record.status = SESSION_SECRET_STATUS.DELETED;
    record.expiresAt = cloneDate(deletedAt);
    record.secretCiphertext = null;
    return metadata(this.repository.save(record), this.clock());
  }

  requireReadableRecord(record, owner, provider) {
    if (!record) {
      throw notFound();
    }
    assertOwner(record, owner, provider);
    const current = this.applyReadTimeExpiry(record);
    if (current.status === SESSION_SECRET_STATUS.DELETED) {
      throw new SecretError({
        code: SECRET_ERROR_CODES.PROVIDER_SECRET_DELETED,
        message: "Session secret has been deleted.",
        status: 403,
        details: { secretId: current.secretId, provider: current.provider }
      });
    }
    if (current.status !== SESSION_SECRET_STATUS.ACTIVE || current.expiresAt <= this.clock()) {
      throw expired(current);
    }
    return current;
  }

  applyReadTimeExpiry(record) {
    if (
      record.status === SESSION_SECRET_STATUS.ACTIVE &&
      record.expiresAt <= this.clock()
    ) {
      const expiredRecord = {
        ...record,
        status: SESSION_SECRET_STATUS.EXPIRED,
        secretCiphertext: null
      };
      return this.repository.save(expiredRecord);
    }
    return record;
  }
}

function requireIdentity(identity) {
  if (!identity || !identity.tenantId || !identity.userId) {
    throw forbidden();
  }
  return {
    tenantId: requireNonEmptyString(identity.tenantId, "identity.tenantId"),
    userId: requireNonEmptyString(identity.userId, "identity.userId")
  };
}

function requireProvider(provider) {
  const normalized = requireNonEmptyString(provider, "provider").trim().toLowerCase();
  if (!Object.values(SUPPORTED_SECRET_PROVIDERS).includes(normalized)) {
    throw validationFailed("provider", "provider must be one of: openai, anthropic.");
  }
  return normalized;
}

function requireSecretValue(secretValue) {
  if (typeof secretValue !== "string" || secretValue.trim().length === 0) {
    throw validationFailed("secretValue", "Provider secret value is required.");
  }
  return secretValue;
}

function validateTtlMs(ttlMs) {
  if (!Number.isInteger(ttlMs) || ttlMs <= 0 || ttlMs > MAX_SESSION_SECRET_TTL_MS) {
    throw validationFailed(
      "ttlMs",
      `Session secret TTL must be an integer between 1 and ${MAX_SESSION_SECRET_TTL_MS}.`
    );
  }
  return ttlMs;
}

function requireValidationStatus(validationStatus) {
  if (!Object.values(SESSION_SECRET_VALIDATION_STATUS).includes(validationStatus)) {
    throw validationFailed(
      "validationStatus",
      "validationStatus must be not_validated, valid, or invalid."
    );
  }
  return validationStatus;
}

function assertOwner(record, owner, provider) {
  if (record.tenantId !== owner.tenantId || record.userId !== owner.userId || record.provider !== provider) {
    throw forbidden();
  }
}

function encryptionContext(owner, provider) {
  return Object.freeze({
    tenantId: owner.tenantId,
    userId: owner.userId,
    provider,
    purpose: SESSION_SECRET_PURPOSE
  });
}

function metadata(record, now) {
  return Object.freeze({
    tenantId: record.tenantId,
    userId: record.userId,
    provider: record.provider,
    secretId: record.secretId,
    fingerprint: record.fingerprint,
    status: record.status,
    validationStatus: record.validationStatus,
    createdAt: toIso(record.createdAt),
    lastValidatedAt: toIso(record.lastValidatedAt),
    expiresAt: toIso(record.expiresAt),
    isExpired: record.expiresAt <= now
  });
}

function notFound() {
  return new SecretError({
    code: SECRET_ERROR_CODES.PROVIDER_SECRET_NOT_FOUND,
    message: "Session secret is not available.",
    status: 403
  });
}

function expired(record) {
  return new SecretError({
    code: SECRET_ERROR_CODES.PROVIDER_SECRET_EXPIRED,
    message: "Session secret has expired.",
    status: 403,
    details: { secretId: record.secretId, provider: record.provider }
  });
}

function requireNonEmptyString(value, field) {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw validationFailed(field, `${field} must be a non-empty string.`);
  }
  return value;
}

function cloneDate(value) {
  return value ? new Date(value.getTime()) : null;
}

function toIso(value) {
  return value instanceof Date ? value.toISOString() : null;
}

function cloneRecord(record) {
  return {
    ...record,
    createdAt: cloneDate(record.createdAt),
    lastValidatedAt: cloneDate(record.lastValidatedAt),
    expiresAt: cloneDate(record.expiresAt)
  };
}
