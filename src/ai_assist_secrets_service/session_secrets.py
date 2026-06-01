from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone

from .errors import SecretError, SecretErrorCodes, forbidden, validation_failed


class SessionSecretStatus:
    ACTIVE = "active"
    EXPIRED = "expired"
    DELETED = "deleted"


class SupportedSecretProviders:
    OPENAI = "openai"
    ANTHROPIC = "anthropic"


class SessionSecretValidationStatus:
    NOT_VALIDATED = "not_validated"
    VALID = "valid"
    INVALID = "invalid"


DEFAULT_SESSION_SECRET_TTL_MS = 8 * 60 * 60 * 1000
MAX_SESSION_SECRET_TTL_MS = DEFAULT_SESSION_SECRET_TTL_MS
SESSION_SECRET_PURPOSE = "session-secret"
SUPPORTED_PROVIDER_VALUES = {
    SupportedSecretProviders.OPENAI,
    SupportedSecretProviders.ANTHROPIC,
}
VALIDATION_STATUS_VALUES = {
    SessionSecretValidationStatus.NOT_VALIDATED,
    SessionSecretValidationStatus.VALID,
    SessionSecretValidationStatus.INVALID,
}


@dataclass(frozen=True)
class SessionSecretRecord:
    tenant_id: str
    user_id: str
    provider: str
    secret_id: str
    secret_ciphertext: str | None
    fingerprint: str
    status: str
    validation_status: str
    created_at: datetime
    last_validated_at: datetime | None
    expires_at: datetime


class InMemorySessionSecretRepository:
    def __init__(self):
        self._records = {}

    def save(self, record):
        self._records[record.secret_id] = record
        return record

    def get_by_id(self, secret_id):
        return self._records.get(secret_id)

    def find_latest(self, *, tenant_id, user_id, provider):
        matches = [
            record
            for record in self._records.values()
            if record.tenant_id == tenant_id
            and record.user_id == user_id
            and record.provider == provider
        ]
        matches.sort(key=lambda record: (record.created_at, record.secret_id), reverse=True)
        return matches[0] if matches else None


class SessionSecretsService:
    def __init__(
        self,
        *,
        repository,
        encryptor,
        fingerprint_hasher,
        clock=None,
        id_generator=None,
    ):
        if repository is None:
            raise TypeError("repository is required.")
        if (
            encryptor is None
            or not callable(getattr(encryptor, "encrypt", None))
            or not callable(getattr(encryptor, "decrypt", None))
        ):
            raise TypeError("encryptor with encrypt and decrypt methods is required.")
        if fingerprint_hasher is None or not callable(getattr(fingerprint_hasher, "fingerprint", None)):
            raise TypeError("fingerprint_hasher.fingerprint is required.")
        if not callable(id_generator):
            raise TypeError("id_generator is required.")
        self.repository = repository
        self.encryptor = encryptor
        self.fingerprint_hasher = fingerprint_hasher
        self.clock = clock or _utc_now
        self.id_generator = id_generator

    def create_session_secret(
        self,
        *,
        identity,
        provider,
        secret_value,
        ttl_ms=DEFAULT_SESSION_SECRET_TTL_MS,
        validation_status=SessionSecretValidationStatus.NOT_VALIDATED,
        last_validated_at=None,
    ):
        owner = _require_identity(identity)
        normalized_provider = _require_provider(provider)
        normalized_secret = _require_secret_value(secret_value)
        normalized_ttl_ms = _validate_ttl_ms(ttl_ms)
        normalized_validation_status = _require_validation_status(validation_status)
        now = self.clock()
        validation_timestamp = (
            last_validated_at
            if normalized_validation_status == SessionSecretValidationStatus.NOT_VALIDATED
            else last_validated_at or now
        )
        secret_id = self.id_generator()
        _require_non_empty_string(secret_id, "secret_id")
        context = encryption_context(owner, normalized_provider)
        record = SessionSecretRecord(
            tenant_id=owner["tenant_id"],
            user_id=owner["user_id"],
            provider=normalized_provider,
            secret_id=secret_id,
            secret_ciphertext=self.encryptor.encrypt(normalized_secret, context=context),
            fingerprint=self.fingerprint_hasher.fingerprint(normalized_secret),
            status=SessionSecretStatus.ACTIVE,
            validation_status=normalized_validation_status,
            created_at=now,
            last_validated_at=validation_timestamp,
            expires_at=now + timedelta(milliseconds=normalized_ttl_ms),
        )
        return metadata(self.repository.save(record), now)

    def get_session_secret_status(self, *, identity, provider):
        owner = _require_identity(identity)
        normalized_provider = _require_provider(provider)
        record = self.repository.find_latest(
            tenant_id=owner["tenant_id"],
            user_id=owner["user_id"],
            provider=normalized_provider,
        )
        if record is None:
            return {
                "tenantId": owner["tenant_id"],
                "userId": owner["user_id"],
                "provider": normalized_provider,
                "available": False,
                "status": "missing",
            }
        current = self.apply_read_time_expiry(record)
        return {
            **metadata(current, self.clock()),
            "available": current.status == SessionSecretStatus.ACTIVE,
        }

    def resolve_session_secret(self, *, identity, provider):
        owner = _require_identity(identity)
        normalized_provider = _require_provider(provider)
        record = self.repository.find_latest(
            tenant_id=owner["tenant_id"],
            user_id=owner["user_id"],
            provider=normalized_provider,
        )
        return metadata(
            self.require_readable_record(record, owner, normalized_provider),
            self.clock(),
        )

    def decrypt_for_provider_call(self, *, identity, secret_id, provider):
        owner = _require_identity(identity)
        normalized_provider = _require_provider(provider)
        _require_non_empty_string(secret_id, "secret_id")
        record = self.repository.get_by_id(secret_id)
        readable = self.require_readable_record(record, owner, normalized_provider)
        try:
            return {
                "secretId": readable.secret_id,
                "tenantId": readable.tenant_id,
                "userId": readable.user_id,
                "provider": readable.provider,
                "secretValue": self.encryptor.decrypt(
                    readable.secret_ciphertext,
                    context=encryption_context(owner, normalized_provider),
                ),
            }
        except Exception as cause:
            raise SecretError(
                code=SecretErrorCodes.SECRET_DECRYPT_FAILED,
                message="Session secret could not be decrypted.",
                status=500,
                details={
                    "secretId": readable.secret_id,
                    "provider": readable.provider,
                    "cause": cause.__class__.__name__,
                },
            ) from cause

    def expire_session_secret(self, *, identity, secret_id, provider, expired_at=None):
        owner = _require_identity(identity)
        normalized_provider = _require_provider(provider)
        _require_non_empty_string(secret_id, "secret_id")
        record = self.repository.get_by_id(secret_id)
        if record is None:
            raise _not_found()
        _assert_owner(record, owner, normalized_provider)
        expired = replace(
            record,
            status=SessionSecretStatus.EXPIRED,
            expires_at=expired_at or self.clock(),
            secret_ciphertext=None,
        )
        return metadata(self.repository.save(expired), self.clock())

    def delete_session_secret(self, *, identity, secret_id, provider, deleted_at=None):
        owner = _require_identity(identity)
        normalized_provider = _require_provider(provider)
        _require_non_empty_string(secret_id, "secret_id")
        record = self.repository.get_by_id(secret_id)
        if record is None:
            raise _not_found()
        _assert_owner(record, owner, normalized_provider)
        deleted = replace(
            record,
            status=SessionSecretStatus.DELETED,
            expires_at=deleted_at or self.clock(),
            secret_ciphertext=None,
        )
        return metadata(self.repository.save(deleted), self.clock())

    def require_readable_record(self, record, owner, provider):
        if record is None:
            raise _not_found()
        _assert_owner(record, owner, provider)
        current = self.apply_read_time_expiry(record)
        if current.status == SessionSecretStatus.DELETED:
            raise SecretError(
                code=SecretErrorCodes.PROVIDER_SECRET_DELETED,
                message="Session secret has been deleted.",
                status=403,
                details={"secretId": current.secret_id, "provider": current.provider},
            )
        if current.status != SessionSecretStatus.ACTIVE or current.expires_at <= self.clock():
            raise _expired(current)
        return current

    def apply_read_time_expiry(self, record):
        if record.status == SessionSecretStatus.ACTIVE and record.expires_at <= self.clock():
            expired = replace(
                record,
                status=SessionSecretStatus.EXPIRED,
                secret_ciphertext=None,
            )
            return self.repository.save(expired)
        return record


def encryption_context(owner, provider):
    return {
        "tenantId": owner["tenant_id"],
        "userId": owner["user_id"],
        "provider": provider,
        "purpose": SESSION_SECRET_PURPOSE,
    }


def metadata(record, now):
    return {
        "tenantId": record.tenant_id,
        "userId": record.user_id,
        "provider": record.provider,
        "secretId": record.secret_id,
        "fingerprint": record.fingerprint,
        "status": record.status,
        "validationStatus": record.validation_status,
        "createdAt": _to_iso(record.created_at),
        "lastValidatedAt": _to_iso(record.last_validated_at),
        "expiresAt": _to_iso(record.expires_at),
        "isExpired": record.expires_at <= now,
    }


def _require_identity(identity):
    if not isinstance(identity, dict):
        raise forbidden()
    tenant_id = identity.get("tenantId", identity.get("tenant_id"))
    user_id = identity.get("userId", identity.get("user_id"))
    if not tenant_id or not user_id:
        raise forbidden()
    return {
        "tenant_id": _require_non_empty_string(tenant_id, "identity.tenantId"),
        "user_id": _require_non_empty_string(user_id, "identity.userId"),
    }


def _require_provider(provider):
    normalized = _require_non_empty_string(provider, "provider").strip().lower()
    if normalized not in SUPPORTED_PROVIDER_VALUES:
        raise validation_failed("provider", "provider must be one of: openai, anthropic.")
    return normalized


def _require_secret_value(secret_value):
    if not isinstance(secret_value, str) or len(secret_value.strip()) == 0:
        raise validation_failed("secret_value", "Provider secret value is required.")
    return secret_value


def _validate_ttl_ms(ttl_ms):
    if not isinstance(ttl_ms, int) or ttl_ms <= 0 or ttl_ms > MAX_SESSION_SECRET_TTL_MS:
        raise validation_failed(
            "ttl_ms",
            f"Session secret TTL must be an integer between 1 and {MAX_SESSION_SECRET_TTL_MS}.",
        )
    return ttl_ms


def _require_validation_status(validation_status):
    if validation_status not in VALIDATION_STATUS_VALUES:
        raise validation_failed(
            "validation_status",
            "validation_status must be not_validated, valid, or invalid.",
        )
    return validation_status


def _assert_owner(record, owner, provider):
    if (
        record.tenant_id != owner["tenant_id"]
        or record.user_id != owner["user_id"]
        or record.provider != provider
    ):
        raise forbidden()


def _not_found():
    return SecretError(
        code=SecretErrorCodes.PROVIDER_SECRET_NOT_FOUND,
        message="Session secret is not available.",
        status=403,
    )


def _expired(record):
    return SecretError(
        code=SecretErrorCodes.PROVIDER_SECRET_EXPIRED,
        message="Session secret has expired.",
        status=403,
        details={"secretId": record.secret_id, "provider": record.provider},
    )


def _require_non_empty_string(value, field):
    if not isinstance(value, str) or len(value.strip()) == 0:
        raise validation_failed(field, f"{field} must be a non-empty string.")
    return value


def _to_iso(value):
    if value is None:
        return None
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _utc_now():
    return datetime.now(timezone.utc)
