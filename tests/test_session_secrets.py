import json
import re
import unittest
from datetime import datetime, timedelta, timezone

from ai_assist_secrets_service import (
    DEFAULT_SESSION_SECRET_TTL_MS,
    InMemorySessionSecretRepository,
    ProviderSecretReadinessStatus,
    SecretError,
    SecretErrorCodes,
    SessionSecretStatus,
    SessionSecretValidationStatus,
    SessionSecretsService,
    create_hmac_fingerprint_hasher,
)


BASE_TIME = datetime(2026, 5, 29, 12, 0, 0, tzinfo=timezone.utc)
VALIDATED_AT = datetime(2026, 5, 29, 11, 59, 0, tzinfo=timezone.utc)
IDENTITY = {"tenantId": "tenant-1", "userId": "user-1"}


class SessionSecretsServiceTest(unittest.TestCase):
    def test_creates_encrypted_metadata_only_session_secrets_with_default_ttl(self):
        service, _, encryptor = create_fixture()

        created = service.create_session_secret(
            identity=IDENTITY,
            provider=" OpenAI ",
            secret_value="sk-test-provider-key",
            validation_status=SessionSecretValidationStatus.VALID,
            last_validated_at=VALIDATED_AT,
        )

        self.assertEqual(created["provider"], "openai")
        self.assertEqual(created["status"], SessionSecretStatus.ACTIVE)
        self.assertEqual(created["validationStatus"], SessionSecretValidationStatus.VALID)
        self.assertEqual(
            created["expiresAt"],
            (BASE_TIME + timedelta(milliseconds=DEFAULT_SESSION_SECRET_TTL_MS))
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z"),
        )
        self.assertRegex(created["fingerprint"], re.compile(r"^hmac-sha256:[a-f0-9]{16}$"))
        self.assertNotIn("secretValue", created)
        self.assertNotIn("secretCiphertext", created)
        self.assertNotIn("provider-key", json.dumps(created))
        self.assertEqual(
            encryptor.encrypt_calls[0]["context"],
            {
                "tenantId": "tenant-1",
                "userId": "user-1",
                "provider": "openai",
                "purpose": "session-secret",
            },
        )

    def test_decrypts_only_through_internal_provider_call_path(self):
        service, _, _ = create_fixture()
        created = service.create_session_secret(
            identity=IDENTITY,
            provider="anthropic",
            secret_value="anthropic-key",
            validation_status=SessionSecretValidationStatus.VALID,
        )

        resolved = service.resolve_session_secret(identity=IDENTITY, provider="anthropic")
        decrypted = service.decrypt_for_provider_call(
            identity=IDENTITY,
            secret_id=created["secretId"],
            provider="anthropic",
        )

        self.assertEqual(resolved["secretId"], created["secretId"])
        self.assertNotIn("secretValue", resolved)
        self.assertEqual(decrypted["secretValue"], "anthropic-key")
        assert_authz_denied(
            self,
            lambda: service.decrypt_for_provider_call(
                identity={"tenantId": "tenant-2", "userId": "user-1"},
                secret_id=created["secretId"],
                provider="anthropic",
            ),
        )

    def test_rejects_expired_secrets_at_read_time_and_clears_ciphertext(self):
        mutable_now = {"value": BASE_TIME}
        service, repository, _ = create_fixture(clock=lambda: mutable_now["value"])
        created = service.create_session_secret(
            identity=IDENTITY,
            provider="openai",
            secret_value="sk-test-provider-key",
            ttl_ms=1,
        )
        mutable_now["value"] = BASE_TIME + timedelta(milliseconds=1)

        assert_secret_error(
            self,
            lambda: service.resolve_session_secret(identity=IDENTITY, provider="openai"),
            SecretErrorCodes.PROVIDER_SECRET_EXPIRED,
            403,
        )
        stored = repository.get_by_id(created["secretId"])
        self.assertEqual(stored.status, SessionSecretStatus.EXPIRED)
        self.assertIsNone(stored.secret_ciphertext)

    def test_delete_and_explicit_expire_return_safe_metadata_and_reject_later_use(self):
        service, repository, _ = create_fixture()
        created = service.create_session_secret(
            identity=IDENTITY,
            provider="openai",
            secret_value="sk-test-provider-key",
            validation_status=SessionSecretValidationStatus.VALID,
        )

        deleted = service.delete_session_secret(
            identity=IDENTITY,
            provider="openai",
            secret_id=created["secretId"],
        )

        self.assertEqual(deleted["status"], SessionSecretStatus.DELETED)
        self.assertIsNone(repository.get_by_id(created["secretId"]).secret_ciphertext)
        assert_secret_error(
            self,
            lambda: service.decrypt_for_provider_call(
                identity=IDENTITY,
                provider="openai",
                secret_id=created["secretId"],
            ),
            SecretErrorCodes.PROVIDER_SECRET_DELETED,
            403,
        )

        second = service.create_session_secret(
            identity=IDENTITY,
            provider="openai",
            secret_value="sk-second-provider-key",
        )
        expired = service.expire_session_secret(
            identity=IDENTITY,
            provider="openai",
            secret_id=second["secretId"],
        )
        self.assertEqual(expired["status"], SessionSecretStatus.EXPIRED)
        assert_secret_error(
            self,
            lambda: service.resolve_session_secret(identity=IDENTITY, provider="openai"),
            SecretErrorCodes.PROVIDER_SECRET_EXPIRED,
            403,
        )

    def test_validates_ttl_and_secret_value_on_create(self):
        service, _, _ = create_fixture()

        assert_secret_error(
            self,
            lambda: service.create_session_secret(
                identity=IDENTITY,
                provider="openai",
                secret_value="   ",
            ),
            SecretErrorCodes.VALIDATION_FAILED,
            400,
        )
        assert_secret_error(
            self,
            lambda: service.create_session_secret(
                identity=IDENTITY,
                provider="openai",
                secret_value="sk-test-provider-key",
                ttl_ms=DEFAULT_SESSION_SECRET_TTL_MS + 1,
            ),
            SecretErrorCodes.VALIDATION_FAILED,
            400,
        )
        assert_secret_error(
            self,
            lambda: service.create_session_secret(
                identity=IDENTITY,
                provider="bedrock",
                secret_value="sk-test-provider-key",
            ),
            SecretErrorCodes.VALIDATION_FAILED,
            400,
        )
        assert_secret_error(
            self,
            lambda: service.create_session_secret(
                identity=IDENTITY,
                provider="openai",
                secret_value="sk-test-provider-key",
                validation_status="maybe_valid",
            ),
            SecretErrorCodes.VALIDATION_FAILED,
            400,
        )

    def test_preserves_validation_status_through_status_and_resolve_metadata(self):
        service, _, _ = create_fixture()
        created = service.create_session_secret(
            identity=IDENTITY,
            provider="anthropic",
            secret_value="anthropic-key",
            validation_status=SessionSecretValidationStatus.VALID,
        )

        status = service.get_session_secret_status(identity=IDENTITY, provider="anthropic")
        resolved = service.resolve_session_secret(identity=IDENTITY, provider="anthropic")

        self.assertEqual(created["validationStatus"], SessionSecretValidationStatus.VALID)
        self.assertEqual(created["lastValidatedAt"], "2026-05-29T12:00:00.000Z")
        self.assertEqual(status["validationStatus"], SessionSecretValidationStatus.VALID)
        self.assertEqual(resolved["validationStatus"], SessionSecretValidationStatus.VALID)
        self.assertNotIn("anthropic-key", json.dumps(status))

    def test_reports_m3_provider_secret_readiness_states_as_metadata_only_refs(self):
        service, _, _ = create_fixture()

        missing = service.get_provider_secret_readiness(identity=IDENTITY, provider="openai")
        pending = service.create_session_secret(
            identity=IDENTITY,
            provider="openai",
            secret_value="sk-pending-provider-key",
        )
        pending_status = service.get_provider_secret_readiness(identity=IDENTITY, provider="openai")
        valid = service.create_session_secret(
            identity=IDENTITY,
            provider="anthropic",
            secret_value="anthropic-valid-key",
            validation_status=SessionSecretValidationStatus.VALID,
        )
        valid_status = service.get_provider_secret_readiness(identity=IDENTITY, provider="anthropic")

        self.assertEqual(missing["status"], ProviderSecretReadinessStatus.MISSING)
        self.assertEqual(missing["error"]["code"], SecretErrorCodes.PROVIDER_SECRET_NOT_FOUND)
        self.assertEqual(pending_status["status"], ProviderSecretReadinessStatus.PENDING_VALIDATION)
        self.assertEqual(pending_status["secretId"], pending["secretId"])
        self.assertEqual(valid_status["status"], ProviderSecretReadinessStatus.VALID)
        self.assertEqual(valid_status["secretId"], valid["secretId"])
        self.assertIn("fingerprint", valid_status)
        self.assertNotIn("secretValue", valid_status)
        self.assertNotIn("secretCiphertext", valid_status)
        self.assertNotIn("anthropic-valid-key", json.dumps(valid_status))

    def test_reports_invalid_and_validation_failed_readiness_without_stored_ciphertext(self):
        service, repository, encryptor = create_fixture()
        invalid = service.create_session_secret(
            identity=IDENTITY,
            provider="openai",
            secret_value="sk-invalid-provider-key",
            validation_status=SessionSecretValidationStatus.INVALID,
        )
        failed = service.create_session_secret(
            identity=IDENTITY,
            provider="anthropic",
            secret_value="anthropic-validation-unavailable",
            validation_status=SessionSecretValidationStatus.VALIDATION_FAILED,
        )

        invalid_status = service.get_provider_secret_readiness(identity=IDENTITY, provider="openai")
        failed_status = service.get_provider_secret_readiness(identity=IDENTITY, provider="anthropic")

        self.assertEqual(invalid_status["status"], ProviderSecretReadinessStatus.INVALID)
        self.assertEqual(invalid_status["error"]["code"], SecretErrorCodes.PROVIDER_SECRET_INVALID)
        self.assertEqual(failed_status["status"], ProviderSecretReadinessStatus.VALIDATION_FAILED)
        self.assertEqual(
            failed_status["error"]["code"],
            SecretErrorCodes.PROVIDER_SECRET_VALIDATION_FAILED,
        )
        self.assertEqual(failed_status["error"]["category"], "DEPENDENCY")
        self.assertIsNone(repository.get_by_id(invalid["secretId"]).secret_ciphertext)
        self.assertIsNone(repository.get_by_id(failed["secretId"]).secret_ciphertext)
        self.assertEqual(encryptor.encrypt_calls, [])
        self.assertNotIn("sk-invalid-provider-key", json.dumps(invalid_status))
        self.assertNotIn("anthropic-validation-unavailable", json.dumps(failed_status))

    def test_reports_expired_readiness_at_read_time_with_no_raw_secret(self):
        mutable_now = {"value": BASE_TIME}
        service, repository, _ = create_fixture(clock=lambda: mutable_now["value"])
        created = service.create_session_secret(
            identity=IDENTITY,
            provider="openai",
            secret_value="sk-expiring-provider-key",
            validation_status=SessionSecretValidationStatus.VALID,
            ttl_ms=1,
        )
        mutable_now["value"] = BASE_TIME + timedelta(milliseconds=1)

        readiness = service.get_provider_secret_readiness(identity=IDENTITY, provider="openai")

        self.assertEqual(readiness["status"], ProviderSecretReadinessStatus.EXPIRED)
        self.assertEqual(readiness["error"]["code"], SecretErrorCodes.PROVIDER_SECRET_EXPIRED)
        self.assertEqual(readiness["error"]["httpStatus"], 401)
        self.assertIsNone(repository.get_by_id(created["secretId"]).secret_ciphertext)
        self.assertNotIn("sk-expiring-provider-key", json.dumps(readiness))

    def test_provider_call_path_requires_valid_secret_status(self):
        service, _, _ = create_fixture()
        pending = service.create_session_secret(
            identity=IDENTITY,
            provider="openai",
            secret_value="sk-pending-provider-key",
        )
        invalid = service.create_session_secret(
            identity=IDENTITY,
            provider="anthropic",
            secret_value="anthropic-invalid-key",
            validation_status=SessionSecretValidationStatus.INVALID,
        )

        assert_secret_error(
            self,
            lambda: service.decrypt_for_provider_call(
                identity=IDENTITY,
                provider="openai",
                secret_id=pending["secretId"],
            ),
            SecretErrorCodes.PROVIDER_SECRET_PENDING_VALIDATION,
            403,
        )
        assert_secret_error(
            self,
            lambda: service.decrypt_for_provider_call(
                identity=IDENTITY,
                provider="anthropic",
                secret_id=invalid["secretId"],
            ),
            SecretErrorCodes.PROVIDER_SECRET_INVALID,
            403,
        )

    def test_reports_missing_status_without_leaking_other_tenant_existence(self):
        service, _, _ = create_fixture()
        service.create_session_secret(
            identity=IDENTITY,
            provider="openai",
            secret_value="sk-test-provider-key",
        )

        status = service.get_session_secret_status(
            identity={"tenantId": "tenant-2", "userId": "user-1"},
            provider="openai",
        )

        self.assertFalse(status["available"])
        self.assertEqual(status["status"], "missing")
        self.assertNotIn("secretId", status)
        self.assertEqual(status["tenantId"], "tenant-2")
        self.assertEqual(status["userId"], "user-1")

    def test_wraps_decrypt_failures_as_typed_fail_closed_errors(self):
        service, _, encryptor = create_fixture()
        created = service.create_session_secret(
            identity=IDENTITY,
            provider="openai",
            secret_value="sk-test-provider-key",
            validation_status=SessionSecretValidationStatus.VALID,
        )
        encryptor.fail_decrypt = True

        assert_secret_error(
            self,
            lambda: service.decrypt_for_provider_call(
                identity=IDENTITY,
                provider="openai",
                secret_id=created["secretId"],
            ),
            SecretErrorCodes.SECRET_DECRYPT_FAILED,
            500,
        )

    def test_returns_newest_matching_secret_when_multiple_active_records_exist(self):
        mutable_now = {"value": BASE_TIME}
        service, _, _ = create_fixture(clock=lambda: mutable_now["value"])
        service.create_session_secret(
            identity=IDENTITY,
            provider="openai",
            secret_value="sk-first-provider-key",
        )
        mutable_now["value"] = BASE_TIME + timedelta(seconds=1)
        latest = service.create_session_secret(
            identity=IDENTITY,
            provider="openai",
            secret_value="sk-second-provider-key",
        )

        status = service.get_session_secret_status(identity=IDENTITY, provider="openai")

        self.assertEqual(status["secretId"], latest["secretId"])

    def test_rejects_missing_references_without_exposing_cross_tenant_existence(self):
        service, _, _ = create_fixture()

        assert_secret_error(
            self,
            lambda: service.resolve_session_secret(identity=IDENTITY, provider="openai"),
            SecretErrorCodes.PROVIDER_SECRET_NOT_FOUND,
            403,
        )
        assert_secret_error(
            self,
            lambda: service.expire_session_secret(
                identity=IDENTITY,
                provider="openai",
                secret_id="missing-secret",
            ),
            SecretErrorCodes.PROVIDER_SECRET_NOT_FOUND,
            403,
        )
        assert_secret_error(
            self,
            lambda: service.delete_session_secret(
                identity=IDENTITY,
                provider="openai",
                secret_id="missing-secret",
            ),
            SecretErrorCodes.PROVIDER_SECRET_NOT_FOUND,
            403,
        )

    def test_validates_identity_and_secret_reference_inputs_before_lookup(self):
        service, _, _ = create_fixture()
        created = service.create_session_secret(
            identity=IDENTITY,
            provider="openai",
            secret_value="sk-test-provider-key",
        )

        assert_authz_denied(
            self,
            lambda: service.get_session_secret_status(identity=None, provider="openai"),
        )
        assert_secret_error(
            self,
            lambda: service.decrypt_for_provider_call(
                identity=IDENTITY,
                provider="openai",
                secret_id=" ",
            ),
            SecretErrorCodes.VALIDATION_FAILED,
            400,
        )
        assert_authz_denied(
            self,
            lambda: service.expire_session_secret(
                identity={"tenantId": "tenant-1", "userId": "user-2"},
                provider="openai",
                secret_id=created["secretId"],
            ),
        )

    def test_validates_constructor_dependencies_and_fingerprint_key_material(self):
        _, repository, encryptor = create_fixture()
        fingerprint_hasher = create_hmac_fingerprint_hasher(
            key="test-fingerprint-key-material"
        )

        with self.assertRaisesRegex(TypeError, "repository is required"):
            SessionSecretsService(
                repository=None,
                encryptor=encryptor,
                fingerprint_hasher=fingerprint_hasher,
                id_generator=lambda: "secret-1",
            )
        with self.assertRaisesRegex(TypeError, "encryptor with encrypt and decrypt methods is required"):
            SessionSecretsService(
                repository=repository,
                encryptor=object(),
                fingerprint_hasher=fingerprint_hasher,
                id_generator=lambda: "secret-1",
            )
        with self.assertRaisesRegex(TypeError, "fingerprint_hasher\\.fingerprint is required"):
            SessionSecretsService(
                repository=repository,
                encryptor=encryptor,
                fingerprint_hasher=object(),
                id_generator=lambda: "secret-1",
            )
        with self.assertRaisesRegex(TypeError, "id_generator is required"):
            SessionSecretsService(
                repository=repository,
                encryptor=encryptor,
                fingerprint_hasher=fingerprint_hasher,
            )
        with self.assertRaisesRegex(TypeError, "fingerprint key must be at least 16 characters"):
            create_hmac_fingerprint_hasher(key="short")

    def test_formats_typed_errors_as_stable_response_envelopes(self):
        error = SecretError(
            code=SecretErrorCodes.VALIDATION_FAILED,
            message="Bad request.",
            status=400,
            details={"field": "provider"},
        )

        self.assertEqual(
            error.to_response(),
            {
                "error": {
                    "code": SecretErrorCodes.VALIDATION_FAILED,
                    "message": "Bad request.",
                    "details": {"field": "provider"},
                },
                "status": 400,
            },
        )


def create_fixture(clock=lambda: BASE_TIME):
    repository = InMemorySessionSecretRepository()
    encryptor = FakeEncryptor()
    fingerprint_hasher = create_hmac_fingerprint_hasher(
        key="test-fingerprint-key-material"
    )
    id_counter = {"value": 0}

    def next_id():
        id_counter["value"] += 1
        return f"secret-{id_counter['value']}"

    service = SessionSecretsService(
        repository=repository,
        encryptor=encryptor,
        fingerprint_hasher=fingerprint_hasher,
        clock=clock,
        id_generator=next_id,
    )
    return service, repository, encryptor


class FakeEncryptor:
    def __init__(self):
        self._plaintext_by_ciphertext = {}
        self.encrypt_calls = []
        self.fail_decrypt = False

    def encrypt(self, plaintext, *, context):
        ciphertext = f"ciphertext:{context['provider']}:{len(plaintext)}:{len(self._plaintext_by_ciphertext) + 1}"
        self._plaintext_by_ciphertext[ciphertext] = plaintext
        self.encrypt_calls.append({"plaintext": plaintext, "context": context})
        return ciphertext

    def decrypt(self, ciphertext, *, context):
        if self.fail_decrypt:
            raise RuntimeError("decrypt failed")
        return self._plaintext_by_ciphertext[ciphertext]


def assert_secret_error(test_case, fn, code, status):
    with test_case.assertRaises(SecretError) as caught:
        fn()
    test_case.assertEqual(caught.exception.code, code)
    test_case.assertEqual(caught.exception.status, status)


def assert_authz_denied(test_case, fn):
    assert_secret_error(test_case, fn, SecretErrorCodes.TENANT_ACCESS_DENIED, 403)


if __name__ == "__main__":
    unittest.main()
