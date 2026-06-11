import json
import re
import unittest
from datetime import timedelta

from ai_assist_secrets_service import (
    DEFAULT_SESSION_SECRET_TTL_MS,
    SecretErrorCodes,
    SessionSecretStatus,
    SessionSecretValidationStatus,
)
from tests.common import (
    BASE_TIME,
    IDENTITY,
    VALIDATED_AT,
    assert_authz_denied,
    assert_secret_error,
    create_fixture,
)


class SessionSecretLifecycleTest(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
