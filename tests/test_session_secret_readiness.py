import json
import unittest
from datetime import timedelta

from ai_assist_secrets_service import (
    ProviderSecretReadinessStatus,
    SecretErrorCodes,
    SessionSecretValidationStatus,
)
from tests.common import BASE_TIME, IDENTITY, assert_secret_error, create_fixture


class SessionSecretReadinessTest(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
