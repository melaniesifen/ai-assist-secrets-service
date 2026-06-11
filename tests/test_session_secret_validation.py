import unittest

from ai_assist_secrets_service import (
    DEFAULT_SESSION_SECRET_TTL_MS,
    SecretErrorCodes,
    SessionSecretValidationStatus,
    SessionSecretsService,
    create_hmac_fingerprint_hasher,
)
from tests.common import (
    IDENTITY,
    assert_authz_denied,
    assert_secret_error,
    create_fixture,
)


class SessionSecretValidationTest(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
