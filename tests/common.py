from datetime import datetime, timezone

from ai_assist_secrets_service import (
    InMemorySessionSecretRepository,
    SecretError,
    SecretErrorCodes,
    SessionSecretsService,
    create_hmac_fingerprint_hasher,
)


BASE_TIME = datetime(2026, 5, 29, 12, 0, 0, tzinfo=timezone.utc)
VALIDATED_AT = datetime(2026, 5, 29, 11, 59, 0, tzinfo=timezone.utc)
IDENTITY = {"tenantId": "tenant-1", "userId": "user-1"}


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
        ciphertext = (
            f"ciphertext:{context['provider']}:{len(plaintext)}:"
            f"{len(self._plaintext_by_ciphertext) + 1}"
        )
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
