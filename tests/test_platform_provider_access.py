import json
import os
import unittest
from unittest.mock import patch

from ai_assist_secrets_service import (
    PLATFORM_CREDENTIAL_SOURCE,
    SecretErrorCodes,
    SecretStoreAccessDenied,
    PlatformProviderAccessService,
    PlatformProviderConfig,
    PlatformProviderStatus,
    platform_provider_config_from_env,
)
from ai_assist_secrets_service.errors import SecretError
from tests.common import assert_secret_error


PLATFORM_OPENAI_SECRET_REF = "arn:aws:secretsmanager:us-west-2:123456789012:secret:openai"
PLATFORM_ANTHROPIC_SECRET_REF = "arn:aws:secretsmanager:us-west-2:123456789012:secret:anthropic"
PLATFORM_OPENAI_SECRET_VALUE = "platform-provider-credential-fixture"


class PlatformProviderAccessTest(unittest.TestCase):
    def test_loads_platform_provider_credential_by_default_with_metadata_only_contract(self):
        service, store, validator = create_platform_fixture(require_metering=True)

        status = service.get_provider_access_status(identity=identity(), request=request())
        access = service.resolve_provider_access(identity=identity(), request=request())
        decrypted = service.decrypt_for_provider_call(
            provider="openai",
            secret_ref=access["secretRef"],
        )

        self.assertEqual(status["provider"], "openai")
        self.assertEqual(status["credentialSource"], PLATFORM_CREDENTIAL_SOURCE)
        self.assertEqual(status["status"], PlatformProviderStatus.AVAILABLE)
        self.assertTrue(status["available"])
        self.assertEqual(status["quotaDecision"], {"decision": "allow", "status": "ready"})
        self.assertEqual(status["auditDecision"], {"decision": "recorded", "status": "ready"})
        self.assertEqual(access["quotaDecision"], {"decision": "allow", "status": "ready"})
        self.assertEqual(access["auditDecision"], {"decision": "recorded", "status": "ready"})
        self.assertEqual(access["secretRef"], PLATFORM_OPENAI_SECRET_REF)
        self.assertNotIn("secretValue", access)
        self.assertNotIn(PLATFORM_OPENAI_SECRET_VALUE, json.dumps(status))
        self.assertNotIn(PLATFORM_OPENAI_SECRET_VALUE, json.dumps(access))
        self.assertEqual(decrypted["secretValue"], PLATFORM_OPENAI_SECRET_VALUE)
        self.assertEqual(store.requests, [PLATFORM_OPENAI_SECRET_REF] * 3)
        self.assertEqual(
            validator.requests,
            [{"provider": "openai", "secret_value": PLATFORM_OPENAI_SECRET_VALUE}] * 3,
        )

    def test_required_metering_fails_closed_without_quota_or_audit_checker(self):
        service, _, _ = create_platform_fixture(require_metering=True, metering_checker=None)

        status = service.get_provider_access_status(identity=identity(), request=request())

        self.assertFalse(status["available"])
        self.assertEqual(status["status"], PlatformProviderStatus.QUOTA_NOT_CONFIGURED)
        self.assertEqual(
            status["error"]["code"],
            SecretErrorCodes.PLATFORM_PROVIDER_QUOTA_NOT_CONFIGURED,
        )
        assert_secret_error(
            self,
            lambda: service.resolve_provider_access(identity=identity(), request=request()),
            SecretErrorCodes.PLATFORM_PROVIDER_QUOTA_NOT_CONFIGURED,
            503,
        )

    def test_quota_denial_blocks_platform_provider_access_without_secret_leakage(self):
        metering = FakeMeteringChecker(quota={"decision": "deny", "status": "limit_exceeded", "reasonCode": "USER_QUOTA_EXCEEDED"})
        service, _, _ = create_platform_fixture(require_metering=True, metering_checker=metering)

        status = service.get_provider_access_status(identity=identity(), request=request())

        serialized = json.dumps(status)
        self.assertFalse(status["available"])
        self.assertEqual(status["status"], PlatformProviderStatus.QUOTA_DENIED)
        self.assertEqual(status["quotaDecision"]["reasonCode"], "USER_QUOTA_EXCEEDED")
        self.assertEqual(
            status["error"]["code"],
            SecretErrorCodes.PLATFORM_PROVIDER_QUOTA_DENIED,
        )
        self.assertNotIn(PLATFORM_OPENAI_SECRET_REF, serialized)
        self.assertNotIn(PLATFORM_OPENAI_SECRET_VALUE, serialized)
        assert_secret_error(
            self,
            lambda: service.resolve_provider_access(identity=identity(), request=request()),
            SecretErrorCodes.PLATFORM_PROVIDER_QUOTA_DENIED,
            429,
        )
        self.assertEqual(
            metering.requests,
            [{"identity": identity(), "provider": "openai", "request": request()}] * 2,
        )

    def test_audit_not_recorded_blocks_platform_provider_access(self):
        service, _, _ = create_platform_fixture(
            require_metering=True,
            metering_checker=FakeMeteringChecker(audit={"decision": "not_configured", "status": "audit_not_ready"}),
        )

        status = service.get_provider_access_status(identity=identity(), request=request())

        self.assertFalse(status["available"])
        self.assertEqual(status["status"], PlatformProviderStatus.AUDIT_NOT_CONFIGURED)
        self.assertEqual(
            status["error"]["code"],
            SecretErrorCodes.PLATFORM_PROVIDER_AUDIT_NOT_CONFIGURED,
        )

    def test_fails_closed_when_default_provider_secret_reference_is_missing(self):
        assert_secret_error(
            self,
            lambda: PlatformProviderAccessService(
                config=PlatformProviderConfig(
                    default_provider="openai",
                    secret_refs={"anthropic": PLATFORM_ANTHROPIC_SECRET_REF},
                ),
                secret_store=FakeSecretStore({}),
            ),
            SecretErrorCodes.PLATFORM_PROVIDER_SECRET_NOT_CONFIGURED,
            503,
        )

    def test_reports_unconfigured_non_default_provider_without_requiring_byo_key(self):
        service, _, _ = create_platform_fixture()

        status = service.get_provider_access_status(provider="anthropic")

        self.assertFalse(status["available"])
        self.assertEqual(status["status"], PlatformProviderStatus.NOT_CONFIGURED)
        self.assertEqual(
            status["error"]["code"],
            SecretErrorCodes.PLATFORM_PROVIDER_SECRET_NOT_CONFIGURED,
        )
        self.assertNotIn("secretValue", status)

    def test_fails_closed_when_secret_store_access_is_denied(self):
        service, store, _ = create_platform_fixture()
        store.denied_refs.add(PLATFORM_OPENAI_SECRET_REF)

        with self.assertRaises(SecretError) as caught:
            service.resolve_provider_access(provider="openai")
        self.assertEqual(
            caught.exception.code,
            SecretErrorCodes.PLATFORM_PROVIDER_SECRET_ACCESS_DENIED,
        )
        self.assertEqual(caught.exception.status, 503)
        serialized_error = json.dumps(caught.exception.to_response())
        self.assertNotIn(PLATFORM_OPENAI_SECRET_REF, serialized_error)
        self.assertNotIn(PLATFORM_OPENAI_SECRET_VALUE, serialized_error)
        assert_secret_error(
            self,
            lambda: service.decrypt_for_provider_call(provider="openai"),
            SecretErrorCodes.PLATFORM_PROVIDER_SECRET_ACCESS_DENIED,
            503,
        )

    def test_invalid_platform_credential_status_blocks_provider_call_without_secret_leakage(self):
        service, _, validator = create_platform_fixture()
        validator.valid = False

        status = service.get_provider_access_status(provider="openai")

        self.assertFalse(status["available"])
        self.assertEqual(status["status"], PlatformProviderStatus.INVALID)
        self.assertEqual(
            status["error"]["code"],
            SecretErrorCodes.PLATFORM_PROVIDER_SECRET_INVALID,
        )
        self.assertNotIn(PLATFORM_OPENAI_SECRET_VALUE, json.dumps(status))
        assert_secret_error(
            self,
            lambda: service.decrypt_for_provider_call(provider="openai"),
            SecretErrorCodes.PLATFORM_PROVIDER_SECRET_INVALID,
            503,
        )

    def test_validation_failure_is_retryable_and_metadata_only(self):
        service, _, validator = create_platform_fixture()
        validator.raise_error = True

        status = service.get_provider_access_status(provider="openai")

        self.assertEqual(status["status"], PlatformProviderStatus.VALIDATION_FAILED)
        self.assertEqual(
            status["error"]["code"],
            SecretErrorCodes.PLATFORM_PROVIDER_SECRET_VALIDATION_FAILED,
        )
        self.assertTrue(status["error"]["retryable"])
        self.assertNotIn(PLATFORM_OPENAI_SECRET_VALUE, json.dumps(status))

    def test_env_config_uses_generic_deployed_secret_reference_names(self):
        with patch.dict(
            os.environ,
            {
                "PLATFORM_PROVIDER_DEFAULT": " openai ",
                "PLATFORM_PROVIDER_SECRET_REF_OPENAI": f" {PLATFORM_OPENAI_SECRET_REF} ",
            },
        ):
            config = platform_provider_config_from_env(os.environ)

        self.assertEqual(config.default_provider, "openai")
        self.assertEqual(config.secret_refs["openai"], PLATFORM_OPENAI_SECRET_REF)


def create_platform_fixture(*, require_metering=False, metering_checker="default"):
    store = FakeSecretStore({PLATFORM_OPENAI_SECRET_REF: PLATFORM_OPENAI_SECRET_VALUE})
    validator = FakeCredentialValidator()
    if metering_checker == "default":
        metering_checker = FakeMeteringChecker()
    service = PlatformProviderAccessService(
        config=PlatformProviderConfig(
            default_provider="openai",
            secret_refs={"openai": PLATFORM_OPENAI_SECRET_REF},
        ),
        secret_store=store,
        credential_validator=validator,
        metering_checker=metering_checker,
        require_metering=require_metering,
    )
    return service, store, validator


def identity():
    return {"tenantId": "tenant_001", "userId": "user_001"}


def request():
    return {"sessionId": "session_001", "requestId": "req_001", "correlationId": "corr_001"}


class FakeSecretStore:
    def __init__(self, values):
        self.values = values
        self.denied_refs = set()
        self.requests = []

    def get_secret_value(self, secret_ref):
        self.requests.append(secret_ref)
        if secret_ref in self.denied_refs:
            raise SecretStoreAccessDenied("access denied")
        return self.values[secret_ref]


class FakeCredentialValidator:
    def __init__(self):
        self.valid = True
        self.raise_error = False
        self.requests = []

    def validate(self, *, provider, secret_value):
        self.requests.append({"provider": provider, "secret_value": secret_value})
        if self.raise_error:
            raise RuntimeError("validation unavailable")
        return {"valid": self.valid}


class FakeMeteringChecker:
    def __init__(self, *, quota=None, audit=None):
        self.quota = quota or {"decision": "allow", "status": "ready"}
        self.audit = audit or {"decision": "recorded", "status": "ready"}
        self.requests = []

    def check_provider_access(self, *, identity, provider, request):
        self.requests.append({"identity": identity, "provider": provider, "request": request})
        return {
            "quotaDecision": self.quota,
            "auditDecision": self.audit,
            "secretRef": "must-not-leak",
            "secretValue": "must-not-leak",
        }


if __name__ == "__main__":
    unittest.main()
