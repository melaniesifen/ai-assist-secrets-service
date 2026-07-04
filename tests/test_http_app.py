import json
import unittest

from ai_assist_secrets_service import (
    PLATFORM_CREDENTIAL_SOURCE,
    PlatformProviderAccessService,
    PlatformProviderConfig,
)
from ai_assist_secrets_service.http_app import SecretsHttpApplication, handle_http_request


AUTH_HEADERS = {"Authorization": "Bearer test-session"}
SECRET_VALUE = "provider-credential-fixture"
SECRET_REF = "OPENAI_PLATFORM_SECRET"


def response_json(response):
    return json.loads(response["body"].decode("utf-8"))


class SecretsHttpAppTests(unittest.TestCase):
    def test_provider_status_returns_platform_access_metadata_without_secret_value(self):
        service = PlatformProviderAccessService(
            config=PlatformProviderConfig(default_provider="openai", secret_refs={"openai": SECRET_REF}),
            secret_store=FakeSecretStore({SECRET_REF: SECRET_VALUE}),
        )
        app = SecretsHttpApplication(platform_access=service)

        response = app.handle(
            method="GET",
            path="/provider-secrets/session/openai/status",
            headers=AUTH_HEADERS,
            query={},
            body=None,
        )
        payload = response_json(response)

        self.assertEqual(response["status"], 200)
        self.assertEqual(response["headers"]["Cache-Control"], "no-store")
        self.assertEqual(payload["providerAccess"]["credentialSource"], PLATFORM_CREDENTIAL_SOURCE)
        self.assertTrue(payload["providerAccess"]["available"])
        self.assertNotIn("secretValue", json.dumps(payload))
        self.assertNotIn(SECRET_VALUE, json.dumps(payload))

    def test_missing_auth_returns_401(self):
        response = handle_http_request(
            method="GET",
            path="/provider-secrets/session/openai/status",
            headers={},
        )

        self.assertEqual(response["status"], 401)
        self.assertEqual(response_json(response)["error"]["category"], "AUTHENTICATION")

    def test_create_rejects_malformed_body_with_400(self):
        response = handle_http_request(
            method="POST",
            path="/provider-secrets/session",
            headers=AUTH_HEADERS,
            body=b"[]",
        )

        self.assertEqual(response["status"], 400)
        self.assertEqual(response_json(response)["error"]["code"], "VALIDATION_FAILED")

    def test_create_fails_closed_without_encrypted_storage(self):
        response = handle_http_request(
            method="POST",
            path="/provider-secrets/session",
            headers=AUTH_HEADERS,
            body=json.dumps({"provider": "openai", "secretValue": SECRET_VALUE}).encode("utf-8"),
        )
        payload = response_json(response)

        self.assertEqual(response["status"], 503)
        self.assertEqual(payload["error"]["code"], "SESSION_SECRET_STORAGE_UNAVAILABLE")
        self.assertNotIn(SECRET_VALUE, json.dumps(payload))

    def test_status_unconfigured_returns_safe_503(self):
        response = handle_http_request(
            method="GET",
            path="/provider-secrets/session/openai/status",
            headers=AUTH_HEADERS,
        )
        payload = response_json(response)

        self.assertEqual(response["status"], 503)
        self.assertEqual(payload["error"]["category"], "DEPENDENCY")

    def test_unknown_route_returns_404(self):
        response = handle_http_request(method="GET", path="/unknown", headers=AUTH_HEADERS)

        self.assertEqual(response["status"], 404)
        self.assertEqual(response_json(response)["error"]["code"], "ROUTE_NOT_FOUND")


class FakeSecretStore:
    def __init__(self, values):
        self.values = values

    def get_secret_value(self, secret_ref):
        return self.values[secret_ref]


if __name__ == "__main__":
    unittest.main()
