from __future__ import annotations

import json
import os
import re
from typing import Any
from urllib.parse import parse_qs, urlparse

from .errors import SecretError, SecretErrorCodes, validation_failed
from .platform_provider_access import (
    PlatformProviderAccessService,
    SecretStoreAccessDenied,
    platform_provider_config_from_env,
)


SERVICE_NAME = "ai-assist-secrets-service"
SESSION_SECRET_ROUTE = "/provider-secrets/session"
SESSION_SECRET_STATUS_RE = re.compile(r"^/provider-secrets/session/([^/]+)/status$")
SESSION_SECRET_DELETE_RE = re.compile(r"^/provider-secrets/session/([^/]+)$")
SECRET_VALUE_ENV_PREFIX = "PLATFORM_PROVIDER_SECRET_VALUE_"
_APP: SecretsHttpApplication | None = None


def handle_http_request(
    *,
    method: str,
    path: str,
    headers: dict[str, str] | None = None,
    query_string: str = "",
    body: bytes | None = None,
) -> dict[str, Any]:
    global _APP
    if _APP is None:
        _APP = create_app_from_env()
    parsed = urlparse(path)
    return _APP.handle(
        method=method.upper(),
        path=parsed.path,
        headers=headers or {},
        query=parse_qs(query_string or parsed.query),
        body=body,
    )


def create_app_from_env(env: dict[str, str] | None = None) -> "SecretsHttpApplication":
    env = env or dict(os.environ)
    platform_access = None
    try:
        platform_access = PlatformProviderAccessService(
            config=platform_provider_config_from_env(env),
            secret_store=_EnvSecretStore(env),
        )
    except SecretError:
        platform_access = None
    return SecretsHttpApplication(platform_access=platform_access)


class SecretsHttpApplication:
    def __init__(self, *, platform_access: Any | None = None) -> None:
        self.platform_access = platform_access

    def handle(
        self,
        *,
        method: str,
        path: str,
        headers: dict[str, str],
        query: dict[str, list[str]],
        body: bytes | None,
    ) -> dict[str, Any]:
        del query
        try:
            _require_bearer(headers)
            if method == "POST" and path == SESSION_SECRET_ROUTE:
                payload = _json_body(body)
                _require_string(payload.get("provider"), "provider")
                if "secretValue" not in payload:
                    raise validation_failed("secretValue", "secretValue is required.")
                return _error_response(
                    503,
                    "SESSION_SECRET_STORAGE_UNAVAILABLE",
                    "Session secret create requires deployed encrypted persistence and KMS dependencies.",
                    category="DEPENDENCY",
                    details={"dependency": "sessionSecretStore"},
                )

            status_match = SESSION_SECRET_STATUS_RE.match(path)
            if method == "GET" and status_match:
                provider = status_match.group(1)
                if self.platform_access is None:
                    return _error_response(
                        503,
                        SecretErrorCodes.PLATFORM_PROVIDER_SECRET_NOT_CONFIGURED,
                        "Platform provider access is not configured in this runtime.",
                        category="DEPENDENCY",
                        details={"provider": provider},
                    )
                status = self.platform_access.get_provider_access_status(provider=provider)
                if status.get("available"):
                    return _json_response(200, {"providerAccess": _public_provider_status(status)})
                error = status.get("error", {})
                return _error_response(
                    int(error.get("httpStatus", 503)),
                    error.get("code", SecretErrorCodes.PLATFORM_PROVIDER_SECRET_NOT_CONFIGURED),
                    error.get("message", "Platform provider credential is not available."),
                    category=error.get("category", "DEPENDENCY"),
                    retryable=bool(error.get("retryable", False)),
                    details={"provider": provider, "status": status.get("status")},
                )

            delete_match = SESSION_SECRET_DELETE_RE.match(path)
            if method == "DELETE" and delete_match:
                provider = delete_match.group(1)
                return _error_response(
                    503,
                    "SESSION_SECRET_STORAGE_UNAVAILABLE",
                    "Session secret delete requires deployed encrypted persistence and KMS dependencies.",
                    category="DEPENDENCY",
                    details={"provider": provider, "dependency": "sessionSecretStore"},
                )

            return _error_response(
                404,
                "ROUTE_NOT_FOUND",
                "Route is not implemented by the secrets service.",
                category="VALIDATION",
            )
        except SecretError as error:
            return _error_response(
                error.status,
                error.code,
                str(error),
                category=_category_for_status(error.status),
                details=dict(error.details),
            )
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            return _error_response(400, SecretErrorCodes.VALIDATION_FAILED, str(error), category="VALIDATION")


class _EnvSecretStore:
    def __init__(self, env: dict[str, str]) -> None:
        self.env = env

    def get_secret_value(self, secret_ref: str) -> str:
        for key in (_secret_ref_value_key(secret_ref), secret_ref):
            value = self.env.get(key)
            if isinstance(value, str) and value.strip():
                return value
        raise SecretStoreAccessDenied("configured secret reference is not resolvable")


def _public_provider_status(status: dict[str, Any]) -> dict[str, Any]:
    return {
        "provider": status["provider"],
        "credentialSource": status["credentialSource"],
        "available": bool(status["available"]),
        "status": status["status"],
        **({"secretRef": status["secretRef"]} if "secretRef" in status else {}),
    }


def _secret_ref_value_key(secret_ref: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9]+", "_", secret_ref).strip("_").upper()
    return f"{SECRET_VALUE_ENV_PREFIX}{normalized}"


def _require_bearer(headers: dict[str, str]) -> str:
    authorization = _header(headers, "authorization") or ""
    if not authorization.startswith("Bearer ") or not authorization[len("Bearer ") :].strip():
        raise SecretError(
            code="AUTHENTICATION_REQUIRED",
            message="Bearer product session token is required.",
            status=401,
        )
    return authorization[len("Bearer ") :].strip()


def _json_body(body: bytes | str | None) -> dict[str, Any]:
    if body in {None, b"", ""}:
        return {}
    raw = body.decode("utf-8") if isinstance(body, bytes) else body
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise validation_failed("body", "JSON request body must be an object.")
    return parsed


def _require_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise validation_failed(field, f"{field} must be a non-empty string.")
    return value.strip()


def _header(headers: dict[str, str], name: str) -> str | None:
    lowered = name.lower()
    for key, value in headers.items():
        if str(key).lower() == lowered:
            return value
    return None


def _json_response(status: int, payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": status,
        "headers": {"Content-Type": "application/json", "Cache-Control": "no-store"},
        "body": json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"),
    }


def _error_response(
    status: int,
    code: str,
    message: str,
    *,
    category: str,
    retryable: bool = False,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    error = {
        "code": code,
        "category": category,
        "message": message,
        "retryable": retryable,
    }
    if details:
        error["details"] = details
    return _json_response(status, {"error": error, "service": SERVICE_NAME})


def _category_for_status(status: int) -> str:
    if status == 401:
        return "AUTHENTICATION"
    if status == 403:
        return "AUTHORIZATION"
    if status >= 500:
        return "DEPENDENCY"
    return "VALIDATION"
