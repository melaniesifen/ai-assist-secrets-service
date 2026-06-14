from collections.abc import Mapping
from dataclasses import dataclass

from .errors import SecretError, SecretErrorCodes, validation_failed
from .session_secrets import SUPPORTED_PROVIDER_VALUES, _require_provider


PLATFORM_PROVIDER_DEFAULT_KEY = "PLATFORM_PROVIDER_DEFAULT"
PLATFORM_PROVIDER_SECRET_REF_PREFIX = "PLATFORM_PROVIDER_SECRET_REF_"
PLATFORM_CREDENTIAL_SOURCE = "platform"


class PlatformProviderStatus:
    AVAILABLE = "available"
    NOT_CONFIGURED = "not_configured"
    ACCESS_DENIED = "access_denied"
    INVALID = "invalid"
    VALIDATION_FAILED = "validation_failed"


class SecretStoreAccessDenied(Exception):
    pass


@dataclass(frozen=True)
class PlatformProviderConfig:
    default_provider: str | None
    secret_refs: dict[str, str]


class PlatformProviderAccessService:
    def __init__(self, *, config, secret_store, credential_validator=None):
        if not callable(getattr(secret_store, "get_secret_value", None)):
            raise TypeError("secret_store.get_secret_value is required.")
        if credential_validator is not None and not callable(
            getattr(credential_validator, "validate", None)
        ):
            raise TypeError("credential_validator.validate is required when provided.")
        self.config = _require_platform_provider_config(config)
        self.secret_store = secret_store
        self.credential_validator = credential_validator

    def get_provider_access_status(self, *, provider=None):
        normalized_provider = self._provider_or_default(provider)
        secret_ref = self.config.secret_refs.get(normalized_provider)
        if secret_ref is None:
            return _status(
                provider=normalized_provider,
                status=PlatformProviderStatus.NOT_CONFIGURED,
                error=_platform_error(
                    code=SecretErrorCodes.PLATFORM_PROVIDER_SECRET_NOT_CONFIGURED,
                    message="Platform provider secret reference is not configured.",
                    http_status=503,
                ),
            )
        try:
            secret_value = self.secret_store.get_secret_value(secret_ref)
            validation_error = self._validate_credential(normalized_provider, secret_value)
        except SecretStoreAccessDenied as cause:
            raise _access_denied(normalized_provider, secret_ref, cause) from cause
        except SecretError:
            raise
        except Exception as cause:
            raise _access_denied(normalized_provider, secret_ref, cause) from cause
        if validation_error is not None:
            return validation_error
        return _status(
            provider=normalized_provider,
            status=PlatformProviderStatus.AVAILABLE,
            secretRef=secret_ref,
        )

    def resolve_provider_access(self, *, provider=None):
        status = self.get_provider_access_status(provider=provider)
        if status["status"] != PlatformProviderStatus.AVAILABLE:
            raise _not_available(status)
        return {
            "provider": status["provider"],
            "credentialSource": PLATFORM_CREDENTIAL_SOURCE,
            "secretRef": status["secretRef"],
            "available": True,
            "status": status["status"],
        }

    def decrypt_for_provider_call(self, *, provider=None, secret_ref=None):
        normalized_provider = self._provider_or_default(provider)
        configured_ref = self.config.secret_refs.get(normalized_provider)
        if configured_ref is None:
            raise _not_configured(normalized_provider)
        if secret_ref is not None and secret_ref != configured_ref:
            raise validation_failed("secret_ref", "secret_ref must match the configured provider reference.")
        try:
            secret_value = self.secret_store.get_secret_value(configured_ref)
            validation_error = self._validate_credential(normalized_provider, secret_value)
        except SecretStoreAccessDenied as cause:
            raise _access_denied(normalized_provider, configured_ref, cause) from cause
        except SecretError:
            raise
        except Exception as cause:
            raise _access_denied(normalized_provider, configured_ref, cause) from cause
        if validation_error is not None:
            raise _not_available(validation_error)
        return {
            "provider": normalized_provider,
            "credentialSource": PLATFORM_CREDENTIAL_SOURCE,
            "secretRef": configured_ref,
            "secretValue": secret_value,
        }

    def _provider_or_default(self, provider):
        if provider is None:
            if self.config.default_provider is None:
                raise _not_configured(None)
            return self.config.default_provider
        return _require_provider(provider)

    def _validate_credential(self, provider, secret_value):
        if not isinstance(secret_value, str) or len(secret_value.strip()) == 0:
            return _status(
                provider=provider,
                status=PlatformProviderStatus.INVALID,
                error=_platform_error(
                    code=SecretErrorCodes.PLATFORM_PROVIDER_SECRET_INVALID,
                    message="Platform provider credential is invalid.",
                    http_status=503,
                ),
            )
        if self.credential_validator is None:
            return None
        try:
            result = self.credential_validator.validate(
                provider=provider,
                secret_value=secret_value,
            )
        except Exception:
            return _status(
                provider=provider,
                status=PlatformProviderStatus.VALIDATION_FAILED,
                error=_platform_error(
                    code=SecretErrorCodes.PLATFORM_PROVIDER_SECRET_VALIDATION_FAILED,
                    message="Platform provider credential validation could not be completed.",
                    http_status=503,
                    retryable=True,
                ),
            )
        if result is False or (isinstance(result, dict) and result.get("valid") is False):
            return _status(
                provider=provider,
                status=PlatformProviderStatus.INVALID,
                error=_platform_error(
                    code=SecretErrorCodes.PLATFORM_PROVIDER_SECRET_INVALID,
                    message="Platform provider credential is invalid.",
                    http_status=503,
                ),
            )
        return None


def platform_provider_config_from_env(env):
    if not isinstance(env, Mapping):
        raise validation_failed("env", "env must be a mapping.")
    secret_refs = {}
    for provider in SUPPORTED_PROVIDER_VALUES:
        key = f"{PLATFORM_PROVIDER_SECRET_REF_PREFIX}{provider.upper()}"
        value = env.get(key)
        if value is not None and len(str(value).strip()) > 0:
            secret_refs[provider] = str(value).strip()
    default_provider = env.get(PLATFORM_PROVIDER_DEFAULT_KEY)
    return _require_platform_provider_config(
        PlatformProviderConfig(
            default_provider=str(default_provider).strip() if default_provider else None,
            secret_refs=secret_refs,
        )
    )


def _require_platform_provider_config(config):
    if isinstance(config, dict):
        config = PlatformProviderConfig(
            default_provider=config.get("default_provider", config.get("defaultProvider")),
            secret_refs=dict(config.get("secret_refs", config.get("secretRefs", {}))),
        )
    if not isinstance(config, PlatformProviderConfig):
        raise TypeError("config must be a PlatformProviderConfig or mapping.")
    normalized_refs = {}
    for provider, secret_ref in config.secret_refs.items():
        normalized_provider = _require_provider(provider)
        if not isinstance(secret_ref, str) or len(secret_ref.strip()) == 0:
            raise validation_failed(
                f"secret_refs.{normalized_provider}",
                "platform provider secret reference must be a non-empty string.",
            )
        normalized_refs[normalized_provider] = secret_ref.strip()
    default_provider = None
    if config.default_provider is not None:
        default_provider = _require_provider(config.default_provider)
        if default_provider not in normalized_refs:
            raise _not_configured(default_provider)
    return PlatformProviderConfig(
        default_provider=default_provider,
        secret_refs=normalized_refs,
    )


def _status(*, provider, status, secretRef=None, error=None):
    return {
        "provider": provider,
        "credentialSource": PLATFORM_CREDENTIAL_SOURCE,
        "available": status == PlatformProviderStatus.AVAILABLE,
        "status": status,
        **({} if secretRef is None else {"secretRef": secretRef}),
        **({} if error is None else {"error": error}),
    }


def _platform_error(*, code, message, http_status, retryable=False):
    return {
        "code": code,
        "category": "DEPENDENCY",
        "message": message,
        "retryable": retryable,
        "httpStatus": http_status,
        "target": "platformProviderSecret",
    }


def _not_configured(provider):
    return SecretError(
        code=SecretErrorCodes.PLATFORM_PROVIDER_SECRET_NOT_CONFIGURED,
        message="Platform provider secret reference is not configured.",
        status=503,
        details={} if provider is None else {"provider": provider},
    )


def _access_denied(provider, secret_ref, cause):
    return SecretError(
        code=SecretErrorCodes.PLATFORM_PROVIDER_SECRET_ACCESS_DENIED,
        message="Platform provider secret could not be accessed.",
        status=503,
        details={
            "provider": provider,
            "cause": cause.__class__.__name__,
        },
    )


def _not_available(status):
    error = status.get("error", {})
    return SecretError(
        code=error.get("code", SecretErrorCodes.PLATFORM_PROVIDER_SECRET_NOT_CONFIGURED),
        message=error.get("message", "Platform provider credential is not available."),
        status=error.get("httpStatus", 503),
        details={"provider": status["provider"], "status": status["status"]},
    )
