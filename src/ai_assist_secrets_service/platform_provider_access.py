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
    QUOTA_DENIED = "quota_denied"
    QUOTA_NOT_CONFIGURED = "quota_not_configured"
    AUDIT_NOT_CONFIGURED = "audit_not_configured"


class SecretStoreAccessDenied(Exception):
    pass


@dataclass(frozen=True)
class PlatformProviderConfig:
    default_provider: str | None
    secret_refs: dict[str, str]


class PlatformProviderAccessService:
    def __init__(
        self,
        *,
        config,
        secret_store,
        credential_validator=None,
        metering_checker=None,
        require_metering=False,
    ):
        if not callable(getattr(secret_store, "get_secret_value", None)):
            raise TypeError("secret_store.get_secret_value is required.")
        if credential_validator is not None and not callable(
            getattr(credential_validator, "validate", None)
        ):
            raise TypeError("credential_validator.validate is required when provided.")
        if metering_checker is not None and not callable(
            getattr(metering_checker, "check_provider_access", None)
        ):
            raise TypeError("metering_checker.check_provider_access is required when provided.")
        self.config = _require_platform_provider_config(config)
        self.secret_store = secret_store
        self.credential_validator = credential_validator
        self.metering_checker = metering_checker
        self.require_metering = bool(require_metering)

    def get_provider_access_status(self, *, provider=None, identity=None, request=None):
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
        metering_error, metering = self._metering_decision(
            provider=normalized_provider,
            identity=identity,
            request=request,
        )
        if metering_error is not None:
            return metering_error
        return _status(
            provider=normalized_provider,
            status=PlatformProviderStatus.AVAILABLE,
            secretRef=secret_ref,
            **metering,
        )

    def resolve_provider_access(self, *, provider=None, identity=None, request=None):
        status = self.get_provider_access_status(provider=provider, identity=identity, request=request)
        if status["status"] != PlatformProviderStatus.AVAILABLE:
            raise _not_available(status)
        return {
            "provider": status["provider"],
            "credentialSource": PLATFORM_CREDENTIAL_SOURCE,
            "secretRef": status["secretRef"],
            "available": True,
            "status": status["status"],
            "quotaDecision": status.get("quotaDecision"),
            "auditDecision": status.get("auditDecision"),
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

    def _metering_decision(self, *, provider, identity, request):
        if self.metering_checker is None:
            if not self.require_metering:
                return None, {}
            return _metering_not_ready(provider), {}
        try:
            result = self.metering_checker.check_provider_access(
                identity=identity,
                provider=provider,
                request=request or {},
            )
        except Exception:
            return _metering_not_ready(provider), {}
        if not isinstance(result, Mapping):
            return _metering_not_ready(provider), {}
        quota = result.get("quotaDecision") if isinstance(result.get("quotaDecision"), Mapping) else {}
        audit = result.get("auditDecision") if isinstance(result.get("auditDecision"), Mapping) else {}
        if _normalized_decision(quota.get("decision")) != "allow":
            status = PlatformProviderStatus.QUOTA_DENIED if _normalized_decision(quota.get("decision")) == "deny" else PlatformProviderStatus.QUOTA_NOT_CONFIGURED
            code = SecretErrorCodes.PLATFORM_PROVIDER_QUOTA_DENIED if status == PlatformProviderStatus.QUOTA_DENIED else SecretErrorCodes.PLATFORM_PROVIDER_QUOTA_NOT_CONFIGURED
            return _status(
                provider=provider,
                status=status,
                quotaDecision=_safe_decision(quota),
                auditDecision=_safe_decision(audit),
                error=_platform_error(
                    code=code,
                    message="Platform provider quota is not available.",
                    http_status=429 if status == PlatformProviderStatus.QUOTA_DENIED else 503,
                    target="platformProviderQuota",
                ),
            ), {}
        if _normalized_decision(audit.get("decision")) != "recorded":
            return _status(
                provider=provider,
                status=PlatformProviderStatus.AUDIT_NOT_CONFIGURED,
                quotaDecision=_safe_decision(quota),
                auditDecision=_safe_decision(audit),
                error=_platform_error(
                    code=SecretErrorCodes.PLATFORM_PROVIDER_AUDIT_NOT_CONFIGURED,
                    message="Platform provider audit recording is not available.",
                    http_status=503,
                    target="platformProviderAudit",
                ),
            ), {}
        return None, {
            "quotaDecision": _safe_decision(quota),
            "auditDecision": _safe_decision(audit),
        }


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


def _status(*, provider, status, secretRef=None, error=None, quotaDecision=None, auditDecision=None):
    return {
        "provider": provider,
        "credentialSource": PLATFORM_CREDENTIAL_SOURCE,
        "available": status == PlatformProviderStatus.AVAILABLE,
        "status": status,
        **({} if secretRef is None else {"secretRef": secretRef}),
        **({} if quotaDecision is None else {"quotaDecision": quotaDecision}),
        **({} if auditDecision is None else {"auditDecision": auditDecision}),
        **({} if error is None else {"error": error}),
    }


def _platform_error(*, code, message, http_status, retryable=False, target="platformProviderSecret"):
    return {
        "code": code,
        "category": "DEPENDENCY",
        "message": message,
        "retryable": retryable,
        "httpStatus": http_status,
        "target": target,
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


def _metering_not_ready(provider):
    return _status(
        provider=provider,
        status=PlatformProviderStatus.QUOTA_NOT_CONFIGURED,
        error=_platform_error(
            code=SecretErrorCodes.PLATFORM_PROVIDER_QUOTA_NOT_CONFIGURED,
            message="Platform provider quota is not configured.",
            http_status=503,
            target="platformProviderQuota",
        ),
    )


def _safe_decision(decision):
    return {
        key: value
        for key, value in dict(decision).items()
        if key in {"decision", "status", "reasonCode", "retryAfterSeconds"}
    }


def _normalized_decision(value):
    if not isinstance(value, str):
        return None
    normalized = value.strip().lower()
    return normalized or None
