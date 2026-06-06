from types import MappingProxyType


class SecretErrorCodes:
    VALIDATION_FAILED = "VALIDATION_FAILED"
    PROVIDER_SECRET_NOT_FOUND = "PROVIDER_SECRET_NOT_FOUND"
    PROVIDER_SECRET_PENDING_VALIDATION = "PROVIDER_SECRET_PENDING_VALIDATION"
    PROVIDER_SECRET_INVALID = "PROVIDER_SECRET_INVALID"
    PROVIDER_SECRET_VALIDATION_FAILED = "PROVIDER_SECRET_VALIDATION_FAILED"
    PROVIDER_SECRET_EXPIRED = "PROVIDER_SECRET_EXPIRED"
    PROVIDER_SECRET_DELETED = "PROVIDER_SECRET_DELETED"
    SECRET_DECRYPT_FAILED = "SECRET_DECRYPT_FAILED"
    TENANT_ACCESS_DENIED = "TENANT_ACCESS_DENIED"


class SecretError(Exception):
    def __init__(self, *, code, message, status=500, details=None):
        super().__init__(message)
        self.code = code
        self.status = status
        self.details = MappingProxyType(dict(details or {}))

    def to_response(self):
        return {
            "error": {
                "code": self.code,
                "message": str(self),
                "details": dict(self.details),
            },
            "status": self.status,
        }


def validation_failed(field, message):
    return SecretError(
        code=SecretErrorCodes.VALIDATION_FAILED,
        message=message,
        status=400,
        details={"field": field},
    )


def forbidden():
    return SecretError(
        code=SecretErrorCodes.TENANT_ACCESS_DENIED,
        message="The requested secret reference is not authorized.",
        status=403,
    )
