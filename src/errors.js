export const SECRET_ERROR_CODES = Object.freeze({
  VALIDATION_FAILED: "VALIDATION_FAILED",
  PROVIDER_SECRET_NOT_FOUND: "PROVIDER_SECRET_NOT_FOUND",
  PROVIDER_SECRET_EXPIRED: "PROVIDER_SECRET_EXPIRED",
  PROVIDER_SECRET_DELETED: "PROVIDER_SECRET_DELETED",
  SECRET_DECRYPT_FAILED: "SECRET_DECRYPT_FAILED",
  TENANT_ACCESS_DENIED: "TENANT_ACCESS_DENIED"
});

export class SecretError extends Error {
  constructor({ code, message, status = 500, details = {} }) {
    super(message);
    this.name = "SecretError";
    this.code = code;
    this.status = status;
    this.details = Object.freeze({ ...details });
  }

  toResponse() {
    return {
      error: {
        code: this.code,
        message: this.message,
        details: this.details
      },
      status: this.status
    };
  }
}

export function validationFailed(field, message) {
  return new SecretError({
    code: SECRET_ERROR_CODES.VALIDATION_FAILED,
    message,
    status: 400,
    details: { field }
  });
}

export function forbidden() {
  return new SecretError({
    code: SECRET_ERROR_CODES.TENANT_ACCESS_DENIED,
    message: "The requested secret reference is not authorized.",
    status: 403
  });
}
