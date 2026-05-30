import { createHmac } from "node:crypto";

const DEFAULT_FINGERPRINT_PREFIX_LENGTH = 16;

export function createHmacFingerprintHasher({ key, prefixLength = DEFAULT_FINGERPRINT_PREFIX_LENGTH }) {
  if (typeof key !== "string" || key.length < 16) {
    throw new TypeError("fingerprint key must be at least 16 characters.");
  }
  return {
    fingerprint(secretValue) {
      const digest = createHmac("sha256", key).update(secretValue, "utf8").digest("hex");
      return `hmac-sha256:${digest.slice(0, prefixLength)}`;
    }
  };
}
