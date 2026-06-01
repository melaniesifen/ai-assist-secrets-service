import hmac
from hashlib import sha256


DEFAULT_FINGERPRINT_PREFIX_LENGTH = 16
MIN_FINGERPRINT_KEY_LENGTH = 16


class HmacFingerprintHasher:
    def __init__(self, *, key, prefix_length=DEFAULT_FINGERPRINT_PREFIX_LENGTH):
        if not isinstance(key, str) or len(key) < MIN_FINGERPRINT_KEY_LENGTH:
            raise TypeError("fingerprint key must be at least 16 characters.")
        self._key = key.encode("utf-8")
        self._prefix_length = prefix_length

    def fingerprint(self, secret_value):
        digest = hmac.new(self._key, secret_value.encode("utf-8"), sha256).hexdigest()
        return f"hmac-sha256:{digest[:self._prefix_length]}"


def create_hmac_fingerprint_hasher(*, key, prefix_length=DEFAULT_FINGERPRINT_PREFIX_LENGTH):
    return HmacFingerprintHasher(key=key, prefix_length=prefix_length)
