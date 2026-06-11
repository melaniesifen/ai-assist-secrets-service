import unittest

from ai_assist_secrets_service import SecretError, SecretErrorCodes


class SecretErrorTest(unittest.TestCase):
    def test_formats_typed_errors_as_stable_response_envelopes(self):
        error = SecretError(
            code=SecretErrorCodes.VALIDATION_FAILED,
            message="Bad request.",
            status=400,
            details={"field": "provider"},
        )

        self.assertEqual(
            error.to_response(),
            {
                "error": {
                    "code": SecretErrorCodes.VALIDATION_FAILED,
                    "message": "Bad request.",
                    "details": {"field": "provider"},
                },
                "status": 400,
            },
        )


if __name__ == "__main__":
    unittest.main()
