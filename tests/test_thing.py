import base64
import hashlib
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from nooie_proxy.env import identity, state_dir
from nooie_proxy.thing import (
    ThingApp,
    ThingSession,
    build_request_params,
    decrypt_result,
    derive_mqtt_credentials,
    encrypt_post_data,
    mqtt_topic,
    rsa_encrypt_password,
    sign_request,
)

APP = ThingApp(
    app_key="test-app-key",
    app_secret="test-app-secret",
    secret_pic_key="test-picture-key",
)
DEVICE_ID = "12345678-1234-4ABC-8DEF-1234567890AB"
REQUEST_ID = "ABCDEF12-3456-4ABC-8DEF-1234567890AB"
SESSION = ThingSession(
    sid="test-session",
    ecode="test-ecode",
    uid="test-user",
    partner_identity="test-partner",
    domain={"mobileMqttsUrl": "ssl://mqtt.example.test", "mqttsPort": 8883},
)


class ThingProtocolTests(unittest.TestCase):
    def test_bundled_material_has_built_in_defaults(self) -> None:
        app = ThingApp()

        self.assertTrue(app.app_key)
        self.assertTrue(app.app_secret)
        self.assertTrue(app.secret_pic_key)
        self.assertEqual(app.bundle_id, "com.nooie.home")

    def test_payload_encryption_round_trips(self) -> None:
        wrapper = {
            "success": True,
            "result": {"sid": "session", "items": [1, 2, 3]},
        }

        encrypted = encrypt_post_data(APP, REQUEST_ID, wrapper, SESSION.ecode)

        self.assertEqual(
            decrypt_result(APP, REQUEST_ID, encrypted, SESSION.ecode), wrapper
        )

    def test_request_without_payload_omits_post_data(self) -> None:
        params = build_request_params(
            APP,
            DEVICE_ID,
            "m.life.home.space.list",
            "1.0",
            None,
            request_id=REQUEST_ID,
            timestamp=1234567890,
            sid=SESSION.sid,
        )

        self.assertNotIn("postData", params)
        self.assertEqual(params["deviceId"], DEVICE_ID)
        signature = params.pop("sign")
        self.assertEqual(signature, sign_request(APP, params))

    def test_raw_rsa_password_operation_encrypts_one_md5_digest(self) -> None:
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=1024
        )
        public_der = private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        encrypted_hex = rsa_encrypt_password(
            "correct horse battery staple",
            base64.b64encode(public_der).decode(),
        )

        numbers = private_key.private_numbers()
        plaintext = pow(
            int(encrypted_hex, 16), numbers.d, numbers.public_numbers.n
        ).to_bytes(private_key.key_size // 8, "big")
        digest = (
            hashlib.md5(b"correct horse battery staple").hexdigest().encode()
        )
        self.assertEqual(plaintext[-len(digest) :], digest)
        self.assertEqual(plaintext[: -len(digest)], bytes(96))

    def test_mqtt_credentials_endpoint_and_account_topic(self) -> None:
        credentials = derive_mqtt_credentials(APP, SESSION, DEVICE_ID)

        client_hash = hashlib.md5(
            (SESSION.sid + "sdkfasodifca").encode()
        ).hexdigest()
        self.assertEqual(credentials.client_id, f"iOS_{DEVICE_ID}_{client_hash}")
        self.assertEqual(mqtt_topic(SESSION), "test-partner/mb/test-user")
        self.assertEqual(SESSION.mqtt_endpoint, ("mqtt.example.test", 8883))
        self.assertNotIn(credentials.password, repr(credentials))


class IdentityTests(unittest.TestCase):
    def test_persisted_identity_is_stable_and_private(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "state"
            with patch.dict(
                os.environ, {"XDG_CONFIG_HOME": str(root), "HOME": str(root)}
            ), patch("sys.platform", "linux"):
                first, second = identity(), identity()
                path = state_dir() / "identity"

            self.assertEqual(first, second)
            self.assertEqual(first, first.upper())
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
