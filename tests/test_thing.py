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

from nooie_tui.thing import (
    ThingApp,
    ThingClient,
    ThingRequestProfile,
    ThingSession,
    build_request_params,
    decrypt_result,
    derive_mqtt_credentials,
    encrypt_post_data,
    load_or_create_device_id,
    mqtt_topics,
    rsa_encrypt_password,
    sign_request,
    thing_app_from_environment,
)

APP = ThingApp(
    app_key="test-app-key",
    app_secret="test-app-secret",
    secret_pic_key="test-picture-key",
)
DEVICE_ID = "12345678-1234-4ABC-8DEF-1234567890AB"
REQUEST_ID = "ABCDEF12-3456-4ABC-8DEF-1234567890AB"
PROFILE = ThingRequestProfile(
    platform_name="test-platform",
    os_system="test-os",
    language="en",
    time_zone_id="Europe/London",
)
SESSION = ThingSession(
    sid="test-session",
    ecode="test-ecode",
    uid="test-user",
    username="test-name",
    partner_identity="test-partner",
    domain={
        "mobileMqttsUrl": "ssl://mqtt.example.test",
        "mqttsPort": 8883,
    },
)


class ThingProtocolTests(unittest.TestCase):
    def test_shared_thing_material_has_built_in_defaults(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            app = thing_app_from_environment()

        self.assertTrue(app.app_key)
        self.assertTrue(app.app_secret)
        self.assertTrue(app.secret_pic_key)
        self.assertEqual(app.bundle_id, "com.nooie.home")

    def test_payload_encryption_round_trips(self) -> None:
        wrapper = {
            "success": True,
            "result": {"sid": "session", "items": [1, 2, 3]},
        }

        encrypted = encrypt_post_data(
            APP, REQUEST_ID, wrapper, SESSION.ecode
        )

        self.assertEqual(
            decrypt_result(APP, REQUEST_ID, encrypted, SESSION.ecode),
            wrapper,
        )

    def test_request_without_payload_omits_post_data(self) -> None:
        params = build_request_params(
            APP,
            DEVICE_ID,
            PROFILE,
            "m.life.home.space.list",
            "1.0",
            None,
            request_id=REQUEST_ID,
            timestamp=1234567890,
            sid=SESSION.sid,
        )

        self.assertNotIn("postData", params)
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
            int(encrypted_hex, 16),
            numbers.d,
            numbers.public_numbers.n,
        ).to_bytes(private_key.key_size // 8, "big")
        digest = hashlib.md5(
            b"correct horse battery staple"
        ).hexdigest().encode()
        self.assertEqual(plaintext[-len(digest) :], digest)
        self.assertEqual(plaintext[: -len(digest)], bytes(96))

    def test_mqtt_credentials_and_account_topic(self) -> None:
        credentials = derive_mqtt_credentials(APP, SESSION, DEVICE_ID)

        client_hash = hashlib.md5(
            (SESSION.sid + "sdkfasodifca").encode()
        ).hexdigest()
        self.assertEqual(
            credentials.client_id,
            f"iOS_{DEVICE_ID}_{client_hash}",
        )
        self.assertEqual(
            mqtt_topics(SESSION),
            ["test-partner/mb/test-user"],
        )
        self.assertNotIn(credentials.password, repr(credentials))

    def test_persisted_device_identity_is_stable_and_private(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "state" / "identity.json"
            with patch.dict(
                os.environ, {"NOOIE_THING_DEVICE_ID": ""}
            ):
                first = load_or_create_device_id(path)
                second = load_or_create_device_id(path)

            self.assertEqual(first, second)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_identity_does_not_restrict_an_existing_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            parent.chmod(0o755)
            path = parent / "identity.json"

            with patch.dict(
                os.environ, {"NOOIE_THING_DEVICE_ID": ""}
            ):
                load_or_create_device_id(path)

            self.assertEqual(
                stat.S_IMODE(parent.stat().st_mode),
                0o755,
            )


class ThingBootstrapTests(unittest.IsolatedAsyncioTestCase):
    async def test_home_bootstrap_uses_the_recovered_actions(self) -> None:
        class RecordingClient(ThingClient):
            def __init__(self) -> None:
                super().__init__(APP, DEVICE_ID, PROFILE)
                self.calls = []

            async def request(
                self,
                http,
                action,
                version,
                payload,
                *,
                ecode="",
                sid="",
            ):
                self.calls.append(
                    (action, version, payload, ecode, sid)
                )
                if action == "m.life.home.space.list":
                    return [{"gid": 42}]
                return []

        client = RecordingClient()

        homes = await client.home_spaces(None, SESSION)
        devices = await client.home_devices(None, SESSION, 42)

        self.assertEqual(homes, [{"gid": 42}])
        self.assertEqual(devices, [])
        self.assertEqual(
            client.calls,
            [
                (
                    "m.life.home.space.list",
                    "1.0",
                    None,
                    SESSION.ecode,
                    SESSION.sid,
                ),
                (
                    "m.life.my.group.device.list",
                    "2.2",
                    {"gid": 42},
                    SESSION.ecode,
                    SESSION.sid,
                ),
            ],
        )


if __name__ == "__main__":
    unittest.main()
