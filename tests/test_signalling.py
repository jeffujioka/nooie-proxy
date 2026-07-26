import unittest
from unittest.mock import patch

from aioice import Connection

from nooie_tui.client import (
    Config,
    SignallingCall,
    client_registration,
    compact_sdp_offer,
    enable_nooie_ice_credentials,
    ice_servers,
    local_candidates,
    login_request_body,
    signalling_candidate,
    signalling_offer,
    signalling_reset,
    signalling_switch,
    websocket_origin,
)

CONFIG = Config(
    app_id="app",
    app_secret="secret",
    api_token="token",
    uid="user",
    request_uuid="request",
    phone_code="phone",
    device_id="camera",
    model_id="model",
)
SESSION = {
    "session_id": "session",
    "device_ices": [
        {
            "iceurl": "turn:camera.example",
            "username": "ice-user",
            "password": "ice-password",
        }
    ],
}


class SignallingTests(unittest.TestCase):
    def test_websocket_origin_matches_socketrocket(self) -> None:
        self.assertEqual(
            websocket_origin("wss://wss.eu.nooie.com/ws"),
            "https://wss.eu.nooie.com",
        )

    def test_login_and_registration_use_distinct_official_brand_fields(
        self,
    ) -> None:
        with patch.dict("os.environ", {}, clear=True):
            login_body = login_request_body(
                "account", "password", "phone", "44", 1
            )
            registration_body = client_registration(CONFIG)

        self.assertEqual(
            login_body["phone_brand"], "iPad Pro 12.9-in. 3rd gen"
        )
        self.assertEqual(registration_body["phone_brand"], "Apple")
        self.assertEqual(
            login_body["password"],
            "5f4dcc3b5aa765d61d8327deb882cf99",
        )

    def test_client_registration_matches_official_field_shape(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            body = client_registration(CONFIG)

        self.assertEqual(
            set(body),
            {
                "phone_brand",
                "zone",
                "phone_version",
                "app_version",
                "phone_screen",
                "device_type",
                "phone_code",
                "package_name",
                "language",
                "app_version_code",
                "country",
                "push_type",
                "phone_model",
            },
        )
        self.assertEqual(body["phone_code"], CONFIG.phone_code)
        self.assertEqual(body["package_name"], "com.nooie.home")
        self.assertEqual(body["device_type"], 2)
        self.assertEqual(body["push_type"], 3)

    def test_candidates_use_compact_sdp_and_media_coordinates(self) -> None:
        sdp = "\r\n".join(
            [
                "m=video 9 UDP/TLS/RTP/SAVPF 126",
                "a=ice-ufrag:abcde",
                "a=mid:video",
                (
                    "a=candidate:video-foundation 1 udp 2130706431 "
                    "192.0.2.10 50000 typ host"
                ),
                "m=audio 9 UDP/TLS/RTP/SAVPF 96",
                "a=mid:audio",
                (
                    "a=candidate:audio-foundation 1 udp 1694498815 "
                    "198.51.100.20 50001 typ srflx "
                    "raddr 192.0.2.10 rport 50001"
                ),
                "",
            ]
        )

        candidates = local_candidates(sdp)

        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].sdp_mid, "video")
        self.assertEqual(candidates[0].sdp_mline_index, 0)
        self.assertIn(" 1 udp ", candidates[0].sdp)
        self.assertEqual(candidates[0].ice_ufrag, "abcde")

    def test_turn_credentials_are_passed_to_aiortc(self) -> None:
        servers = ice_servers(
            {
                "user_ices": [
                    {"iceurl": "stun:stun.example"},
                    {
                        "iceurl": "turn:turn.example?transport=udp",
                        "username": "turn-user",
                        "password": "turn-password",
                    },
                ]
            }
        )

        self.assertEqual(len(servers), 2)
        self.assertIsNone(servers[0].username)
        self.assertIsNone(servers[0].credential)
        self.assertEqual(servers[1].username, "turn-user")
        self.assertEqual(servers[1].credential, "turn-password")

    def test_call_uses_one_monotonic_message_sequence(self) -> None:
        call = SignallingCall(call_uuid="12345678-90AB-CDEF-1234-567890ABCDEF")
        reset = signalling_reset(CONFIG, call)
        offer = signalling_offer(CONFIG, SESSION, call, "00\n{}")
        candidates = local_candidates(
            "\r\n".join(
                [
                    "m=video 9 UDP/TLS/RTP/SAVPF 126",
                    "a=ice-ufrag:abcde",
                    "a=mid:0",
                    (
                        "a=candidate:foundation 1 udp 2130706431 "
                        "192.0.2.10 50000 typ host"
                    ),
                    "",
                ]
            )
        )
        candidate = signalling_candidate(
            CONFIG, SESSION, call, candidates[0]
        )
        switch = signalling_switch(CONFIG, SESSION, call)

        self.assertEqual(call.call_id, "iOS_12345678-90A")
        self.assertEqual(reset["method"], "service.Close")
        self.assertEqual(reset["data"], {})
        self.assertTrue(reset["msg_id"].endswith("_1001"))
        self.assertEqual(offer["msg_id"], "iOS_12345678-90A_1002")
        self.assertTrue(candidate["msg_id"].startswith("iOS_"))
        self.assertTrue(candidate["msg_id"].endswith("_1003"))
        self.assertTrue(switch["msg_id"].startswith("iOS_"))
        self.assertTrue(switch["msg_id"].endswith("_1004"))
        self.assertNotIn(" ", candidate["data"]["WebrtcCandidate"])
        self.assertRegex(
            candidate["data"]["WebrtcCandidate"],
            r"^candidate:\d+1udp2122260223",
        )
        self.assertIn(
            "typhostgeneration0ufragabcdenetwork-id1network-cost10",
            candidate["data"]["WebrtcCandidate"],
        )
        self.assertEqual(candidate["data"]["WebrtcSdpMid"], "0")
        self.assertEqual(candidate["data"]["WebrtcSdpMLineIndex"], 0)
        self.assertIn("time", switch)
        self.assertNotIn("tme", switch)

    def test_compact_offer_uses_ios_bare_lf_marker(self) -> None:
        sdp = "\r\n".join(
            [
                "o=- 12345 2 IN IP4 127.0.0.1",
                "a=ice-ufrag:ufrag",
                "a=ice-pwd:password",
                "a=fingerprint:sha-256 AA:BB",
                "",
            ]
        )

        self.assertTrue(compact_sdp_offer(sdp).startswith("00\n{"))
        self.assertFalse(compact_sdp_offer(sdp).startswith("00\r\n{"))

    def test_ice_credentials_match_ios_lengths(self) -> None:
        enable_nooie_ice_credentials()
        connection = Connection(ice_controlling=True)

        self.assertEqual(len(connection.local_username), 4)
        self.assertEqual(len(connection.local_password), 24)


if __name__ == "__main__":
    unittest.main()
