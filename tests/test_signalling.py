import json
import unittest
from unittest.mock import patch

from aioice import Connection
from nooie_proxy import rtc, sdp, signalling
from nooie_proxy.cloud import Config, ice_servers, login_body, registration_body

CONFIG = Config(
    api_token="token",
    uid="user",
    phone_code="phone",
    request_uuid="request",
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
            signalling.origin("wss://wss.eu.nooie.com/ws"),
            "https://wss.eu.nooie.com",
        )

    def test_websocket_json_matches_foundation_pretty_format(self) -> None:
        value = {
            "z": "a/b",
            "data": {},
            "items": ["one", "two"],
            "enabled": True,
        }

        self.assertEqual(
            signalling.dumps(value),
            "\n".join(
                [
                    "{",
                    '  "data" : {',
                    "",
                    "  },",
                    '  "enabled" : true,',
                    '  "items" : [',
                    '    "one",',
                    '    "two"',
                    "  ],",
                    '  "z" : "a\\/b"',
                    "}",
                ]
            ),
        )

    def test_login_and_registration_use_distinct_official_brand_fields(
        self,
    ) -> None:
        with patch.dict("os.environ", {}, clear=True):
            login = login_body("account", "password", "phone")
            registration = registration_body(CONFIG)

        self.assertEqual(login["phone_brand"], "iPad Pro 12.9-in. 3rd gen")
        self.assertEqual(login["password"], "5f4dcc3b5aa765d61d8327deb882cf99")
        self.assertEqual(registration["phone_brand"], "Apple")
        self.assertEqual(registration["phone_code"], CONFIG.phone_code)
        self.assertEqual(
            set(registration),
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

    def test_candidates_use_compact_sdp_and_media_coordinates(self) -> None:
        offer = "\r\n".join(
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

        candidates = sdp.local_candidates(offer)

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
        call = signalling.Call(call_uuid="12345678-90AB-CDEF-1234-567890ABCDEF")
        offer = signalling.offer(CONFIG, SESSION, call, "00\r\n{}")
        candidates = sdp.local_candidates(
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
        candidate = signalling.candidate(CONFIG, SESSION, call, candidates[0])
        switch = signalling.switch(CONFIG, SESSION, call)

        self.assertEqual(call.call_id, "iOS_12345678-90A")
        self.assertEqual(offer["msg_id"], "iOS_12345678-90A_1001")
        self.assertEqual(offer["data"]["IceUrl"], ["turn:camera.example"])
        self.assertIs(offer["data"]["EnableMic"], False)
        self.assertIs(offer["data"]["EnableSpeaker"], False)
        self.assertTrue(candidate["msg_id"].startswith("iOS_"))
        self.assertTrue(candidate["msg_id"].endswith("_1002"))
        self.assertTrue(switch["msg_id"].endswith("_1003"))
        self.assertRegex(
            candidate["data"]["WebrtcCandidate"],
            r"^candidate:\d+ 1 udp 2122260223 ",
        )
        self.assertIn(
            "typ host generation 0 ufrag abcde network-id 1 network-cost 10",
            candidate["data"]["WebrtcCandidate"],
        )
        self.assertEqual(candidate["data"]["WebrtcSdpMid"], "0")
        self.assertEqual(candidate["data"]["WebrtcSdpMLineIndex"], 0)
        self.assertIn("tme", switch)
        self.assertNotIn("time", switch)

    def test_compact_offer_matches_decrypted_ios_shape(self) -> None:
        compact = sdp.compact_offer(
            "\r\n".join(
                [
                    "o=- 12345 2 IN IP4 127.0.0.1",
                    "a=ice-ufrag:ufrag",
                    "a=ice-pwd:password",
                    "a=fingerprint:sha-256 AA:BB",
                    "",
                ]
            )
        )
        payload = json.loads(compact[4:])

        self.assertTrue(compact.startswith("00\r\n{"))
        self.assertRegex(payload["com"]["iO"], r"^ \d{19} 2 IN IP4 127\.0\.0\.1$")
        self.assertEqual(payload["com"]["o"], "trickle renomination")
        self.assertEqual(payload["com"]["I"], " IP4 0.0.0.0")
        self.assertEqual(payload["com"]["iT"], "0 0")
        self.assertEqual(payload["com"]["iG"], "0 1")
        self.assertEqual(payload["com"]["ft"], "sha-256 AA:BB")
        self.assertEqual(payload["com"]["u"], "ufrag")
        self.assertEqual(payload["com"]["p"], "password")
        self.assertEqual(payload["audio"]["md"], "Lo AID")
        self.assertEqual(payload["video"]["md"], "Lo VID")
        self.assertEqual(payload["video"]["fmtp"], ["99 apt=126", "101 apt=100"])

    def test_compact_answer_accepts_space_separated_ios_candidate(self) -> None:
        answer = {
            "com": {
                "ft": "sha-256 AA:BB",
                "ic": (
                    "0 1 udp 2130706431 192.0.2.10 50000 typ host "
                    "raddr 0.0.0.0 rport 0 generation 0 ufrag abcd "
                    "network-cost 999"
                ),
                "u": "abcd",
                "p": "answer-password",
                "s": "active",
            },
            "video": {
                "pt": 126,
                "sc": "1234",
                "ce": "video-cname",
                "m": 9,
                "mid": 0,
                "pts": 90000,
            },
            "audio": {
                "pt": 96,
                "sc": "5678",
                "ce": "audio-cname",
                "m": 9,
                "mid": 1,
                "pts": 16000,
            },
        }

        expanded = sdp.expand_answer(
            "00\r\n" + json.dumps(answer, separators=(",", ":"))
        )

        self.assertIn("a=fingerprint:sha-256 AA:BB\r\n", expanded)
        self.assertNotIn("sha-256  AA:BB", expanded)
        self.assertIn(
            "a=candidate:0 1 udp 2130706431 192.0.2.10 50000 "
            "typ host raddr 0.0.0.0 rport 0 generation 0 "
            "ufrag abcd network-cost 999\r\n",
            expanded,
        )
        self.assertEqual(sdp.video_ssrc(expanded), 1234)

    def test_compact_answer_expands_a_space_free_candidate(self) -> None:
        self.assertEqual(
            sdp.expand_candidate("11udp2130706431192.0.2.1050000typhost"),
            "1 1 udp 2130706431 192.0.2.10 50000 typ host",
        )

    def test_ice_credentials_match_ios_lengths(self) -> None:
        rtc.patch()
        connection = Connection(ice_controlling=True)

        self.assertEqual(len(connection.local_username), 4)
        self.assertEqual(len(connection.local_password), 24)


if __name__ == "__main__":
    unittest.main()
