"""the nooie ios build this proxy impersonates: credentials and fingerprint.

everything the account servers see about the caller comes from one app build
(nooie ios 3.7.0, on an ipad pro 12.9). if nooie ships a new app and the
backend starts rejecting this one, the strings to update all live here.
"""

# --- nooie cloud rest api and websocket signalling -------------------------

API_BASE = "https://app.eu.nooie.com/v2"
WS_URL = "wss://wss.eu.nooie.com/ws"
APP_ID = "4adcd2139621b1ef"
APP_SECRET = "9e03f0b14adcd2139621b1ef984b2ac0"
USER_AGENT = "Nooie_IOS_3.7.0"

# the install metadata posted at login and client registration.
DEVICE = {
    "phone_brand": "iPad Pro 12.9-in. 3rd gen",
    "phone_version": "26.5",
    "app_version": "3.7.0",
    "app_version_code": "11",
    "phone_screen": "[1470, 956]",
    "device_type": 2,
    "package_name": "com.nooie.home",
    "language": "en",
    "phone_model": "iPad8,6",
    "push_type": 3,
}

# --- apeman p2p control channel -------------------------------------------

APEMAN_SALT = "ApEMaNSNoOiE"
APEMAN_RPC_VERSION = b"5.0.0"
POLICY_HOST = "policy-eu.nooie.com"
POLICY_PORT = 9000
