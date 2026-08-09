"""the nooie ios build this proxy impersonates: credentials and fingerprint.

everything the account servers see about the caller comes from one app build
(nooie ios 3.7.0, thing sdk 5.7.10, on an ipad pro 12.9). if nooie ships a
new app and the backend starts rejecting this one, the strings to update all
live here.
"""

import json

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

# --- the thing/tuya sdk bundle nooie ships inside the app ------------------

THING_API_URL = "https://a1.tuyaeu.com/api.json"
THING_APP_KEY = "kvradrme9pmyjckdd7ws"
THING_APP_SECRET = "jmaj939wk95awxur9xe7trgpwnyddpu8"
THING_PICTURE_KEY = "8ey4j8m7dsx8qtvpnrdhfwqn7p4gv579"
THING_BUNDLE_ID = "com.nooie.home"

THING_BIZ_DATA = json.dumps(
    {
        "miniappVersion": json.dumps(
            {
                "MapKit": "3.9.4",
                "BizKit": "4.14.8",
                "BaseKit": "3.18.6",
                "container": "3.25.0",
                "MiniKit": "3.15.3",
                "DeviceKit": "4.13.6",
                "basicLib": "",
            },
            separators=(",", ":"),
        ),
        "nd": 1,
        "customDomainSupport": "1",
    },
    separators=(",", ":"),
)

# static sdk 5.7.10 identification, exactly as the ios build reports it.
THING_SDK = {
    "sdkVersion": "5.7.10",
    "deviceCoreVersion": "5.18.0",
    "appVersion": "3.7.0",
    "appRnVersion": "5.92",
    "channel": "sdk",
    "os": "IOS",
    "osSystem": "26.5",
    "platform": "iPad8,6",
    "lang": "en",
    "timeZoneId": "Europe/London",
    "ttid": "appstore_r",
    "et": "0.0.2",
    "nd": "1",
    "cp": "gzip",
    "lat": "0",
    "lon": "0",
    "bizData": THING_BIZ_DATA,
}

# --- apeman p2p control channel -------------------------------------------

APEMAN_SALT = "ApEMaNSNoOiE"
APEMAN_RPC_VERSION = b"5.0.0"
POLICY_HOST = "policy-eu.nooie.com"
POLICY_PORT = 9000
