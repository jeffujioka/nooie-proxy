"""the websocket call protocol: envelopes in, camera answers out."""

import json
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from . import sdp
from .cloud import Config


@dataclass
class Call:
    """the per-call identifiers nooie's ios signalling implementation uses."""

    call_uuid: str = field(default_factory=lambda: str(uuid.uuid4()).upper())
    message_id: int = 1000

    @property
    def call_id(self) -> str:
        return f"iOS_{self.call_uuid[:12]}"

    def next_message_id(self, *, call_scoped: bool = False) -> str:
        self.message_id += 1
        prefix = (
            self.call_id if call_scoped else f"iOS_{str(uuid.uuid4()).upper()}"
        )
        return f"{prefix}_{self.message_id}"


def origin(url: str) -> str:
    """match socketrocket's native ws->http / wss->https origin mapping."""
    parsed = urlsplit(url)
    schemes = {"ws": "http", "wss": "https"}
    if parsed.scheme not in schemes or not parsed.netloc:
        raise ValueError("Nooie WebSocket URL is invalid")
    return f"{schemes[parsed.scheme]}://{parsed.netloc}"


def dumps(value: Any) -> str:
    """match nsjsonserialization's pretty-printed signalling wire format."""

    def render(item: Any, level: int) -> str:
        indent = "  " * level
        child = "  " * (level + 1)
        if isinstance(item, dict):
            if not item:
                return "{\n\n" + indent + "}"
            fields = [
                child
                + json.dumps(str(key), ensure_ascii=False)
                + " : "
                + render(item[key], level + 1)
                for key in sorted(item)
            ]
            return "{\n" + ",\n".join(fields) + "\n" + indent + "}"
        if isinstance(item, (list, tuple)):
            if not item:
                return "[\n\n" + indent + "]"
            fields = [child + render(entry, level + 1) for entry in item]
            return "[\n" + ",\n".join(fields) + "\n" + indent + "]"
        return json.dumps(
            item, ensure_ascii=False, separators=(",", ":")
        ).replace("/", r"\/")

    return render(value, 0)


def envelope(
    config: Config,
    session: dict[str, Any],
    call: Call,
    method: str,
    data: dict[str, Any],
    *,
    call_scoped: bool = False,
    time_key: str = "time",
) -> dict[str, Any]:
    return {
        "method": f"service.{method}",
        "msg_id": call.next_message_id(call_scoped=call_scoped),
        "ver": "1.0",
        time_key: int(time.time()),
        "origin": 1,
        "uuid": config.device_id,
        "device_model": config.model_id,
        "data": {
            "SessionId": session["session_id"],
            "call_id": call.call_id,
            **data,
        },
    }


def offer(
    config: Config, session: dict[str, Any], call: Call, compact: str
) -> dict[str, Any]:
    ices = session.get("device_ices", [])
    return envelope(
        config,
        session,
        call,
        "SdpOffer",
        {
            "IceUrl": [item.get("iceurl", "") for item in ices],
            "IceUsername": [item.get("username", "") for item in ices],
            "IcePassword": [item.get("password", "") for item in ices],
            "WebrtcSdp": compact,
            "Action": 2,
            "TrickleICE": 0,
            "Timestamp": 0,
            "CodecMode": 1,
            "Quality": 1,
            "EnableSpeaker": False,
            "EnableMic": False,
            "Prepare": 0,
            "dtlsTimeOut": 2000,
            "onlyRelay": 0,
        },
        call_scoped=True,
    )


def candidate(
    config: Config,
    session: dict[str, Any],
    call: Call,
    local: sdp.LocalIceCandidate,
) -> dict[str, Any]:
    return envelope(
        config,
        session,
        call,
        "IceCandidate",
        {
            "WebrtcCandidate": sdp.compact_candidate(local),
            "WebrtcSdpMLineIndex": local.sdp_mline_index,
            "WebrtcSdpMid": local.sdp_mid,
            "nsType": "",
            "type": "candidate",
        },
    )


def switch(
    config: Config, session: dict[str, Any], call: Call
) -> dict[str, Any]:
    # "tme" is the camera's own spelling; it ignores the corrected key.
    return envelope(
        config, session, call, "Switch", {"Action": 0}, time_key="tme"
    )


def close(config: Config, session: dict[str, Any], call: Call) -> dict[str, Any]:
    return envelope(config, session, call, "Close", {})


def nested_dicts(value: Any) -> Iterator[dict[str, Any]]:
    """walk a signalling frame, descending into json carried as strings."""
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from nested_dicts(child)
    elif isinstance(value, list):
        for child in value:
            yield from nested_dicts(child)


def methods(message: Any) -> set[str]:
    return {str(item.get("method", "")) for item in nested_dicts(message)}


def matching_signal(
    message: Any, call_id: str, session_id: str
) -> dict[str, Any] | None:
    """find this call's answer or trickled candidate inside a frame."""
    # the answer reuses the offer's msg_id and carries SessionId but no
    # call_id; device ice events carry call_id. accept either identifier.
    for item in nested_dicts(message):
        method = str(item.get("method", ""))
        if "SdpAnswer" not in method and "IceCandidate" not in method:
            continue
        for data in nested_dicts(item.get("data")):
            if data.get("call_id") == call_id or (
                session_id and data.get("SessionId") == session_id
            ):
                return {"method": method, "data": data}
    return None
