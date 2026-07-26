"""place one webrtc call and mux the camera's a/v into fragmented mp4."""

import asyncio
import json
import signal
import time
from contextlib import suppress
from typing import Any

import aiohttp
from aiortc import (
    RTCBundlePolicy,
    RTCConfiguration,
    RTCPeerConnection,
    RTCSessionDescription,
)
from aiortc.contrib.media import MediaRecorder
from aiortc.rtp import RtcpRrPacket

from . import cloud, rtc, sdp, signalling
from .cloud import Config
from .env import log

# fragmenting is what makes the mp4 a stream: no trailing index to wait for,
# so the writer never has to seek back.
FRAGMENTED = {"movflags": "frag_keyframe+empty_moov+default_base_moof"}
# a pipe or a file has one reader, present from the first byte, so it can be
# given the mp4 header once. a network sink is joined whenever the consumer
# feels like it, and mp4 has no way to catch such a reader up -- mpeg-ts
# repeats its tables forever, so anyone can tune in at the next keyframe.
JOINABLE = ("udp", "tcp", "srt", "http", "https")
ANSWER_TIMEOUT = 30


def container(target: str) -> tuple[str, dict[str, str]]:
    """the muxer that suits how this sink will be read."""
    scheme = target.partition("://")[0] if "://" in target else ""
    return ("mpegts", {}) if scheme in JOINABLE else ("mp4", FRAGMENTED)


async def stream(config: Config, target: str) -> None:
    """run until the camera, the network, or a signal ends the call."""
    rtc.patch()
    async with aiohttp.ClientSession(
        timeout=aiohttp.ClientTimeout(total=30),
        skip_auto_headers={"Accept", "Accept-Encoding", "User-Agent"},
    ) as http:
        log("connecting to Nooie signalling")
        async with http.ws_connect(
            cloud.WS_URL,
            headers={
                "uid": config.uid,
                "appid": cloud.APP_ID,
                "api_token": config.api_token,
                "phone_code": config.phone_code,
                "Origin": signalling.origin(cloud.WS_URL),
            },
            heartbeat=20,
        ) as websocket:
            session = await cloud.create_session(http, config)
            await place_call(config, session, websocket, target)


async def place_call(
    config: Config,
    session: dict[str, Any],
    websocket: aiohttp.ClientWebSocketResponse,
    target: str,
) -> None:
    call = signalling.Call()
    peer = RTCPeerConnection(
        RTCConfiguration(
            iceServers=cloud.ice_servers(session),
            bundlePolicy=RTCBundlePolicy.MAX_BUNDLE,
        )
    )
    muxer, options = container(target)
    sink = MediaRecorder(target, format=muxer, options=options)
    started: asyncio.Task[None] | None = None
    connected = asyncio.Event()
    stopped = asyncio.Event()
    loop = asyncio.get_running_loop()
    for number in (signal.SIGINT, signal.SIGTERM):
        # unwind rather than die, so the container is flushed and closed.
        loop.add_signal_handler(number, stopped.set)

    async def open_sink() -> None:
        await asyncio.sleep(0.5)  # let the second track arrive first
        await sink.start()

    @peer.on("track")
    def on_track(track: Any) -> None:
        nonlocal started
        log(f"receiving {track.kind}")
        sink.addTrack(track)
        started = started or asyncio.create_task(open_sink())

    @peer.on("connectionstatechange")
    async def on_state_change() -> None:
        log(f"peer {peer.connectionState}")
        if peer.connectionState == "connected":
            connected.set()
        elif peer.connectionState in ("failed", "closed"):
            stopped.set()

    async def send(frame: dict[str, Any]) -> None:
        await websocket.send_json(frame, dumps=signalling.dumps)

    try:
        rtc.receive_only(peer)
        await peer.setLocalDescription(await peer.createOffer())
        offer = peer.localDescription
        if offer is None:
            raise RuntimeError("aiortc did not produce a local description")
        await send(
            signalling.offer(config, session, call, sdp.compact_offer(offer.sdp))
        )
        for local in sdp.local_candidates(offer.sdp):
            await send(signalling.candidate(config, session, call, local))
        log("offer sent; waiting for the camera")

        deadline = time.monotonic() + ANSWER_TIMEOUT
        while not connected.is_set() and time.monotonic() < deadline:
            message = await receive(websocket, deadline - time.monotonic())
            if message is False:
                raise RuntimeError("signalling closed during the handshake")
            found = signalling.matching_signal(
                message, call.call_id, session["session_id"]
            )
            if found is None:
                continue
            data = found["data"]
            if "IceCandidate" in found["method"]:
                candidate = sdp.remote_candidate(data)
                if candidate is not None:
                    await peer.addIceCandidate(candidate)
                continue
            ret = int(data.get("Ret", 0))
            if ret != 0:
                raise RuntimeError(f"camera rejected the call with Ret={ret}")
            if data.get("WebrtcSdp"):
                await peer.setRemoteDescription(
                    RTCSessionDescription(
                        sdp=sdp.expand_answer(str(data["WebrtcSdp"])),
                        type="answer",
                    )
                )
                log("camera answered")
                await asyncio.wait_for(connected.wait(), timeout=10)
        if not connected.is_set():
            raise RuntimeError(
                f"no usable answer within {ANSWER_TIMEOUT} seconds"
            )

        await send(signalling.switch(config, session, call))
        await receive(websocket, 2)
        await request_keyframe(peer)
        log(f"streaming to {target}")
        while not stopped.is_set():
            message = await receive(websocket, 1)
            if message is False:
                log("signalling closed")
                break
            if message and any(
                "SwitchResp" in method for method in signalling.methods(message)
            ):
                await request_keyframe(peer)
    finally:
        # always release the session; the camera's connection pool is small
        # and half-open calls linger in it.
        if not websocket.closed:
            with suppress(aiohttp.ClientError, ConnectionError):
                await send(signalling.close(config, session, call))
        if started is not None:
            await started
        # a reader that quit first leaves nothing to flush into.
        with suppress(OSError):
            await sink.stop()
        await peer.close()


async def receive(
    websocket: aiohttp.ClientWebSocketResponse, timeout: float
) -> Any:
    """the next decoded frame, None on timeout or noise, False once closed."""
    try:
        async with asyncio.timeout(max(0.1, timeout)):
            message = await websocket.receive()
    except TimeoutError:
        return None
    if message.type is aiohttp.WSMsgType.TEXT:
        try:
            return json.loads(message.data)
        except json.JSONDecodeError:
            return None
    if message.type in {
        aiohttp.WSMsgType.CLOSED,
        aiohttp.WSMsgType.CLOSE,
        aiohttp.WSMsgType.ERROR,
    }:
        return False
    return None


async def request_keyframe(peer: RTCPeerConnection) -> None:
    """the camera only starts sending video once it is asked to."""
    if peer.remoteDescription is None:
        return
    ssrc = sdp.video_ssrc(peer.remoteDescription.sdp)
    if ssrc is None:
        return
    for transceiver in peer.getTransceivers():
        if transceiver.kind == "video":
            await transceiver.receiver._send_rtcp(
                RtcpRrPacket(ssrc=transceiver.sender._ssrc, reports=[])
            )
            await transceiver.receiver._send_rtcp_pli(ssrc)
