"""place one webrtc call and mux the camera's a/v to the sink."""

import asyncio
import fractions
import json
import signal
import time
from contextlib import suppress
from typing import Any

import aiohttp
import av
from aiortc import (
    MediaStreamTrack,
    RTCBundlePolicy,
    RTCConfiguration,
    RTCPeerConnection,
    RTCSessionDescription,
)
from aiortc.mediastreams import MediaStreamError
from aiortc.rtp import RtcpRrPacket

from . import cloud, rtc, sdp, signalling
from .cloud import Config
from .env import log

ANSWER_TIMEOUT = 30
# mpeg-ts for every sink, because it repeats its tables forever and so can
# be joined at any moment. mp4 would need an initialisation segment that
# only a reader present from the first byte ever sees.
MUXER = "mpegts"
# hand each packet to the sink as it is muxed rather than pooling it in
# the io buffer, so a datagram leaves as soon as there is one to send.
MUX = {"flush_packets": "1"}
# the clocks rtp dates each kind in, which the muxer has to be told.
BASE = {
    "video": fractions.Fraction(1, 90000),
    "audio": fractions.Fraction(1, rtc.AAC.clockRate),
}
# packets dated inside one tick reach the muxer a single dts apart, which
# a player reads as a frame lasting no time at all.
TICK = {"video": 90000 // 30, "audio": 1}


def aligned(target: str) -> str:
    """size udp datagrams in whole transport packets.

    ffmpeg fills a datagram to 1472 bytes, which is seven 188-byte packets
    and a fragment of an eighth. a player that is handed the fragment
    discards it and the head of the next datagram with it, which vlc
    reports as a continuity error a hundred times a second.
    """
    if not target.startswith("udp://") or "pkt_size=" in target:
        return target
    return f"{target}{'&' if '?' in target else '?'}pkt_size={7 * 188}"


class Timed(MediaStreamTrack):
    """a track dated by this machine's clock rather than the camera's.

    aiortc hands on the camera's rtp timing untouched: each track begins at
    its own first packet, and this camera's video clock runs some 3.5% fast,
    so video gains about two minutes on audio every hour. mpeg-ts carries
    timestamps as it is given them, and a player joining an hour-old stream
    is otherwise handed tracks minutes apart and shows nothing.
    """

    def __init__(self, track: MediaStreamTrack, origin: float) -> None:
        super().__init__()
        self.kind = track.kind
        self.track = track
        self.origin = origin
        self.shift: int | None = None
        self.last = -TICK[self.kind]

    async def recv(self) -> Any:
        frame = await self.track.recv()
        now = round((time.monotonic() - self.origin) / frame.time_base)
        if self.shift is None:
            self.shift = now - frame.pts
        # video is dated by arrival, the one clock here that keeps time.
        # audio arrives true, and its sample cadence has to stay unbroken
        # for a decoder, so it is moved bodily onto the same origin.
        stamp = now if self.kind == "video" else frame.pts + self.shift
        frame.dts = frame.pts = self.last = max(
            self.last + TICK[self.kind], stamp
        )
        return frame


class Remux:
    """the container the camera's own packets are written into.

    nothing is decoded and nothing is re-encoded: the access units aiortc
    has already reassembled are muxed as they arrive. that costs almost no
    cpu, and spares the picture the seconds an encoder spends looking ahead
    of it before letting any of it go.
    """

    def __init__(self, target: str) -> None:
        self.container = av.open(
            aligned(target), "w", format=MUXER, options=MUX
        )
        self.streams: dict[Any, Any] = {}
        self.pumps: list[asyncio.Task[None]] = []

    def add(self, track: Any) -> None:
        """declare a track, which every one must be before the first packet."""
        self.streams[track] = (
            self.video() if track.kind == "video" else self.audio()
        )

    def video(self) -> Any:
        # a mux stream builds no codec context at all, so the muxer reads
        # the camera's parameter sets out of the stream where they belong.
        return self.container.add_mux_stream("h264", time_base=BASE["video"])

    def audio(self) -> Any:
        # aac has to be declared the long way: the muxer can only frame it
        # once it has been handed the config the camera announced in sdp.
        stream = self.container.add_stream("aac")
        stream.codec_context.sample_rate = rtc.AAC.clockRate
        stream.codec_context.layout = "mono"
        stream.codec_context.extradata = bytes.fromhex(
            str(rtc.AAC.parameters["config"])
        )
        stream.time_base = BASE["audio"]
        return stream

    async def start(self) -> None:
        self.pumps = [
            asyncio.create_task(self.pump(track, stream))
            for track, stream in self.streams.items()
        ]

    async def pump(self, track: Any, stream: Any) -> None:
        with suppress(MediaStreamError):
            while True:
                packet = await track.recv()
                packet.stream = stream
                self.container.mux(packet)

    async def stop(self) -> None:
        for pump in self.pumps:
            pump.cancel()
        await asyncio.gather(*self.pumps, return_exceptions=True)
        self.container.close()


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
    sink = Remux(target)
    origin = time.monotonic()
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
        sink.add(Timed(track, origin))
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
