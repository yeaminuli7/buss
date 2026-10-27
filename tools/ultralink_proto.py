#!/usr/bin/env python3
"""
ultralink_proto.py -- reference model of the UltraLink / TranChat wire protocol.

Target app : com.transsion.intercom ("UltraLink" 2.0.4.11, Transsion/Infinix)
Transport  : Bluetooth Classic RFCOMM (insecure) or BLE L2CAP CoC,
             plus a BLE-advertising "beacon" channel driven by the vendor BT stack.

Everything here was reconstructed from the APK (see docs/PROTOCOL.md for the
class-level evidence).  Nothing in this file is copied from the vendor binary;
it is a clean-room description of the observed on-the-wire behaviour.

Usage
-----
    python3 ultralink_proto.py selftest
    python3 ultralink_proto.py opcodes
    python3 ultralink_proto.py outline            # show the call/talk state machine
    python3 ultralink_proto.py dump capture.bin   # decode a raw channel capture
    python3 ultralink_proto.py uuid               # print the two RFCOMM UUIDs

Capture format for `dump`: the file must start at an opcode boundary of the
*text* channel (the byte stream carried by the RFCOMM / L2CAP socket).
"""

from __future__ import annotations

import hashlib
import json
import struct
import sys
import uuid
from dataclasses import dataclass, field
from typing import Iterator

# --------------------------------------------------------------------------- #
# Opcodes
# --------------------------------------------------------------------------- #
# The protocol uses a single *signed* byte as the frame type.  Values are shown
# as they appear in the smali (`const/16 vX, -95`) next to their unsigned form.

OPCODES: dict[int, str] = {
    # ---- text channel (RFCOMM / L2CAP) --------------------------------------
    0xA1: "HEAD_TEXT_MSG",             # UTF-8 JSON, length implied by the read() boundary, <= 1000 B
    0xA2: "HEAD_TALK_STOP",            # push-to-talk released
    0xA5: "HEAD_END_CALL",             # peer hangs up            (reply: 0xB5)
    0xA9: "HEAD_DISCONNECT_CHANNEL",   # tear the socket down
    0xB1: "HEAD_TALK_AUDIO",           # [seq:u16be][10 x codec frame]  (codec mode)
                                       # [640 B raw PCM]                (raw PCM mode)
    0xB2: "HEAD_VOICE_MSG_DATA",       # [len:u8][<=160 B chunk]
    0xB3: "HEAD_VOICE_MSG_END",        # ASCII duration in ms, right after the byte
    0xB4: "HEAD_VERSION_INFO",         # [len:u8][UTF-8 version string]
    0xB5: "HEAD_END_CALL_REPLY",
    0xB6: "HEAD_PICTURE_MSG_DATA",     # [len:u8][<=160 B chunk]
    0xB7: "HEAD_PICTURE_MSG_END",
    # ---- control plane (sent on both channels) ------------------------------
    0xC1: "HEAD_TALK_REQUEST",         # [+ peer display name, optional]
    0xC2: "HEAD_TALK_ACCEPT",
    0xC3: "HEAD_TALK_REFUSE",
    0xC4: "HEAD_TALK_REQUEST_TIMEOUT",
    0xC5: "HEAD_REINIT_CHANNEL",
    0xC6: "HEAD_CANCEL_TALK_REQUEST",
    0xC7: "HEAD_CALL_REQUEST",         # [+ peer display name, optional]
    0xC8: "HEAD_CALL_ACCEPT",
    0xC9: "HEAD_CALL_REFUSE",
    0xCA: "HEAD_CALL_REQUEST_TIMEOUT",
    0xCB: "HEAD_CANCEL_CALL_REQUEST",
    0xCC: "HEAD_CLOSE_BT",
    0xD1: "HEAD_SEND_PSM",             # ASCII L2CAP PSM, used to open the BLE CoC
    0xE1: "HEAD_FORBID_TALK_NOT_CONTACT",
    0xE2: "HEAD_FORBID_TALK_NOT_ALLOWED",
    0xE3: "HEAD_FORBID_CALL_NOT_CONTACT",
    0xE4: "HEAD_FORBID_CALL_NOT_ALLOWED",
}

BY_NAME = {v: k for k, v in OPCODES.items()}

# Opcodes that are followed by a 1-byte length + that many payload bytes.
LEN8_PAYLOAD = {0xB2, 0xB4, 0xB6}
# End-of-transfer opcodes.  0xB3 additionally carries the note duration as up to
# six *unframed* ASCII digits (the receiver does read(buf, 0, 6)); 0xB7 is bare.
END_OPCODES = {0xB3: "duration_ms", 0xB7: ""}
# Audio packets: in codec mode the 2 bytes after 0xB1 are a *sequence number*
# (wrapping at 32767, one unit = 200 ms of audio), not a length.  The payload is
# 10 encoded frames (10 * 23 B = 230 B, or 10 * 8 B = 80 B).  In the raw-PCM
# fallback there is no header at all: exactly 640 B of PCM-16 follow.
AUDIO_SEQ_MOD = 32767
FRAMES_PER_PACKET = 10

CHUNK = 160            # file-chunk payload size used for voice notes and pictures
CODEC_HOP_SAMPLES = 320   # 20 ms @ 16 kHz
CODEC_HOP_BYTES = 640     # 320 samples * 16 bit
CODEC_FRAME_BYTES = {9200: 23, 3200: 8}   # bitrate -> bytes per 20 ms hop
# 10 hops per packet  ->  200 ms per packet, 32767 * 200 ms ~= 1.8 h before wrap

# --------------------------------------------------------------------------- #
# Channel identifiers
# --------------------------------------------------------------------------- #
# Generated in x2.i / x2.c with UUID.nameUUIDFromBytes(...) ->  MD5 name UUIDs
# (version 3, IETF variant).
UUID_SEEDS = {
    "text": "tranchat.bt.text.channel",
    "await": "tranchat.bt.await.channel",
}

SERVICE_RECORD = {"text": "TranChatTextInsecure", "await": "TranChatAwaitInsecure"}


def name_uuid(seed: str) -> uuid.UUID:
    """Equivalent of java.util.UUID.nameUUIDFromBytes(seed.getBytes(UTF_8))."""
    d = bytearray(hashlib.md5(seed.encode()).digest())
    d[6] = (d[6] & 0x0F) | 0x30   # version 3
    d[8] = (d[8] & 0x3F) | 0x80   # IETF variant
    return uuid.UUID(bytes=bytes(d))


CHANNEL_UUID = {k: name_uuid(v) for k, v in UUID_SEEDS.items()}

# com.android.bluetooth vendor extension used for discovery / beacon messaging.
AIDL_INTERFACE = "android.bluetooth.IIntercomManagerService"
AIDL_CALLBACK = "android.bluetooth.IIntercomCallback"
AIDL_TX = {
    4: "registerCallback(IIntercomCallback)",
    5: "unregisterCallback(IIntercomCallback)",
    6: "sendData(int, Bundle)",        # intercom_enable / intercom_name / intercom_priority
    7: "sendDataWithText(byte opcode, String text)",
    8: "sendData(byte opcode)",
    9: "restartAwaitChannel()",
    11: "setIntercomName(String)",
    12: "getIntercomList() -> ArrayList<IntercomDevice>",
}
AIDL_CB = {
    1: "onReceiveData(Bundle)",
    2: "onCallStateChange(int)",
    3: "onAwaitConnectStateMsg(int)",
    4: "handleBleData(byte[])",
    5: "onReportConnectDevice(String mac + '####' + name)",
}

# Call/talk state machine (com.transsion.intercom.model.CallStates)
STATES = {
    0: "INVALID", 1: "NEW", 2: "IDLE", 3: "ACTIVE_CALL", 4: "INCOMING_CALL",
    6: "ONGOING_CALL", 7: "ONGOING_UPGRADE_CALL", 8: "INCOMING_UPGRADE_CALL",
    10: "TALK_REQUESTING", 11: "INCOMING_REQUEST", 12: "ACTIVE_TALK",
}


def op_name(b: int) -> str:
    return OPCODES.get(b & 0xFF, f"UNKNOWN_0x{b & 0xFF:02X}")


# --------------------------------------------------------------------------- #
# Frame builders
# --------------------------------------------------------------------------- #
def frame_text(obj: str | dict) -> bytes:
    """0xA1 + UTF-8 JSON (must fit in 1000 bytes; the receiver has no length field)."""
    if isinstance(obj, dict):
        obj = json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
    raw = obj.encode()
    if len(raw) > 1000:
        raise ValueError(f"text frame is {len(raw)} B, limit is 1000 B")
    return bytes([0xA1]) + raw


def frame_control(op: int, text: str | None = None) -> bytes:
    """Control opcode, optionally followed by a display name (0xC1 / 0xC7)."""
    out = bytes([op])
    if text is not None:
        out += text.encode()
    return out


def frame_psm(psm: int) -> bytes:
    """0xD1 + ASCII PSM, delivered through the BLE beacon channel."""
    return bytes([0xD1]) + str(psm).encode()


def frame_audio(encoded: bytes, seq: int, codec_mode: bool = True) -> bytes:
    """0xB1 + [seq:u16be] + 10 encoded frames (codec mode) or raw 640 B PCM."""
    if codec_mode:
        return bytes([0xB1]) + struct.pack(">H", seq % (AUDIO_SEQ_MOD + 1)) + encoded
    if len(encoded) != CODEC_HOP_BYTES:
        raise ValueError(f"raw PCM frame must be {CODEC_HOP_BYTES} B")
    return bytes([0xB1]) + encoded


def frame_file(data: bytes, op_data: int = 0xB2, op_end: int = 0xB3,
               trailer: bytes = b"") -> list[bytes]:
    """Chunk a voice note (0xB2/0xB3) or a picture (0xB6/0xB7) into 160 B frames."""
    frames = []
    for i in range(0, len(data), CHUNK):
        chunk = data[i:i + CHUNK]
        frames.append(bytes([op_data, len(chunk)]) + chunk)
    frames.append(bytes([op_end]) + trailer)
    return frames


def text_message(text: str, user_info: str) -> dict:
    """Payload of a 0xA1 chat message."""
    return {"text": text, "user": user_info}


def ack(msg_id: int) -> dict:
    return {"success": 1, "msgId": msg_id}


# --------------------------------------------------------------------------- #
# Parser
# --------------------------------------------------------------------------- #
@dataclass
class Event:
    op: int
    name: str
    payload: bytes = b""
    notes: str = ""
    extra: dict = field(default_factory=dict)

    def __str__(self) -> str:
        p = self.payload
        if self.op == 0xA1:
            body = p.decode("utf-8", "replace")
        elif self.op in (0xB2, 0xB6, 0xB1):
            body = f"{len(p)} B {p[:8].hex()}{'...' if len(p) > 8 else ''}"
        elif p:
            body = p.decode("utf-8", "replace")
        else:
            body = "-"
        tail = f"   ({self.notes})" if self.notes else ""
        return f"0x{self.op:02X} {self.name:<30} {body}{tail}"


def parse(data: bytes, *, frame_size: int = 23, frames_per_packet: int = FRAMES_PER_PACKET
          ) -> list[Event]:
    """Walk a captured text-channel byte stream and decode frames.

    NOTE: 0xA1 carries no length.  In the original app the message boundary is
    simply 'whatever one InputStream.read() returned', so a capture has to be
    re-framed by hand when a text frame appears mid-stream.  We do the pragmatic
    thing: a 0xA1 payload runs until the next byte that is a known opcode AND
    is followed by a structurally valid frame (or end of buffer).
    """
    ev: list[Event] = []
    i, n = 0, len(data)
    while i < n:
        op = data[i]
        i += 1
        if op == 0xA1:
            start = i
            # find the longest prefix that still parses as JSON, else fall back
            j = n
            while j > start:
                try:
                    json.loads(data[start:j].decode("utf-8"))
                    break
                except Exception:
                    j -= 1
            if j > start:
                ev.append(Event(op, op_name(op), data[start:j]))
                i = j
            else:
                ev.append(Event(op, op_name(op), data[start:n], "unterminated JSON"))
                i = n
        elif op == 0xB1:
            # codec mode: seq + frames_per_packet * frame_size (frame size depends
            # on the negotiated bitrate, so the caller tells us)
            seq = struct.unpack(">H", data[i:i + 2])[0]
            i += 2
            want = frame_size * frames_per_packet
            ev.append(Event(op, op_name(op), data[i:i + want],
                            f"seq={seq} frames={frames_per_packet} fsz={frame_size}"))
            i += want
        elif op in LEN8_PAYLOAD:
            want = data[i]
            i += 1
            ev.append(Event(op, op_name(op), data[i:i + want]))
            i += want
        elif op == 0xB3:
            # up to six ASCII digits, no length prefix
            j = i
            while j < n and j - i < 6 and chr(data[j]).isdigit():
                j += 1
            ev.append(Event(op, op_name(op), data[i:j], "duration_ms"))
            i = j
        elif op == 0xB7:
            ev.append(Event(op, op_name(op)))
        elif op == 0xD1:
            # ASCII PSM fills the remainder of the beacon payload
            ev.append(Event(op, op_name(op), data[i:n], "ascii psm"))
            i = n
        elif op in (0xC1, 0xC7):
            # Optional trailing display name with no length prefix.  On the BLE
            # beacon channel the transport supplies the byte[] length, so this is
            # unambiguous there; on the socket channel we consume to end of buffer.
            ev.append(Event(op, op_name(op), data[i:n], "name, unframed"))
            i = n
        else:
            ev.append(Event(op, op_name(op)))
    return ev


# --------------------------------------------------------------------------- #
# Nominal audio / file budget
# --------------------------------------------------------------------------- #
def bandwidth_report() -> str:
    lines = ["UltraLink audio budget (16 kHz mono PCM16, 20 ms hop, 10 hops/packet):"]
    for br, nbytes in CODEC_FRAME_BYTES.items():
        per_packet = 3 + FRAMES_PER_PACKET * nbytes      # opcode + seq + frames
        lines.append(
            f"  {br:>5} bit/s  ->  {FRAMES_PER_PACKET}x{nbytes:>2} B + 3 B = "
            f"{per_packet:>4} B / 200 ms  = {per_packet * 5:>5} B/s "
            f"({per_packet * 5 * 8 / 1000:.1f} kbit/s on air)"
        )
    lines.append(f"  raw PCM fallback: 641 B / 20 ms = 32050 B/s (256 kbit/s), no header")
    return "\n".join(lines)


def outline() -> str:
    return """\
Call/talk flow (observed on both channels)

  A (caller)                                    B (callee)
  ---------                                     ----------
  [await ch] 0xC7 CALL_REQUEST + name   --->
                                             UI: AnswerActivity (full screen)
                                             [await ch] 0xC8 CALL_ACCEPT   <---
  [await ch] 0xD1 PSM (BLE path)        --->
  L2CAP CoC connect to PSM   (or RFCOMM connect to the text UUID)
  [text ch]  0xB4 VERSION_INFO          <-->   capability/version exchange
  state ACTIVE_CALL (3)
  [text ch]  0xB1 audio frames          <-->   push-to-talk media
  [text ch]  0xA2 TALK_STOP             --->   half-duplex release
  [text ch]  0xA5 END_CALL              <-->   hang up; 0xB5 confirms
  [text ch]  0xA9 DISCONNECT_CHANNEL    --->   socket teardown, state IDLE (2)

  Refusals / timeouts: 0xC9 refuse, 0xCA timeout, 0xCB cancel.
  Policy refusals:     0xE1..0xE4 (peer not a contact / not allowed).
  Talk-only variant uses 0xC1/0xC2/0xC3/0xC4/0xC6 (walkie-talkie, no ringing).
"""


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def _selftest() -> int:
    ok = True

    def check(cond, what):
        nonlocal ok
        print(("  ok   " if cond else "  FAIL ") + what)
        ok = ok and bool(cond)

    print("UUID derivation")
    check(str(CHANNEL_UUID["text"]) == "a65c79d7-0ef1-3384-b42b-45a29fe94ae9",
          f"text channel UUID = {CHANNEL_UUID['text']}")
    check(str(CHANNEL_UUID["await"]) == "682ede1c-ed3e-3959-b614-7ba71700e024",
          f"await channel UUID = {CHANNEL_UUID['await']}")

    print("round-trip")
    msg = frame_text(text_message("hello", '{"deviceName":"Pixel"}'))
    check(msg[0] == 0xA1 and len(msg) < 1001, "text frame builds")
    ev = parse(msg)
    check(len(ev) == 1 and ev[0].op == 0xA1, "text frame parses")
    check(json.loads(ev[0].payload)["text"] == "hello", "text payload decodes")

    blob = frame_audio(b"\x11" * 230, seq=7)
    ev = parse(blob)
    check(len(ev) == 1 and ev[0].payload == b"\x11" * 230, "audio packet round-trips")
    check("seq=7" in str(ev[0]), "audio packet carries the sequence number")
    check(len(frame_audio(b"\x00" * 640, 0, codec_mode=False)) == 641,
          "raw PCM packet is 641 B (opcode + 640)")

    frames = frame_file(b"A" * 400, 0xB2, 0xB3, b"1234")
    check(len(frames) == 4, f"400 B voice note -> {len(frames)} frames (3 data + end)")
    check(frames[-1] == bytes([0xB3]) + b"1234", "voice end carries the duration")
    ev = parse(b"".join(frames))
    check(len(ev) == 4 and ev[-1].payload == b"1234", "voice stream parses")

    ctrl = parse(frame_control(0xC7, "Alice"))
    check(ctrl[0].payload == b"Alice", "CALL_REQUEST carries the display name")
    psm = parse(frame_psm(4097))
    check(psm[0].payload == b"4097", "PSM beacon frame parses")

    print("budget")
    print(bandwidth_report())
    return 0 if ok else 1


def main(argv: list[str]) -> int:
    cmd = argv[1] if len(argv) > 1 else "help"
    if cmd == "selftest":
        return _selftest()
    if cmd == "opcodes":
        for v, n in sorted(OPCODES.items()):
            print(f"  0x{v:02X}  {v - 256 if v > 127 else v:>4}  {n}")
        return 0
    if cmd == "outline":
        print(outline())
        print(bandwidth_report())
        return 0
    if cmd == "uuid":
        for k, u in CHANNEL_UUID.items():
            print(f"  {k:<6} {u}   service record: {SERVICE_RECORD[k]}")
        print(f"  AIDL   {AIDL_INTERFACE}")
        print(f"  AIDL   {AIDL_CALLBACK}")
        return 0
    if cmd == "dump" and len(argv) > 2:
        with open(argv[2], "rb") as fh:
            data = fh.read()
        for e in parse(data):
            print(e)
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
