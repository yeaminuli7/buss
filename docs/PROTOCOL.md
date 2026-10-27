# UltraLink / "TranChat" wire protocol — specification

Reconstructed from `com.transsion.intercom` 2.0.4.11. Every claim below cites the
decompiled class that implements it. Executable reference:
[`tools/ultralink_proto.py`](../tools/ultralink_proto.py) (`python3 tools/ultralink_proto.py selftest`).

---

## 1. Transport matrix

The app uses **two independent byte paths** and keeps them in sync by hand.

| Path | Carried by | Established in | Used for |
|---|---|---|---|
| **Beacon channel** ("await") | `com.android.bluetooth` vendor service — `IIntercomManagerService.transact(7/8)`, delivered back in `IIntercomCallback.handleBleData(byte[])` | `BtChatService.initSocketService()` binds the AIDL; the *stack* advertises/scans | control plane: `0xC1`–`0xCC`, `0xD1`, `0xE1`–`0xE4`; also a Bundle channel (`3001`) |
| **Data channel** ("text") | Bluetooth **RFCOMM** (`listenUsingInsecureRfcommWithServiceRecord` / `createInsecureRfcommSocketToServiceRecord`) **or** **L2CAP CoC** (`listenUsingInsecureL2capChannel` / `createInsecureL2capChannel(psm)`) | `x2.c` (await) and `x2.i` (text) | chat text, push-to-talk audio, voice notes, pictures, version exchange |

Both sockets are created with the **insecure** variants: no MITM protection, no
authenticated pairing requirement at the API level.

### 1.1 L2CAP CoC upgrade ("BLE path")

Enabled when system property `ro.tr_ultralink.feature.version > 0` (`y2.k.d`).

1. Listener side calls `listenUsingInsecureL2capChannel()`; the returned PSM is
   remembered (`x2.i.i`, exposed via `x2.i.d()`).
2. It is handed to the peer **out of band**, through the beacon channel, as
   `0xD1` + ASCII decimal PSM (`BtChatService.S((byte)-47, String.valueOf(psm))`).
3. Peer receives it in `IIntercomCallback.handleBleData` → `App.p.n = psm`
   (`x2.n`, transact handler case `-47`).
4. Peer opens `createInsecureL2capChannel(psm)`; the connection type is stored in
   `x2.i.j = socket.getConnectionType()`.

If the property is absent the app never binds the AIDL, never learns a PSM, and
falls back to RFCOMM-only operation.

---

## 2. Channel identifiers

The RFCOMM service UUIDs are **derived from literal strings** with
`java.util.UUID.nameUUIDFromBytes(...)` — i.e. MD5-based name UUIDs (version 3):

| Role | Seed string | Resulting UUID | Service record name |
|---|---|---|---|
| Data ("text") | `tranchat.bt.text.channel` | `a65c79d7-0ef1-3384-b42b-45a29fe94ae9` | `TranChatTextInsecure` |
| Control ("await") | `tranchat.bt.await.channel` | `682ede1c-ed3e-3959-b614-7ba71700e024` | `TranChatAwaitInsecure` |

Consequence: the UUIDs are **deterministic and universal** — every UltraLink
install on every device uses the same two. They are effectively a protocol
identifier, not a secret.

---

## 3. Vendor AIDL (`android.bluetooth.IIntercomManagerService`)

Recovered transaction table from `b/a.java` (client stub) and `x2/n.java`
(callback implementation):

### 3.1 Client → BT stack

| transact | signature | purpose |
|---|---|---|
| 4 | `d(IIntercomCallback)` | register callback |
| 5 | `h(IIntercomCallback)` | unregister callback |
| 6 | `e(int what, Bundle b)` | send key/value data — `intercom_enable` (bool), `intercom_name` (String), `intercom_priority` (int); `what = 1000` |
| 7 | `g(byte opcode, String text)` | send `[opcode][text]` through the beacon (used for `0xD1` PSM) |
| 8 | `f(byte opcode)` | send a bare opcode through the beacon |
| 9 | `c()` | restart the await/advertising service |
| 11 | `a(String)` | set intercom name |
| 12 | `b()` | `getIntercomList()` → `ArrayList<IntercomDevice>` (`b/d.java`: `int a; String b,c,d,e`) |

### 3.2 BT stack → app (`android.bluetooth.IIntercomCallback`)

| onTransact | argument | effect |
|---|---|---|
| 1 | `Bundle` | forwarded to the UI as event `3001` |
| 2 | `int` | call-state change (logged only) |
| 3 | `int` | await-channel state message, posted into the service handler (`1411 CONNECT_FAILED` is ignored during an active call/talk) |
| 4 | `byte[]` | **beacon payload** → opcode dispatch (see §5.2) |
| 5 | `String "MAC####name"` | "peer wants to connect": sets pending device + `setAwaitConnectDeviceType` |

---

## 4. Frame grammar (data channel)

One signed byte of type, then a type-dependent body. Values are given as
unsigned hex with the smali signed value in brackets.

| Opcode | Name | Body | Direction |
|---|---|---|---|
| `0xA1` [-95] | `HEAD_TEXT_MSG` | UTF-8 JSON, **no length prefix** (receiver does `read(buf,0,1000)`) | ↔ |
| `0xA2` [-94] | `HEAD_TALK_STOP` | — | ↔ |
| `0xA5` [-91] | `HEAD_END_CALL` | — | ↔ |
| `0xA9` [-87] | `HEAD_DISCONNECT_CHANNEL` | — | ↔ |
| `0xB1` [-79] | `HEAD_TALK_AUDIO` | `seq:u16be` + 10×encoded frame (codec) **or** 640 B raw PCM (no header) | ↔ |
| `0xB2` [-78] | `HEAD_VOICE_MSG_DATA` | `len:u8` + ≤160 B | ↔ |
| `0xB3` [-77] | `HEAD_VOICE_MSG_END` | up to 6 ASCII digits = duration in ms (unframed) | ↔ |
| `0xB4` [-76] | `HEAD_VERSION_INFO` | `len:u8` + UTF-8 string | ↔ |
| `0xB5` [-75] | `HEAD_END_CALL_REPLY` | — | ↔ |
| `0xB6` [-74] | `HEAD_PICTURE_MSG_DATA` | `len:u8` + ≤160 B | ↔ |
| `0xB7` [-73] | `HEAD_PICTURE_MSG_END` | — | ↔ |
| `0xC1` [-63] | `HEAD_TALK_REQUEST` | optional peer display name, unframed | beacon (+ socket) |
| `0xC2` [-62] | `HEAD_TALK_ACCEPT` | — | |
| `0xC3` [-61] | `HEAD_TALK_REFUSE` | — | |
| `0xC4` [-60] | `HEAD_TALK_REQUEST_TIMEOUT` | — | |
| `0xC5` [-59] | `HEAD_REINIT_CHANNEL` | — | |
| `0xC6` [-58] | `HEAD_CANCEL_TALK_REQUEST` | — | |
| `0xC7` [-57] | `HEAD_CALL_REQUEST` | optional peer display name, unframed | |
| `0xC8` [-56] | `HEAD_CALL_ACCEPT` | — | |
| `0xC9` [-55] | `HEAD_CALL_REFUSE` | — | |
| `0xCA` [-54] | `HEAD_CALL_REQUEST_TIMEOUT` | — | |
| `0xCB` [-53] | `HEAD_CANCEL_CALL_REQUEST` | — | |
| `0xCC` [-52] | `HEAD_CLOSE_BT` | — | beacon |
| `0xD1` [-47] | `HEAD_SEND_PSM` | ASCII decimal L2CAP PSM | beacon |
| `0xE1` [-31] | `FORBID_TALK_NOT_CONTACT` | — | beacon |
| `0xE2` [-30] | `FORBID_TALK_NOT_ALLOWED` | — | beacon |
| `0xE3` [-29] | `FORBID_CALL_NOT_CONTACT` | — | beacon |
| `0xE4` [-28] | `FORBID_CALL_NOT_ALLOWED` | — | beacon |

Notes and traps:

* **`0xA1` has no length.** The boundary is "whatever one `InputStream.read()`
  returned", capped at 1000 B. A sender that writes a text frame in two TCP-ish
  segments, or two frames in one write, breaks the peer. Any reimplementation
  should keep text frames in a single `write()` **and** must treat 1000 B as a
  hard limit (the app logs `text message length is too long, return!` and fails
  the send).
* **`0xC1`/`0xC7` names are unframed** — on the socket they extend to the end of
  the read buffer, on the beacon channel the transport supplies the byte[] length.
* **`0xB3`** is followed by a variable number of ASCII digits (the receiver reads
  at most 6 and applies `\d+`), so it is only self-delimiting because a new
  opcode never parses as a digit.
* File transfers are chunked in `y2.e.C(file, opcode)` into `[op][len:u8][≤160 B]`
  frames; the last chunk may be short, and the transfer always ends with the
  matching `…_END` opcode.
* Text payloads are serialised with **fastjson**, compact (`toJSONString()`), keys
  are lower-case except the stored user blob.

---

## 5. Payload schemas

### 5.1 Chat text (`0xA1`)

```json
{"text":"see you at the gate","user":"{\"deviceId\":\"..\",\"deviceName\":\"..\",\"userInfo\":\"..\"}"}
```

`user` is the verbatim contents of `bt_attribute` row `"userinfo"`
(`BtAttributeDao.USERINFO`, written from the `User` model: `deviceId`,
`deviceName`, `rssi`, `isBTUser`, `applyTime`, `priority`, `user`,
`contactNameWithSuffix`). Because it is copied verbatim into every message, the
peer's stored blob is echoed back to it — an unintentional data-echo loop.

Send result notification (UI event `1113 MSG_BT_SEND_RESPONSE`):

```json
{"success":1,"msgId":12345}      // or "success":0 on failure
```

Voice-note message body (`Message.mContent` = JSON, `Message.mAttach` = file path):

```json
{"AUDIO":4150}                    // duration in ms
```

### 5.2 Beacon payload dispatch (`x2/n`, `handleBleData`)

The same opcodes, but the first byte selects a behaviour keyed to UI events:
`-63→1403`, `-62→1404`, `-61→1405`, `-60→1408`, `-58→1407`, `-57→1413`,
`-56→1414`, `-55→1415`, `-54→1417`, `-53→1416`, `-52→1419`, plus the policy
refusals above. For `0xC1`/`0xC7` the remainder after the opcode is decoded with
`y2.k.d(bytes, len)` to obtain the requester's display name, which falls back to
a localised string when absent.

### 5.3 Version exchange (`0xB4`)

`[0xB4][len][ASCII version]`, e.g. `2.0.4.11`. Received version is only logged
(`HEAD_VERSION_INFO str:`); there is **no compatibility negotiation** — the app
trusts the peer to speak the same protocol.

---

## 6. Session sequences

### 6.1 Full "call" (ringing)

```
A                                                B
│ 0xC7 CALL_REQUEST [+name]  (beacon)  ────────► │  AnswerActivity (full screen, own task)
│                                               │
│ 0xC8 CALL_ACCEPT           (beacon)  ◄──────── │  user accepts
│ 0xD1 PSM                  (beacon)   ────────► │
│                                               │  createInsecureL2capChannel(psm)   [or RFCOMM]
│ socket established (CONNECT_SUC 1517, state 3) │
│ 0xB4 VERSION_INFO          (socket)  ◄───────► │
│             call state → ACTIVE_CALL (3)      │
│ 0xB1 audio packets (seq + 10 frames) ◄───────► │  continuous, full duplex
│             (both sides also start 2002/2003 location updates)
│ 0xA2 TALK_STOP (optional)                     │
│ 0xA5 END_CALL              (socket)  ◄───────► │
│ 0xB5 END_CALL_REPLY        (socket)  ◄───────► │
│ 0xA9 DISCONNECT_CHANNEL               ────────► │  state → IDLE (2)
```

Refusals: `0xC9` (user refused), `0xCA` (timeout), `0xCB` (caller cancelled),
`0xCC` (BT closing); the peer then logs the appropriate
`TYPE_NOT_CONNECTED / RULE_REC` history row.

### 6.2 Push-to-talk ("talk", no ringing)

`0xC1 TALK_REQUEST` → `0xC2 TALK_ACCEPT` | `0xC3 TALK_REFUSE` |
`0xC4 TALK_REQUEST_TIMEOUT` | `0xC6 CANCEL_TALK_REQUEST`; media is half duplex
and the talker releases with `0xA2`. Internally the app upgrades/downgrades
between `ONGOING_CALL` (6), `ONGOING_UPGRADE_CALL` (7),
`INCOMING_UPGRADE_CALL` (8), `TALK_REQUESTING` (10), `INCOMING_REQUEST` (11) and
`ACTIVE_TALK` (12).

### 6.3 Voice note

```
0xB2 [len≤160] … ×N     (chunked OGG/Opus file, 160 B payload per frame)
0xB3 "4150"             (duration ms, unframed ASCII)
```
Recordings shorter than 1000 ms are discarded client-side (`1523` UI event).

### 6.4 Picture

```
0xB6 [len≤160] … ×N
0xB7
```
The receiver appends the chunks to an in-memory `ByteArrayOutputStream` and
persists the file on `0xB7`.

---

## 7. State model

`CallStates` (int stored in `u2.d.r`):

| Value | Name | Meaning |
|---|---|---|
| 0 | `INVALID` | — |
| 1 | `NEW` | service starting |
| 2 | `IDLE` | connected-but-quiet |
| 3 | `ACTIVE_CALL` | full-duplex call |
| 4 | `INCOMING_CALL` | ringing, callee side |
| 6 | `ONGOING_CALL` | call being set up / muted |
| 7 | `ONGOING_UPGRADE_CALL` | call → talk downgrade in progress |
| 8 | `INCOMING_UPGRADE_CALL` | incoming downgrade |
| 10 | `TALK_REQUESTING` | talk request sent |
| 11 | `INCOMING_REQUEST` | talk request received |
| 12 | `ACTIVE_TALK` | half-duplex talking |

Socket state (`x2.i.h`): `0 NONE`, `1 LISTEN`, `2 CONNECTING`, `3 CONNECTED`;
the await channel uses its own 20/21/22/23 set.

---

## 8. Bandwidth

| Mode | Per 200 ms packet | Wire rate | Notes |
|---|---|---|---|
| Lyra 9.2 kbit/s | `0xB1` + 2 B seq + 230 B | ≈ 1.17 kB/s (9.3 kbit/s) | default on most devices |
| Lyra 3.2 kbit/s | `0xB1` + 2 B seq + 80 B | ≈ 415 B/s (3.3 kbit/s) | `App.p.e == 2` |
| Raw PCM fallback | `0xB1` + 640 B every 20 ms | 32 kB/s (256 kbit/s) | no header, untested in the field |

Plus ~5 location updates/minute during calls (`2003`), each a small beacon frame.

---

## 9. Reproduction / interception notes

* Log tags (all prefixed `TranChat-`): `BtBaseChannel`, `BtAwaitChannel`,
  `BtChatService`, `LinkAudioService`, `ConvergedLocationService`, `Codec2Jni`.
  Enable verbose payload dumps with `adb shell setprop log.tag.intercom DEBUG`
  (`y2.e.v()` also returns true on `userdebug`/`eng` builds).
* HCI snoop log captures both RFCOMM and L2CAP traffic; the RFCOMM UUID and the
  PSM are visible at connection setup, which is all a sniffer needs to find the
  byte streams.
* To *emulate* the app you need the beacon channel. Without the Transsion stack,
  replace it with a BLE GATT service (advertise name/priority, characteristic for
  `[opcode][payload]`, characteristic for PSM) and keep the data channel and
  framing exactly as above — `tools/ultralink_proto.py` provides the framing.

---

## 10. Known protocol weaknesses

1. No length on `0xA1` + 1000 B cap → trivial desync/DoS by writing a >1000 B or
   fragmented text frame.
2. No version negotiation despite `0xB4`.
3. No integrity check, no sequence on control frames, no retransmission: a lost
   `0xC8` leaves the caller waiting for the timeout.
4. `0xB1` sequence is 16-bit at 5 packets/s → wraps after ~1.8 h; a long call
   relies on the wrap heuristic (`+32767*200 ms`) to stay in sync.
5. Everything is plaintext, including GPS coordinates (§`docs/SECURITY.md`).
