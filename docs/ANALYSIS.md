# UltraLink (`com.transsion.intercom`) 2.0.4.11 — full reverse-engineering analysis

> Scope: static analysis of `UltraLink_2.0.4.11.apk` (20,279,973 B, sha256
> `15c78a6e0df61d89f0c3b5ab8f5953f2182128dce6c38cdbe19ba3a6f3b153fd`).
> Everything below was derived from the artifact itself; no live device, no
> vendor source. Statements that are inference are marked **[inferred]**.

---

## 1. Executive summary

UltraLink is **Transsion/Infinix's preinstalled offline "walkie-talkie" app** — a
Bluetooth peer-to-peer messenger and half-duplex voice-call client, shipped as a
**platform-privileged system app** and signed with the **public AOSP test key**.

At a glance:

| Question | Answer |
|---|---|
| Network | **None.** Zero URLs, zero sockets to the internet, no HTTP stack in the DEX. |
| Transport | Bluetooth Classic **RFCOMM** (insecure) *or* **BLE L2CAP CoC**, plus a vendor BLE-advertising "beacon" channel. |
| Voice | **Google Lyra V2** neural speech codec (TFLite) at 3.2 / 9.2 kbit/s, 16 kHz mono, 20 ms hops. |
| Messaging | Push-to-talk (hold to talk) **and** full-duplex calls, text chat (JSON), voice notes (OGG/Opus, chunked over BT), pictures (chunked over BT). |
| Discovery | Delegated to the **vendor Bluetooth stack** via a private AIDL (`android.bluetooth.IIntercomManagerService`); the app never consumes scan results itself (no `ACTION_FOUND` receiver). |
| Identity | `persist.bluetooth.mwc.name` + `intercom_name`/`intercom_priority` injected into `com.android.bluetooth`. |
| Storage | Plain SQLite (`bt_friend`, `bt_chat_list`, `bt_chat_history`, `bt_attribute`), plain JSON, unencrypted media. |
| Crypto | **None at the application layer.** No `Cipher`, no `MessageDigest`, no key material anywhere in app code. |
| Privilege | `BLUETOOTH_PRIVILEGED`, `TETHER_PRIVILEGED`, `WRITE_SECURE_SETTINGS`, `MODIFY_PHONE_STATE`, `INTERACT_ACROSS_USERS_FULL`, `STATUS_BAR`, `LOCAL_MAC_ADDRESS` … 33 permissions in total. |
| Packaging | Single 3.8 MB `classes.dex`, arm64-only native libs (9.2 MB), 156 locale configurations, R8-obfuscated app logic. |

The interesting engineering is not the UI — it is that a 3.2 kbit/s neural codec
makes a **Bluetooth walkie-talkie that works without any network**, and that the
whole discovery/handshake path is implemented **inside the phone's Bluetooth
stack**, not in the app.

---

## 2. Identity, provenance and signing

| Property | Value |
|---|---|
| Package | `com.transsion.intercom` |
| Label | UltraLink (`@7F11001D`) |
| versionName / Code | `2.0.4.11` / `20004011` |
| minSdk / targetSdk / compileSdk | 33 / 35 / 36 |
| ABI payload | `arm64-v8a` only |
| Vendor branding | `meta-data brand=infinix`, `tran_widgets 16.3.0.9-alpha11`, `islandSDKCode 200020022` |
| Host integrations | `com.transsion.launcher3`, `com.android.systemui`, `com.transsion.atomiccore`, `com.transsion.atomicbrain` (declared in `<queries>`) |
| Signature | v1 + v2 + v3, RSA-2048, `CN=Android, O=Android, android@android.com`, serial `0x936EACBE07F201DF`, valid 2008-02-29 → 2035-07-17 |
| Signer SHA-256 | `a40da80a59d170caa950cf15c18c454d47a39b26989d8b640ecd745ba71bf5dc` |
| Build fingerprint | Kotlin 1.9.0 · AGP 8.6.1 · Gradle 8.9 · git revision `1bfd67dfd999c1163614567ac020b1dc7cd5cdcd` |

**The signing key is the well-known AOSP test key** (`android@android.com`,
`e=3`). Anybody can forge this certificate; it proves nothing about authorship.
On a production Transsion ROM that is harmless (the OTA/system partition is
verified elsewhere, and the private platform key is what grants privileged
permissions), but it means the APK itself is **not a trustworthy provenance
anchor**, and any resign of it with the same key is indistinguishable at the
certificate level. This is typical for platform apps built from AOSP-derived
trees, but it is worth calling out: *do not* treat "signed with the Android
platform key" here as evidence that a given APK is genuine.

Build leftovers that leak the vendor's toolchain:
`META-INF/version-control-info.textproto` (AGP VCS info, git SHA),
`kotlin-tooling-metadata.json`, `DebugProbesKt.bin` (kotlinx-coroutines debug
probes still bundled), `assets/dexopt/baseline.prof{,.m}`.

---

## 3. Feature set (reconstructed)

1. **Contact list of nearby UltraLink users** — discovered over BLE advertising by
   the BT stack; each peer becomes a `Friend` with `deviceId` (BT MAC), `name`,
   `rssi`, `priority`, `isBTUser`.
2. **Text chat** — JSON messages over the socket channel, persisted locally.
3. **Push-to-talk ("talk")** — half duplex: hold to talk, `0xA2` releases; no
   ringing, the peer just starts receiving.
4. **Full-duplex "call"** — ringing with a full-screen `AnswerActivity` on the
   peer, accept/refuse, then continuous audio.
5. **Voice notes** — recorded as OGG/Opus, chunked over BT, playable in-line.
6. **Pictures** — chunked over BT, `ImagePreviewActivity` viewer.
7. **Distance / proximity** — during a call both sides push GPS coordinates
   (`ConvergedLocationService`, 5 s polling) to show how far apart the pair is.
8. **Dynamic Island / Atomic Card integration** — live call state in the island,
   atomic-card provider for the launcher's "atomic" widgets.
9. **Bluetooth speaker / audio routing control, proximity screen-off, vibration,
   ringtone, call-audio focus** (`AudioManager.setMode(MODE_IN_COMMUNICATION)`,
   SCO teardown, `CommunicationDevice` tracking).

---

## 4. Packaging budget

| Area | Uncompressed | Entries |
|---|---|---|
| `lib/arm64-v8a` | 9,213,784 B | 4 |
| `assets/` | 3,954,519 B | 28 |
| `res/` | 1,266,893 B | 1,381 |
| `classes.dex` | 3,812,816 B | 1 |
| `resources.arsc` | 2,588,680 B | 1 |
| `META-INF/` | 286,483 B | 69 |
| **Total** | **21,175,606 B** | **1,494** |

Native libraries:

* `libtensorflowlite.so` (4.40 MB) — TFLite 2.11-era runtime, C++ symbols kept.
* `libjni_codec_transsion.so` (3.78 MB) — the codec bridge; links `libtensorflowlite.so`.
* `libc++_shared.so` (1.03 MB).
* `libsdk.so` — thin wrapper, only exports `_Z4demov` (`void demo()`).

Only `arm64-v8a` is shipped: this app is **never** going to run on a 32-bit or
x86 emulator without rebuilding the codec stack.

Assets worth noting: the three Lyra models (`soundstream_encoder.tflite` 1.78 MB,
`lyragan.tflite` 1.48 MB, `quantizer.tflite` 329 KB), ten Lottie animations
(`answer.json`, `cancel_ripples.json`, `dynamic_island_unanswered.json`,
`loading_*`, `RU.json` = `player_visualization`), `tossymbol.ttf` (Transsion
icon font) and `assets/table/*.sql` — the **database DDL is shipped as plain
`.sql`**, including Navicat headers and Chinese-language authoring metadata
(`Source Server: aaa`, dated 2024-06-14 … 2024-06-17).

---

## 5. Component map

| Component | Exported | Guard | Notes |
|---|---|---|---|
| `TranChatLauncherActivity` | ✅ | launcher intent-filter | Adds flags `0x34000000` and re-dispatches its own intent to `MainActivity`, then `finish()`. |
| `MainActivity` | ✅ | `VIEW`, custom `com.transsion.intercom.action.Login`, NFC `NDEF_DISCOVERED` with MIME `tran_direct_ntf/intercom_home` | Requests permissions at runtime, hosts `HomeFragment`. |
| `ChatActivity` | ❌ | — | Conversation UI (2,026 lines decompiled — the largest UI class). |
| `AnswerActivity` | ❌ | — | Full-screen incoming-call UI; `directBootAware`, `excludeFromRecents`, own task affinity. |
| `UnlinkDialogActivity` | ❌ | — | "No SIM inserted" / disconnect dialog. |
| `ImagePreviewActivity` | ❌ | — | Photo viewer (`PhotoView`). |
| **`BtChatService`** | ✅ | **none** | Foreground service (`connectedDevice\|microphone`), `intent-filter ACTION_START_CALL`. Core of the app, 58 methods. |
| `DynamicIslandNotificationService` | ❌ | — | `IntentService` rendering island notifications/actions. |
| `IslandAliveService` (vendor SDK) | ✅ | none | Keep-alive for the island SDK, actions `ALIVE_SERVICE`, `ANIMATION_START/END`. |
| `NotificationBroadcastReceiver` | ❌ | — | Handles `ACTION_ACCEPT_REQUEST`, `REJECT`, `HANG_UP`, `TURN_ON/OFF_SPEAKER`, `CLOSE`, `DISABLE`, `extra.EXTRA_NOTIFICATION_ID` + `macAddress` extra. |
| `AtomicClientProvider` | ✅ | `com.transsion.permission.atomiccore.safe` | `ContentProvider.call()` bridge for Atomic Card data. |
| `FileShareProvider` (vendor) | ❌ | read perm | Shares generated files with the atomic-core host. |
| `FileProvider` (androidx) | ❌ | — | `com.transsion.intercom.fileprovider`. |
| `InitializationProvider` (androidx) | ❌ | — | EmojiCompat / Lifecycle / ProfileInstaller. |
| `ProfileInstallReceiver` (androidx) | ✅ | `android.permission.DUMP` | System-only, harmless. |

`allowBackup="true"` with `dataExtractionRules` + `fullBackupContent`: chat
history, friend list and the `bt_attribute` identity blob are eligible for
cloud/adb backup.

---

## 6. Permissions and the "system app" story

33 requested permissions, of which these are **signature/privileged** and cannot
be granted to a normal app:

`BLUETOOTH_PRIVILEGED`, `TETHER_PRIVILEGED`, `WRITE_SECURE_SETTINGS`,
`WRITE_SETTINGS`, `MODIFY_PHONE_STATE`, `MODIFY_AUDIO_ROUTING`,
`INTERACT_ACROSS_USERS_FULL`, `STATUS_BAR`, `LOCAL_MAC_ADDRESS`,
`READ_WALLPAPER_INTERNAL`, `SYSTEM_ALERT_WINDOW`, `READ_PHONE_NUMBERS`,
`READ_PHONE_STATE`, `READ_CONTACTS`, `RECORD_AUDIO`, `ACCESS_FINE_LOCATION`.

Evidence of actual privileged use in code (not just declaration):

* `Settings.Global.putInt(cr, "tran_tdd_intercom_able", 0)` in
  `BtChatService.onDestroy()` — a Transsion-specific global setting.
* `Settings.Global.putInt(cr, "callable_type", n)` in `C2/e` — vendor telephony knob.
* `TranSystemProperties.set("persist.bluetooth.mwc.name", …)` — writes a **system
  property** (via the vendor `hubsdk`), i.e. the advertising/beacon name.
* `new TranBluetoothA2dp().setScanMode(adapter, 23)` — forces
  `SCAN_MODE_CONNECTABLE_DISCOVERABLE` while "discoverable".
* `BluetoothDevice#getAddress()` used freely (needs `LOCAL_MAC_ADDRESS`/
  `BLUETOOTH_PRIVILEGED` on modern Android).
* `TelephonyManager`/`SubscriptionManager` call-state queries to suppress the
  intercom ringtone during a real cellular call.

**Conclusion:** this is not an installable consumer app. It is a
system-partition component that expects platform signature + vendor `hubsdk`
(plus `com.android.bluetooth` extensions `IIntercomManagerService`). Running it
on stock Android is not possible; reimplementing it requires emulating the
vendor BT-stack AIDL (see `docs/PROTOCOL.md` §3).

---

## 7. Architecture

```
┌─────────────────────────── UI process ───────────────────────────────────┐
│ MainActivity / HomeFragment (C2/u)   ChatActivity   AnswerActivity        │
│   │  EventBus (org.greenrobot) : UItoServiceEvent / ServiceToUIEvent      │
│   ▼                                        ▲                              │
│ BtChatService  (foreground, single instance, owner of all state)          │
│   ├─ x2.c  BtAwaitChannel   ── control plane (request/accept/refuse/PSM)  │
│   ├─ x2.i  BtBaseChannel    ── data plane (text/voice/picture/audio)      │
│   │     ├─ x2.a AcceptThread / ConnectThread  (RFCOMM or L2CAP CoC)       │
│   │     ├─ x2.h ConnectedThread  ── I/O loop, Lyra codec, AudioTrack/Record│
│   │     └─ x2.q Handler          ── command handler, 60+ message codes     │
│   ├─ x2.w  ConvergedLocationService ── GPS/network updates during calls   │
│   ├─ x2.u  CallProximitySensorService ── screen off near ear, wake lock   │
│   ├─ x2.B  "LinkAudio" engine ── audio focus, ringtone, vibration, SCO    │
│   └─ w2.*  notification / dynamic-island / atomic-card plumbing           │
└───────────────┬───────────────────────────────────────────────────────────┘
                │ bindService(ACTION = "android.bluetooth.IIntercomManagerService")
                ▼
   ┌──────────────────────── vendor Bluetooth stack (com.android.bluetooth) ┐
   │ IIntercomManagerService  ← beacon/advertise/scan/notify                 │
   │ IIntercomCallback        → onReceiveData / handleBleData / state msgs   │
   └────────────────────────────────────────────────────────────────────────┘
                │ RFCOMM (insecure) or L2CAP CoC (PSM handed over via the beacon)
                ▼
            peer device running the same app
```

Global state lives in two singletons: `com.transsion.intercom.App` (`p`, holding
currently connected `BluetoothDevice`s, `d` = role/state, `n` = negotiated
**PSM**, `c` = peer-supplied display name) and the package-visible `u2.d`
(connection state, call state, pending request ids, timers, last location).

Audio runs on a dedicated `HandlerThread("LinkAudio")` plus a single-thread
`ExecutorService`; the socket writer is another executor (`y2.b.c`), so UI never
touches the socket directly.

### Event bus

`UItoServiceEvent(what, obj)` and `ServiceToUIEvent(what, obj)` are plain integer
messages. The full dictionary is recoverable from `y2.k.l(int)`
(`MSG_BT_START_RECORD 1111`, `MSG_BT_TALK_ACCEPT 1107`, `MSG_BT_SEND_PICTURE 1131`,
`MSG_BT_TEXT 1105`, `MSG_BT_UPDATE_TEMP_DATA 1129`, `MSG_BT_RECONNECT 1114`,
`MSG_BT_DISCOVERABLE 1115`, `MSG_BT_CLEAR_UNREAD 1126`, `3001/3003` vendor
callbacks, `1308` shutdown, …). It doubles as the app's own RPC layer across the
process boundary.

---

## 8. Audio pipeline

| Stage | Implementation |
|---|---|
| Capture | `AudioRecord` source `VOICE_COMMUNICATION`, 16 000 Hz, mono, PCM-16, buffer 640 B (= 20 ms) |
| Pre-processing | `AcousticEchoCanceler`, `NoiseSuppressor`, `AutomaticGainControl`, all enabled if available |
| Encode | `Codec2Jni.encode(byte[640])` → 8 B (3.2 kbit/s) or 23 B (9.2 kbit/s) per 20 ms hop |
| Framing | `0xB1` + big-endian `uint16` **sequence number** + 10 encoded frames (200 ms, 233 B or 83 B per packet). The sequence counter wraps at 32767 — exactly 1 h 49 m of audio, which is how the receiver rebuilds media time (`seq * 200 ms`). |
| Buffering | six rotating 233 B packet buffers on capture, a 5-deep queue drained by the `CallWrite` thread; on playback a 90-deep queue drained by the `audioTrackWrite` thread (drop-oldest when full); the socket send buffer is forced to `frame_size * 40` B (920 B at 9.2 kbit/s) by reflecting `BluetoothSocket.mSocket` → `LocalSocket#setSendBufferSize` |
| Decode | `Codec2Jni.decode(byte[n])` → 640 B PCM → `AudioTrack` (16 kHz, mono) |
| Playback | `AudioTrack` in `MODE_STREAM`; writes are off-loaded to an `audioTrackWrite` thread |
| Routing | `AudioManager.setMode(MODE_IN_COMMUNICATION)` (3), audio-focus request/abandon, `startBluetoothSco`/`stopBluetoothSco`, `CommunicationDevice` monitoring, wired-headset detection |
| Fallback | If the codec cannot be initialised, raw PCM is streamed: `0xB1` + 640 B of PCM-16 per 20 ms, no header, 256 kbit/s — unusable over a classic link in practice, so codec init failing effectively disables calling |

The DSP is Google's **Lyra V2** (`chromemedia::codec::LyraEncoder/LyraDecoder`,
`GilbertModel` for packet-loss concealment) wrapped by `com.ucchip.sdk.codec.jni.Codec2Jni`
— `codecInit(16000, 1, bitrate, 0, assetDir)`. The models are copied at first run
from `assets/codec1_model_coeffs/` to `files/codec1/` because TFLite needs real
file paths, not APK assets.

Bitrate selection is a device-class heuristic: `App.p.e != 2` selects
`Codec2Jni(0)` = 9.2 kbit/s, otherwise `Codec2Jni(1)` = 3.2 kbit/s (name shown in
`toString()` as `Size = 640, enFrameSize = 23/8 … Codec0`).

Voice notes are *not* Lyra: they use `MediaRecorder` (`OGG` container, `OPUS`
encoder, 16 kHz) written to `getExternalFilesDir(NOTIFICATIONS)/send_*.opus` and
`receive_*.opus`.

---

## 9. Discovery, pairing and channel setup

1. When the user enables "discoverable", `BtChatService.U()` writes
   `persist.bluetooth.mwc.name = <intercom name>` and calls
   `TranBluetoothA2dp().setScanMode(adapter, 23)`, then pushes a `Bundle
   {intercom_enable=1, intercom_name, intercom_priority}` to the BT stack over
   `IIntercomManagerService.transact(6)`. On failure it falls back to the public
   `REQUEST_DISCOVERABLE` intent (300 s).
2. The **stack** advertises/scans; the app is a passive listener. Peer reports
   arrive in `IIntercomCallback.onReportConnectDevice("MAC####name")` (code 5)
   and `onReceiveData(Bundle)` (code 1, forwarded to the UI as `3001`).
   The only local discovery is a user-triggered button in `HomeFragment`
   (`C2/u`, `startBtScan`: `BluetoothAdapter.startDiscovery()`, 15 s timeout,
   cancelled again before every connect in `x2.a`/`x2.b`). Notably there is **no
   `ACTION_FOUND` receiver** — the inquiry is only used to nudge the stack; peer
   identity still comes back through the AIDL callback.
3. Control frames (request/accept/refuse/timeout/cancel, PSM) travel as bytes
   through `transact(7)` / `transact(8)` and come back in
   `IIntercomCallback.handleBleData(byte[])` (code 4).
4. Data channels are ordinary Bluetooth sockets opened by the app:
   * **RFCOMM**, `listenUsingInsecureRfcommWithServiceRecord` /
     `createInsecureRfcommSocketToServiceRecord`, UUID derived from a literal
     string (see `docs/PROTOCOL.md` §2);
   * or **L2CAP CoC** (`listenUsingInsecureL2capChannel()`,
     `createInsecureL2capChannel(psm)`) when the peer announced a PSM via `0xD1`.
   `getConnectionType()` is recorded in `x2.i.j`, `getMaxTransmitPacketSize()`
   is logged — so the code explicitly supports both LE and Classic links.
5. `isBle` support is gated on the system property
   `ro.tr_ultralink.feature.version > 0` (`y2.k.d`). Without it, the app is
   RFCOMM-only and never binds the vendor AIDL.

Note the deliberate use of **insecure** sockets: no MITM protection and no
authenticated pairing is required at the API level.

---

## 10. Data model and storage

SQLite, DDL shipped in `assets/table/`:

| Table | Columns (from DDL) |
|---|---|
| `bt_friend` | `deviceId`, `name`, `newName`, `userInfo`, `deviceName`, `rssi`, `isBTUser`, `applyTime`, `priority`, … |
| `bt_chat_list` | `from`, `to`, `updateTime`, `unread`, `isBtUser`, `lastMsg`, `isRequester`, `nickName` |
| `bt_chat_history` | `id`, `from`, `to`, `time`, `type`, `status`, `content` (BLOB), `rule`, `attach`, `remark`, `group`, `multiple` |
| `bt_attribute` | `key` TEXT PK, `value` TEXT — stores `deviceId`, `macAddress`, `deviceName`, `userinfo`, `bt_discoverable` |

Message `type` ∈ {`TYPE_TEXT 0`, `TYPE_AUDIO 1`, `TYPE_TALK 2`, `TYPE_REMIND 3`},
`status` ∈ {SEND 0, FAILED 1, DEFAULT 2, SENDING 3}, `rule` ∈ {send, receive,
auto, not-connected}.

Media: pictures in `getExternalFilesDir(PICTURES)`, voice notes in
`getExternalFilesDir(NOTIFICATIONS)/{send,receive}_yyyyMMdd_HHmmss.opus`, codec
models in `files/codec1/`, plus a stray `files/ucchip.db` used by the codec SDK's
Glide/DB helper. Nothing is encrypted and nothing is deleted on logout.

### SQL injection (confirmed)

`BtAttributeDao` builds SQL by string concatenation:

```java
"SELECT * FROM bt_attribute WHERE `key` = '" + p2 + "'"
"INSERT OR REPLACE INTO bt_attribute (`key`,`value`) VALUES ('" + p2 + "', '" + p3 + "')"
```

Keys are mostly internal constants, but `userinfo` is a **peer-controlled JSON
blob** that is stored verbatim and re-emitted on the wire. A peer that can reach
the channel can therefore influence stored content; see `docs/SECURITY.md`.

---

## 11. Third-party / support inventory

`com.transsion.hubsdk` (588 classes, vendor `hubsdk` shim over hidden APIs),
`com.alibaba.fastjson` 1.x (274 classes — JSON for both DB rows *and* the wire),
`com.transsion.island` SDK (90), AndroidX activity/fragment/lifecycle/window,
`io.github.inflationx` (ViewPump), `com.bumptech.glide` (images + a shared SQLite
helper), `org.greenrobot.eventbus`, Material Components, Transsion widget/theming
libraries (`widgetslib`, `widgetthemes`, `widgetsliquid`, `widgetslistitemlayout`),
`com.transsion.atomiccore` (Atomic Card host SDK — note it also ships a small
`AES/CBC` helper used only for its own island IPC). No networking library at all —
the absence of OkHttp/Retrofit/Volley is itself the strongest evidence the app is
network-silent.

---

## 12. Obfuscation and how the analysis was done

R8 with heavy renaming and **class merging**: single-letter classes such as `x2.u`
and `K0.c` contain methods belonging to several original classes, so a decompiled
file often starts with an unrelated method (e.g. `y3.e.A()` is Glide internals).
Practical consequences:

* rely on **string constants, log tags and API calls**, not on class names;
* `y2.e` is the logger (`TranChat-<tag>`), `y2.k` the opcode/environment helper,
  `u2.d` the global state, `x2.*` the BT channel layer, `w2.*` notifications;
* `analysis/find_str.py` (instruction-level search) and
  `analysis/str_xref.py` (string cross-references) were the workhorses.

Toolchain used: `androguard` 4.x for manifest/ARSC/DEX plus its DAD decompiler
for 1,981 classes (the app surface reachable from `com.transsion.intercom` and
`com.ucchip`, see `analysis/reachable.py`). `jadx` was **not** available in this
sandbox (release assets are unfetchable here) — see `README.md` if you want to
redo the decompilation with jadx, which will read better.

Runtime reverse-engineering hooks the app itself provides:

```bash
adb shell setprop log.tag.intercom DEBUG   # enables verbose peer payload dumps
adb logcat -s TranChat-BtBaseChannel TranChat-BtChatService \
              TranChat-BtAwaitChannel TranChat-LinkAudioService TranChat-Codec2Jni
```
`y2.e.v()` gates full hex/JSON logging of every received frame on
`Log.isLoggable("intercom", DEBUG)` **or** a `userdebug`/`eng` build — i.e. the
vendor itself expects this to be debugged with logcat. For packet-level capture,
HCI snoop logging is the right tool (RFCOMM + L2CAP are both visible there).

---

## 13. Reimplementation feasibility

| Goal | Verdict |
|---|---|
| Understand the protocol | **Done** — see `docs/PROTOCOL.md`, `tools/ultralink_proto.py`. |
| Port to another Android phone (rewrite) | Feasible **without** the vendor stack only for the socket half: implement RFCOMM UUID + framing + Lyra; replace discovery with a normal BLE advertise/scan using a custom service UUID. Roughly 1–2 k local code plus the Lyra runtime. |
| Reuse the original APK on stock Android | Not possible (privileged permissions, `hubsdk`, `com.android.bluetooth` extension, AIDL). |
| Reuse the audio codec | `libjni_codec_transsion.so` + `libtensorflowlite.so` are self-contained and only need `Java_com_ucchip_sdk_codec_jni_Codec2Jni_*` + `files/codec1/`. Relicensable only if you honour the upstream Lyra/TFLite licences. |
| Interop with a real UltraLink device | Requires the vendor BT stack, i.e. a Transsion phone. Without it you can only impersonate the socket side **after** the stack half of the handshake has happened. |

---

## 14. Limits of this analysis

* No dynamic execution: nothing here was validated on a device or over the air.
* The vendor stack (`com.android.bluetooth` on Transsion ROMs) is not in this APK;
  the AIDL surface is reconstructed from the client side only.
* `libjni_codec_transsion.so` was not decompiled beyond symbols/strings; the
  Lyra integration details (quantizer settings, packet-loss model parameters) are
  inferred from the model tensor names and the Java bitrate/frame size values.
* Obfuscated class merging makes a few call sites ambiguous (noted inline where
  relevant).
