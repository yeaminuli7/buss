# Security & privacy assessment — UltraLink 2.0.4.11

Static assessment only. No dynamic testing was performed; findings are marked
**[confirmed]** (visible in the artifact) or **[inferred]** (behaviour deduced
from code paths but not executed).

Context that shapes everything below: this is a **platform-signed system app**
with ‑‑ among others ‑‑ `BLUETOOTH_PRIVILEGED`, `WRITE_SECURE_SETTINGS`,
`MODIFY_PHONE_STATE` and `INTERACT_ACROSS_USERS_FULL`. It is meant to be part of
the ROM, not installed by a user. Most "missing hardening" below is therefore not
exploitable by a normal third-party app, but it *is* relevant to (a) anyone
auditing the ROM, (b) anyone interoperating with the protocol, and (c) the
privacy of the people using it.

---

## 1. Findings summary

| ID | Finding | Severity | Status |
|---|---|---|---|
| S1 | No application-layer encryption on chat, voice, pictures or location | High (privacy) | confirmed |
| S2 | Insecure RFCOMM / L2CAP sockets (no MITM-protected pairing); deterministic, universal service UUIDs | Medium | confirmed |
| S3 | Exported `BtChatService` (`ACTION_START_CALL`) accepts caller-supplied MAC + name without any caller check | Medium | confirmed |
| S4 | Precise GPS coordinates are streamed to the peer during every call | Medium (privacy) | confirmed |
| S5 | `allowBackup=true`: chat history, friend list, identity blob and media are backup-eligible | Medium | confirmed |
| S6 | Signed with the public AOSP test key — APK provenance cannot be established from the certificate | Medium (supply chain) | confirmed |
| S7 | SQL built by string concatenation in `BtAttributeDao`, storing peer-supplied blobs | Low | confirmed |
| S8 | Declared `DEVICE_PERMISSION` is never used; `IslandAliveService` and the launcher/Main activities are exported with no guard | Low | confirmed |
| S9 | Protocol has no integrity/authentication and a length-less text frame (1000 B cap) | Low | confirmed |
| S10 | Debug leftovers (`DebugProbesKt.bin`), verbose payload logging gated by `log.tag.intercom` | Informational | confirmed |
| S11 | Vendor AIDL (`IIntercomManagerService`) has no visible caller verification in the client; trust model lives in the BT stack | Informational | inferred |

---

## 2. Detail

### S1 — plaintext media and messages

There is **no cryptography in the app layer**: no `Cipher`, `SecretKey`,
`MessageDigest`, `KeyStore` or key material in any of the 1,981 app classes. Text
(`0xA1` JSON), push-to-talk audio (`0xB1` Lyra frames), voice notes (`0xB2/B3`),
pictures (`0xB6/B7`) and GPS fixes (`0xE2`-era beacon bundles) all travel as-is.

Confidentiality therefore rests entirely on the Bluetooth link key (BR/EDR
encryption) — which does exist for paired Classic links, but see S2.

One caveat for completeness: the *bundled vendor* Dynamic Island SDK does contain
an AES helper (`com.transsion.island.sdk.b.a`, `AES/CBC/PKCS5Padding`) which it
uses for its own island IPC payloads. Its key is the first 16 characters of a
passphrase string and its IV the last 16 — i.e. key and IV are derived from the
same secret, which is a textbook anti-pattern — but it has **nothing to do with
the intercom transport**, which never calls it.

### S2 — insecure sockets and universal UUIDs

`listenUsingInsecureRfcommWithServiceRecord` / `createInsecureRfcommSocketToServiceRecord`
are used deliberately (`x2.a`, `x2.b`), i.e. the *insecure* variants that skip
MITM protection during pairing. The L2CAP path is likewise
`listenUsingInsecureL2capChannel`. The service UUIDs are **derived from fixed
strings** (`tranchat.bt.text.channel`, `tranchat.bt.await.channel`) and are the
same on every install — so a peer knows exactly where to connect.

Practical impact: an attacker within radio range who can pair (JustWorks, no
MITM) can reach the data channel. The application protocol itself provides no
authentication, no session key, no nonce, and no replay protection: opcodes are
accepted purely on the basis of arriving on the socket (see `x2.h.run()`).

### S3 — exported service with no caller validation [confirmed]

```xml
<service android:name=".service.BtChatService" android:exported="true"
         android:foregroundServiceType="0x90">
  <intent-filter><action android:name="com.transsion.intercom.ACTION_START_CALL"/></intent-filter>
</service>
```

`onStartCommand()` accepts `ACTION_START_CALL` and reads `extra_name` (string) and
`extra_id` (a **Bluetooth MAC address**) with no permission, no signature check
and no verification that the device is bonded, a friend, or even an UltraLink
peer. The permission check in that method (`F()`) validates *UltaLink's own*
permissions, not the caller's.

Because the service owns microphone access, a local app that can bind/start it
can drive the "call" state machine toward an arbitrary address; whether audio
actually starts depends on the peer answering the handshake. **[inferred]** —
not executed.

Mitigation for ROM builders: add `android:permission` (signature-level) to the
service, or validate the caller's UID.

### S4 — location sharing

`x2.w` (`ConvergedLocationService`) registers `requestLocationUpdates("gps", 5000, 0, …)`
and `("network", 5000, 0, …)` for the duration of a call, and pushes each fix to
the peer over the BT link; the peer replies with its own so both can display a
distance. This is **precise** location (no rounding, no fuzzing) and it is
transmitted in cleartext (S1). There is no visible consent UI specific to this
feature beyond the runtime location permission at first launch.

### S5 — backups

`android:allowBackup="true"` with `dataExtractionRules`/`fullBackupContent`.
The SQLite database (`bt_friend`, `bt_chat_list`, `bt_chat_history`,
`bt_attribute`) and the recorded `.opus` files in
`getExternalFilesDir(NOTIFICATIONS)` are inside the app sandbox/external app dir
and are therefore eligible for cloud backup and device-to-device transfer.
`bt_attribute.userinfo` is the local identity blob that gets echoed to peers.

### S6 — signing key

`CN=Android, O=Android, android@android.com`, serial `0x936EACBE07F201DF`,
RSA-2048, `e=3` — the **public AOSP test key** shipped in every AOSP tree at
`build/target/product/security/testkey`. Consequences:

* anyone can produce an APK with an identical certificate;
* "signed with the platform key" is *not* evidence of vendor authorship here;
* on a real Transsion ROM this is harmless because the ROM is verified
  separately, but any manual reinstall/update of this app is inherently
  unauthenticated at the APK level.

### S7 — SQL string concatenation

`BtAttributeDao.queryAttribute()` / `saveOrInsertAttribute()` interpolate values
into SQL text. Most callers use internal constants, but `userinfo` is a
peer-derived JSON blob and other DAOs pass MAC-address-derived strings. The
attack surface is narrow (no SQL shell, single-argument, parameterless API) but
it is a genuine second-order injection pattern and violates the parameterised
style used everywhere else in the app (`?` binding in `BtChatHistoryDao`).

### S8 — exported components without guards

* `com.transsion.island.sdk.IslandAliveService` — exported, no permission; part of
  the vendor Dynamic Island SDK.
* `MainActivity` — exported for `VIEW`, a custom `com.transsion.intercom.action.Login`
  action and NFC `NDEF_DISCOVERED` with MIME `tran_direct_ntf/intercom_home`; it
  does not appear to act on arbitrary extras, but it can be launched by anyone.
* `TranChatLauncherActivity` — exported launcher; copies its own intent
  (action/data/extras) into `MainActivity` with `FLAG_ACTIVITY_NEW_TASK|CLEAR_TASK`.
* The declared permission `com.transsion.intercom.permission.DEVICE_PERMISSION`
  (`protectionLevel=normal`) is **not referenced anywhere** in the DEX.
* `AtomicClientProvider` is exported but protected by
  `com.transsion.permission.atomiccore.safe` (defined by the vendor host, not here).

### S9 — protocol robustness

No MAC, no checksum, no authentication tag, no replay counter on control frames;
`0xA1` relies on read-boundary framing with a 1000 B ceiling; `0xB1` uses a
16-bit sequence that wraps in ~1.8 h. A hostile peer can desynchronise or stall
sessions easily. This matters for interop more than for confidentiality.

### S10 — leftovers and logging

`DebugProbesKt.bin` (kotlinx-coroutines debug probes) is still packaged.
`y2.e.v()` enables hex/JSON dumps of *every* received frame when
`log.tag.intercom` is `DEBUG` or the build is `userdebug`/`eng`; on production
builds the verbose paths are off, but the ordinary `TranChat-*` logs still carry
MAC addresses, peer names and state transitions.

---

## 3. What is *not* wrong (worth stating)

* No network stack at all — no HTTP client, no telemetry endpoint, no analytics
  SDK, no URL strings. The app cannot exfiltrate data off-device by itself.
* `PendingIntent`s are created with `FLAG_IMMUTABLE` (`0x02000000`), not mutable.
* `androidx.core.content.FileProvider` is `exported=false` with `grantUriPermissions`.
* `ProfileInstallReceiver` (exported) is guarded by `android.permission.DUMP`.
* All sockets are released and audio effects/`AudioRecord`/`AudioTrack` are
  released on teardown; wake locks are bounded by the call lifetime.
* The heavy lifting for discovery lives in the BT stack, which is the right place
  for it from a permission standpoint (the app only gets what the stack reports).

---

## 4. Recommendations

For the vendor / ROM integrator:

1. Encrypt the data channel (even a static-DH + AES-GCM session key negotiated
   over the beacon would be enough) and add a per-session nonce; the protocol
   has spare opcodes.
2. Move discovery-adjacent state into the stack (already partially the case) and
   drop `BLUETOOTH_PRIVILEGED`/`LOCAL_MAC_ADDRESS` usage from the app layer.
3. Protect `BtChatService` with a signature-level permission and validate the
   caller UID.
4. Set `allowBackup="false"` or exclude the chat DB and media via
   `dataExtractionRules`.
5. Make the location-sharing feature explicit and opt-in per call.
6. Parameterise the `BtAttributeDao` queries.
7. Sign release builds with the device-unique platform key, not `testkey`.

For users: treat UltraLink traffic as "anyone in radio range with a paired
device can join", assume the peer receives your GPS position during calls, and
be aware that chat history is included in device backups.
