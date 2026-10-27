# UltraLink APK — reverse engineering workspace

Static, reproducible analysis of the Transsion/Infinix **UltraLink**
(`com.transsion.intercom`) Android app, plus a clean-room description and
reference implementation of the Bluetooth protocol it speaks.

**Target:** `UltraLink_2.0.4.11.apk` · versionCode `20004011` ·
sha256 `15c78a6e0df61d89f0c3b5ab8f5953f2182128dce6c38cdbe19ba3a6f3b153fd` ·
20,279,973 B · 1,494 zip entries.

---

## TL;DR

* It is a **completely offline** Bluetooth walkie-talkie / chat app for
  Transsion devices. There is no HTTP stack, no URL, no telemetry anywhere in
  the 3,548-class DEX.
* Voice uses **Google Lyra V2** (TFLite) at **3.2 / 9.2 kbit/s**, 16 kHz mono,
  20 ms hops, ten hops per packet — a 9.3 kbit/s full-duplex call over Bluetooth.
* Peers are discovered by the **vendor Bluetooth stack**
  (`android.bluetooth.IIntercomManagerService`) — the app never handles
  `ACTION_FOUND`; it only opens ordinary RFCOMM/L2CAP sockets afterwards.
* It is a **platform-privileged system app** (`BLUETOOTH_PRIVILEGED`,
  `WRITE_SECURE_SETTINGS`, `MODIFY_PHONE_STATE`, …) signed with the **public
  AOSP test key**.
* There is **zero application-layer crypto**: messages, voice, pictures and GPS
  coordinates are plaintext on the link.

Full write-ups:

| Document | Contents |
|---|---|
| [`docs/ANALYSIS.md`](docs/ANALYSIS.md) | identity, provenance, packaging, components, permissions, architecture, audio, discovery, storage, obfuscation, feasibility |
| [`docs/PROTOCOL.md`](docs/PROTOCOL.md) | transport matrix, UUIDs, vendor AIDL, frame grammar, opcode table, payload schemas, session sequences, state model |
| [`docs/SECURITY.md`](docs/SECURITY.md) | security & privacy findings with severity and recommendations |

---

## Repository layout

```
artifacts/            the APK under analysis (not committed; see below)
analysis/             reproducible triage + decompilation tooling (Python/androguard)
docs/                 the analysis, protocol spec and security assessment
tools/                ultralink_proto.py — reference protocol model (stdlib only)
```

## Quick start

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt

# put the APK here (it is git-ignored on purpose):
cp /path/to/UltraLink_2.0.4.11.apk artifacts/

.venv/bin/python analysis/apk_report.py            # manifest / cert / dex / size triage
.venv/bin/python analysis/decompile.py 'Lcom/transsion/intercom/' --out work/src
python3 tools/ultralink_proto.py selftest          # protocol model, no deps
python3 tools/ultralink_proto.py outline
python3 tools/ultralink_proto.py uuid
```

## What the analysis pipeline does

| Script | Purpose |
|---|---|
| `analysis/apk_report.py` | one-shot triage → `analysis/out_report.json` + markdown (manifest, permissions, components, signer, DEX statistics, size budget, native libs) |
| `analysis/decompile.py` | androguard DAD decompiler for any class-regex, with a raw instruction dump fallback; writes a `.java` tree |
| `analysis/find_str.py` | instruction-level search: "which class/method references this API call or constant" |
| `analysis/str_xref.py` | DEX string cross-reference lookup |
| `analysis/strings_scan.py` | indicator sweep over all 24,363 DEX strings (URLs, IPs, paths, permission names, crypto names, `com.transsion.*`) |
| `analysis/reachable.py` | BFS over the call graph from the app packages → the ~1.2 k classes that actually matter |

Results of the last run are kept in `analysis/out_*.{txt,json}` so the report can
be checked without re-running anything.

## Notes on tooling

* **androguard 4.x** does all the heavy lifting (AXML/ARSC parsing plus DAD
  decompilation). It decompiled the whole app surface — 1,981 classes — without a
  single failure in ~20 s.
* **jadx was not usable in this environment** (its GitHub release assets are not
  reachable from the sandbox, and no jadx package exists on PyPI/npm). If you have
  jadx locally, rerun with:
  `jadx -d work/jadx --no-res --no-json artifacts/UltraLink_2.0.4.11.apk`;
  the source will read much better than DAD output, especially around R8
  class-merging artefacts.
* The APK ships only `arm64-v8a` native code, so any attempt to run it needs an
  arm64 device/emulator (or a rebuild of the Lyra stack).

## Provenance of these numbers

Everything in `docs/` is derived from the APK in this repository's
`artifacts/` directory. Where a conclusion required inference from obfuscated
code it is explicitly marked **[inferred]**. Dynamic behaviour was not tested —
there was no device and no Transsion Bluetooth stack involved.

## Legal

The APK is proprietary vendor software and is deliberately **not** committed to
this repository. The analysis documents are original work. The bundled Lyra
models/runtime are Google's, under their own licences; the neural codec is
`chromemedia::codec` (github.com/google/lyra).
