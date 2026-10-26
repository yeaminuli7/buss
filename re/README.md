# APK analysis workspace

Target (from share link): `sg bussid 4.4.1.apk` (924 MB) + `main.2006529.com.maleo.bussimulatorid.obb` (179 MB).

## Why the binaries are not in Git
GitHub rejects files over 100 MB, so the APK/OBB are git-ignored. Options:
- Keep them locally in the sandbox (`re/input/`, ignored) for analysis.
- Attach them to a GitHub Release (assets up to 2 GB each).

## Workflow
1. Place the APK in `re/input/` (git-ignored).
2. Run `re/scripts/analyze_apk.sh re/input/<file>.apk`.
3. Decompiled sources land in `re/work/<name>/jadx/` (readable Java) and `apktool/` (smali + resources).

## Notes
- Only analyze/modify what you have rights to. Changes to a paid/online game (e.g. bypassing purchases, server checks, or anti-cheat) are out of scope.
- A 924 MB APK is unusually large for this game; verify the SHA-256 against the official Play Store/publisher build before trusting it, and don't install it on a device used for personal accounts.
