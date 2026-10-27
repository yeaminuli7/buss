# analysis/

Reproducible static-analysis tooling for `com.transsion.intercom` (UltraLink).

All scripts are standalone and take the APK from `../artifacts/` by default.
Run them with the venv described in the top-level `README.md`.

| script | what it answers |
|---|---|
| `apk_report.py` | what is in the package: manifest, components, permissions, signer, DEX counts, size budget → `out_report.json` |
| `decompile.py <regex>` | give me Java for these classes (DAD, with a raw-dump fallback) |
| `find_str.py <regex…>` | which method calls `BluetoothLeAdvertiser` / reads this constant |
| `str_xref.py <string…>` | which classes reference these exact DEX strings |
| `strings_scan.py` | indicator sweep (URLs, IPs, paths, permissions, crypto names) → `out_strings.json` |
| `reachable.py` | BFS call-graph closure from the app packages → `out_reachable.json` |
| `class_inventory.py` | DEX totals, `com.transsion.intercom` class list, package histogram → `out_classes.txt` |

Committed outputs from the last full run:

* `out_report.json` — triage of 2.0.4.11
* `out_strings.json`, `out_strings.txt` — indicator sweep
* `out_reachable.json`, `out_reachable.txt` — 1,195-class app surface
* `out_classes.txt` — DEX totals + package histogram + `com.transsion.intercom` class list

Decompiled sources are *not* committed (12 MB, and they are vendor code);
regenerate with `decompile.py` into any directory outside the repo.
