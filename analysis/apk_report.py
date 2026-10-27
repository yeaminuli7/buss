#!/usr/bin/env python3
"""
apk_report.py -- reproducible triage report for the UltraLink APK.

Emits:
  analysis/out_report.json   machine readable
  stdout                     human readable markdown

Requires androguard (see requirements.txt).

    python3 analysis/apk_report.py [path/to/app.apk]
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import zipfile
from collections import Counter

from loguru import logger

logger.remove()

from androguard.core.apk import APK  # noqa: E402
from androguard.misc import AnalyzeAPK  # noqa: E402

DEFAULT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..",
                       "artifacts", "UltraLink_2.0.4.11.apk")


def cert_info(apk: APK) -> dict:
    der = apk.get_certificates_der_v2() or apk.get_certificates_der_v3()
    if not der:
        return {}
    from asn1crypto import x509
    c = x509.Certificate.load(der[0])
    tbs = c["tbs_certificate"]
    return {
        "subject": c.subject.human_friendly,
        "issuer": c.issuer.human_friendly,
        "serial_hex": hex(c.serial_number),
        "not_before": str(tbs["validity"]["not_before"].native),
        "not_after": str(tbs["validity"]["not_after"].native),
        "pubkey": f"{c.public_key.algorithm} {c.public_key.bit_size}",
        "sha256": hashlib.sha256(der[0]).hexdigest(),
        "signed_v1": apk.is_signed(),
        "signed_v2": apk.is_signed_v2(),
        "signed_v3": apk.is_signed_v3(),
    }


def main(path: str) -> int:
    apk = APK(path)
    a, ds, dx = AnalyzeAPK(path)
    d = ds[0]

    z = zipfile.ZipFile(path)
    groups = ["lib/", "assets/", "res/", "META-INF/"]
    size = {
        "apk_bytes": os.path.getsize(path),
        "uncompressed_bytes": sum(i.file_size for i in z.infolist()),
        "entries": len(z.infolist()),
        "groups": {
            g: {"bytes": sum(i.file_size for i in z.infolist() if i.filename.startswith(g)),
                "entries": sum(1 for i in z.infolist() if i.filename.startswith(g))}
            for g in groups
        },
        "single_files": {
            f: next((i.file_size for i in z.infolist() if i.filename == f), 0)
            for f in ("classes.dex", "resources.arsc", "AndroidManifest.xml")
        },
    }

    def pkg_of(class_name: str) -> str:
        parts = class_name.lstrip("L").rstrip(";").split("/")[:-1]
        if not parts:
            return "<default>"
        # keep short obfuscated roots readable, e.g. A2, x2, y3
        return "/".join(parts[:2]) if len(parts[0]) > 2 else parts[0]

    pkgs = Counter(pkg_of(c.get_name()) for c in d.get_classes())

    report = {
        "file": os.path.basename(path),
        "sha256": hashlib.sha256(open(path, "rb").read()).hexdigest(),
        "package": apk.get_package(),
        "label": apk.get_app_name(),
        "version_name": apk.get_androidversion_name(),
        "version_code": apk.get_androidversion_code(),
        "min_sdk": apk.get_min_sdk_version(),
        "target_sdk": apk.get_target_sdk_version(),
        "max_sdk": apk.get_max_sdk_version(),
        "certificate": cert_info(apk),
        "permissions": sorted(apk.get_permissions()),
        "declared_permissions": apk.get_declared_permissions(),
        "features": apk.get_features(),
        "main_activity": apk.get_main_activity(),
        "activities": apk.get_activities(),
        "services": apk.get_services(),
        "receivers": apk.get_receivers(),
        "providers": apk.get_providers(),
        "dex": {
            "classes": len(list(d.get_classes())),
            "methods": len(list(d.get_methods())),
            "fields": len(list(d.get_fields())),
            "strings": len(list(d.get_strings())),
            "top_packages": pkgs.most_common(25),
        },
        "size": size,
        "native_libs": sorted({i.filename for i in z.infolist() if i.filename.startswith("lib/")}),
    }

    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "out_report.json")
    with open(out, "w") as fh:
        json.dump(report, fh, indent=2)

    c = report["certificate"]
    print(f"""# APK triage — {report['file']}

| field | value |
|---|---|
| package | `{report['package']}` |
| label | {report['label']} |
| version | {report['version_name']} (versionCode {report['version_code']}) |
| SDK | min {report['min_sdk']} / target {report['target_sdk']} |
| sha256 | `{report['sha256']}` |
| size | {size['apk_bytes']:,} B compressed, {size['uncompressed_bytes']:,} B expanded, {size['entries']} entries |
| signer | {c.get('subject')} |
| signer sha256 | `{c.get('sha256')}` |
| scheme | v1={c.get('signed_v1')} v2={c.get('signed_v2')} v3={c.get('signed_v3')} |
| main activity | `{report['main_activity']}` |

## Components

* activities: {', '.join('`%s`' % x.split('.')[-1] for x in report['activities'])}
* services: {', '.join('`%s`' % x.split('.')[-1] for x in report['services'])}
* receivers: {', '.join('`%s`' % x.split('.')[-1] for x in report['receivers'])}
* providers: {', '.join('`%s`' % x.split('.')[-1] for x in report['providers'])}

## Permissions ({len(report['permissions'])})

{', '.join('`%s`' % p.replace('android.permission.', '') for p in report['permissions'])}

## DEX

* classes {report['dex']['classes']:,} · methods {report['dex']['methods']:,} · fields {report['dex']['fields']:,} · strings {report['dex']['strings']:,}

Top packages:
""" + "\n".join(f"* {n:>6}  `{p}`" for p, n in report["dex"]["top_packages"]) + f"""

## Native libraries

{chr(10).join('* `%s`' % x for x in report['native_libs'])}

Report written to `{out}`.
""")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1] if len(sys.argv) > 1 else DEFAULT))
