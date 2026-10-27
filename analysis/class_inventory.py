#!/usr/bin/env python3
"""
class_inventory.py -- DEX inventory: totals, package histogram, and the full
list of `com.transsion.intercom` classes with method counts.

Writes analysis/out_classes.txt and prints the same to stdout.
"""
import collections
import os
import sys

from loguru import logger

logger.remove()

from androguard.misc import AnalyzeAPK  # noqa: E402

DEFAULT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..",
                       "artifacts", "UltraLink_2.0.4.11.apk")


def pkg_of(class_name: str) -> str:
    parts = class_name.lstrip("L").rstrip(";").split("/")[:-1]
    if not parts:
        return "<default>"
    return "/".join(parts[:2]) if len(parts[0]) > 2 else parts[0]


def main(path: str) -> int:
    a, ds, dx = AnalyzeAPK(path)
    d = ds[0]
    out = []
    out.append("== DEX header ==")
    out.append(f"classes: {len(list(d.get_classes()))}")
    out.append(f"methods: {len(list(d.get_methods()))}")
    out.append(f"fields:  {len(list(d.get_fields()))}")
    out.append(f"strings: {len(list(d.get_strings()))}")
    out.append("")
    out.append("== com.transsion.intercom (application code) ==")
    for c in sorted(d.get_classes(), key=lambda x: x.get_name()):
        if "transsion/intercom" in c.get_name():
            out.append(f"  {c.get_name()}  methods={len(list(c.get_methods()))}")
    out.append("")
    hist = collections.Counter(pkg_of(c.get_name()) for c in d.get_classes())
    out.append(f"== package histogram ({len(hist)} roots) ==")
    for p, n in hist.most_common():
        out.append(f"{n:6d}  {p}")
    text = "\n".join(out)
    target = os.path.join(os.path.dirname(os.path.abspath(__file__)), "out_classes.txt")
    with open(target, "w") as fh:
        fh.write(text + "\n")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1] if len(sys.argv) > 1 else DEFAULT))
