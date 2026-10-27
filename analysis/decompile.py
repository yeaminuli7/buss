#!/usr/bin/env python3
"""Decompile selected classes from the UltraLink APK using androguard's DAD decompiler.
Usage: decompile.py <regex-filter> [--out DIR] [--all]
Writes one .java file per class under OUT/<dotted.package path>/<Class>.java
Classes that DAD cannot handle get a raw method/instruction dump instead.
"""
import argparse, os, re, sys, traceback
from loguru import logger
logger.remove()
from androguard.misc import AnalyzeAPK

APK = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "artifacts", "UltraLink_2.0.4.11.apk")

def raw_dump(c):
    out = [f"// RAW DUMP (decompiler failed) {c.get_name()}"]
    for m in c.get_methods():
        out.append(f"\n  .method {m.get_access_flags_string()} {m.name}{m.get_descriptor()}")
        try:
            for ins in m.get_instructions():
                out.append(f"      {ins.get_name():24s} {ins.get_output()}")
        except Exception as e:
            out.append(f"      <no instructions: {e}>")
    return "\n".join(out)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("filter", help="regex over the class descriptor")
    ap.add_argument("--out", default="/home/user/work/decompiled")
    ap.add_argument("--raw", action="store_true", help="force raw instruction dump")
    args = ap.parse_args()
    rx = re.compile(args.filter)
    a, ds, dx = AnalyzeAPK(APK)
    d = ds[0]
    todo = [c for c in d.get_classes() if rx.search(c.get_name())]
    print(f"matching classes: {len(todo)}", file=sys.stderr)
    ok = fail = 0
    for c in sorted(todo, key=lambda x: x.get_name()):
        raw = c.get_name()
        name = raw.lstrip("L").rstrip(";") if raw not in ("L", "L;") else "_invalid_" + raw.encode().hex()
        parts = [re.sub(r"[^\w.$-]", "_", p) or "_" for p in name.split("/")]
        safe = "/".join(parts).lstrip("/") or "_root"
        path = os.path.join(args.out, safe.replace("/", os.sep) + ".java")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        try:
            if args.raw:
                raise RuntimeError("forced raw")
            src = c.get_source()
            if not src or len(src) < 20:
                raise RuntimeError("empty source")
            ok += 1
        except Exception:
            src = raw_dump(c); fail += 1
        with open(path, "w") as fh:
            fh.write(src)
    print(f"decompiled={ok} raw_fallback={fail}", file=sys.stderr)

if __name__ == "__main__":
    main()
