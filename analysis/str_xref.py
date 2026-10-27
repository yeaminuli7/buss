#!/usr/bin/env python3
"""Show which methods reference the given exact strings (uses androguard string xrefs)."""
import sys
from loguru import logger; logger.remove()
from androguard.misc import AnalyzeAPK
a, ds, dx = AnalyzeAPK("artifacts/UltraLink_2.0.4.11.apk")
want = set(sys.argv[1:])
for s in dx.get_strings():
    v = s.get_value()
    if v in want:
        print(f'\n"{v}" referenced by:')
        for c, m in s.get_xref_from():
            print(f"   {c.get_name()} -> {m.get_name()}{m.get_descriptor()}")
