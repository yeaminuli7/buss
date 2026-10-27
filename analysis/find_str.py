#!/usr/bin/env python3
"""Find classes/methods referencing given strings, class names or method names.
Usage: find_str.py <regex> [<regex> ...]   (matched against disassembled instruction output)"""
import sys, re
from loguru import logger; logger.remove()
from androguard.misc import AnalyzeAPK
a, ds, dx = AnalyzeAPK("artifacts/UltraLink_2.0.4.11.apk")
pats = [re.compile(p) for p in sys.argv[1:]]
seen = set()
for ma in dx.get_methods():
    m = ma.get_method()
    try:
        if m.get_code() is None: continue
    except AttributeError:
        continue
    for i in m.get_instructions():
        o = str(i.get_output())
        if any(p.search(o) for p in pats):
            key = (m.get_class_name(), m.get_name())
            if key in seen: continue
            seen.add(key)
            print(f"{m.get_class_name()}  ->  {m.get_name()}{m.get_descriptor()}\n      {i.get_name()} {o[:160]}")
            break
