#!/usr/bin/env python3
"""BFS from the app package through the call graph to find the app's real code surface."""
import json, sys, collections
from loguru import logger; logger.remove()
from androguard.misc import AnalyzeAPK
a, ds, dx = AnalyzeAPK("artifacts/UltraLink_2.0.4.11.apk")
roots = [c for c in dx.get_classes() if 'transsion/intercom' in c.name or 'ucchip' in c.name]
SKIP = ('Landroidx/','Lkotlin','Landroid/','Lcom/google/','Ljava','Ldalvik','Lorg/intellij','Lorg/jetbrains',
        'Lcom/alibaba/fastjson','Lcom/bumptech','Lio/github','Lcom/transsion/hubsdk','Lcom/transsion/widgets',
        'Lcom/transsion/island','Lcom/transsion/atomiccore','Lcom/transsion/widgetthemes','Lcom/transsion/widgetsliquid',
        'Lcom/transsion/widgetslistitemlayout','Lorg/greenrobot','Lcom/transsion/tran','Lcom/airbnb','Lcom/facebook')
seen = set(); q = collections.deque(roots)
while q:
    ca = q.popleft()
    if ca.name in seen: continue
    seen.add(ca.name)
    for m in ca.get_methods():
        for _, callee, _ in m.get_xref_to():
            n = callee.class_name
            if n in seen or n.startswith(SKIP): continue
            if n in dx.classes: q.append(dx.classes[n])
out = sorted(seen)
print(len(out))
json.dump(out, open("analysis/out_reachable.json","w"), indent=0)
import re
for n in out: print(n)
