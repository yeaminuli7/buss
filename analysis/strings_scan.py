#!/usr/bin/env python3
"""Extract interesting indicators from the APK's DEX strings and all text assets."""
import os, re, sys, json, zipfile, collections
from loguru import logger; logger.remove()
from androguard.misc import AnalyzeAPK

APK = "artifacts/UltraLink_2.0.4.11.apk"
a, ds, dx = AnalyzeAPK(APK)
strings = set()
for d in ds:
    strings.update(d.get_strings())
strings = sorted(strings)
print(f"total unique dex strings: {len(strings)}")

pats = {
 "url":          r"https?://[^\s\"'<>]{4,200}",
 "ws":           r"wss?://[^\s\"'<>]{4,200}",
 "ipv4":         r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
 "ipv6":         r"\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b",
 "domain":       r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|cn|bd|ai|co|app|dev|xyz|top|me|info)\b",
 "file_path":    r"/(?:data|sdcard|storage|system|vendor|proc|sys)/[\w./\-]{2,120}",
 "uuid":         r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
 "hexblob":      r"\b[0-9a-fA-F]{32,}\b",
 "b64blob":      r"\b[A-Za-z0-9+/]{40,}={0,2}\b",
 "pem":          r"-----BEGIN [A-Z ]+-----",
 "jwt":          r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}\b",
 "email":        r"\b[\w.+-]+@[\w-]+\.[\w.]{2,}\b",
 "intent_action":r"\b(?:com|android)\.[\w.]*action[\w.]*",
 "perm":         r"\bandroid\.permission\.[A-Z_]+",
 "transsion":    r"com\.transsion\.[\w.]+",
 "api_suffix":   r"\b(?:/api/|/v\d/)[\w/{}\-.]{2,80}",
 "crypto_name":  r"\b(?:AES|DES|RSA|HmacSHA\d+|SHA-\d+|MD5|X25519|ECDH|ChaCha20|PBKDF2)[\w/\-]*\b",
}
res = {}
for k, p in pats.items():
    rx = re.compile(p)
    hits = collections.Counter()
    for s in strings:
        for m in rx.findall(s):
            hits[m] += 1
    res[k] = [h for h, _ in hits.most_common(400)]
    print(f"\n### {k}: {len(res[k])} unique")
    for h in res[k][:60]:
        print("   ", h)
json.dump(res, open("analysis/out_strings.json", "w"), indent=1)
