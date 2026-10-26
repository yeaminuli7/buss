#!/usr/bin/env bash
# Usage: re/scripts/analyze_apk.sh path/to/app.apk
# Produces a static-analysis report under re/work/<name>/ (git-ignored).
set -euo pipefail
APK="${1:?usage: $0 path/to/app.apk}"
NAME="$(basename "$APK" .apk | tr ' ' '_')"
OUT="re/work/$NAME"
mkdir -p "$OUT"

echo "== Basic info ==" | tee "$OUT/summary.txt"
ls -lh "$APK" | tee -a "$OUT/summary.txt"
sha256sum "$APK" | tee -a "$OUT/summary.txt"
file "$APK" | tee -a "$OUT/summary.txt"

echo "== Archive listing ==" 
unzip -l "$APK" > "$OUT/archive_listing.txt"
echo "entries: $(wc -l < "$OUT/archive_listing.txt")"
# Largest entries are often bundled assets or hidden payloads
sort -k1,1nr "$OUT/archive_listing.txt" | head -25 > "$OUT/largest_entries.txt"

echo "== Extracting (unzip, raw) =="
unzip -oq "$APK" -d "$OUT/raw" || true

if command -v aapt2 >/dev/null; then
  aapt2 dump badging "$APK" > "$OUT/badging.txt" || true
  aapt2 dump permissions "$APK" > "$OUT/permissions.txt" || true
fi
if [ -f "$OUT/raw/AndroidManifest.xml" ]; then
  echo "Binary AndroidManifest.xml extracted; use apktool/jadx for readable form."
fi
if [ -d "$OUT/raw/lib" ]; then
  find "$OUT/raw/lib" -name '*.so' | sort > "$OUT/native_libs.txt"
fi
if command -v apktool >/dev/null; then
  apktool d -f -o "$OUT/apktool" "$APK" > "$OUT/apktool.log" 2>&1 || true
fi
if command -v jadx >/dev/null; then
  jadx -d "$OUT/jadx" "$APK" > "$OUT/jadx.log" 2>&1 || true
fi
echo "Done. Report in $OUT/"
