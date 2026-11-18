#!/usr/bin/env bash
# Sync the Lantern web dashboard into mobile/www for the Capacitor app.
#
# Copies ../lantern/web (index.html, app.js, styles.css) plus the
# mobile client files (src/api.js, src/settings.js, src/mobile.js)
# into www/, then injects the mobile script tags into the copied
# index.html, before app.js. The Python dashboard under lantern/ is
# never modified.
#
# Idempotent: www/ is rebuilt from scratch on every run, so running
# this twice gives the same result. Run from the mobile/ directory.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MOBILE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
WEB_DIR="$MOBILE_DIR/../lantern/web"
WWW_DIR="$MOBILE_DIR/www"

if [ ! -d "$WEB_DIR" ]; then
  echo "error: Lantern web dashboard not found at $WEB_DIR" >&2
  exit 1
fi

rm -rf "$WWW_DIR"
mkdir -p "$WWW_DIR"

cp "$WEB_DIR/index.html" "$WEB_DIR/app.js" "$WEB_DIR/styles.css" "$WWW_DIR/"
cp "$MOBILE_DIR/src/api.js" "$MOBILE_DIR/src/settings.js" "$MOBILE_DIR/src/mobile.js" "$WWW_DIR/"

# Inject the mobile script tags before app.js. Python is used instead
# of sed so the replacement is exact and safe to re-run.
python3 - "$WWW_DIR/index.html" <<'PYEOF'
import sys

path = sys.argv[1]
text = open(path, encoding="utf-8").read()
old = '<script src="app.js"></script>'
new = (
    '<script src="api.js"></script>\n'
    '<script src="settings.js"></script>\n'
    '<script src="mobile.js"></script>\n'
    '<script src="app.js"></script>'
)
if old not in text:
    raise SystemExit("error: expected app.js script tag not found in index.html")
if new in text:
    raise SystemExit("error: mobile script tags are already injected")
open(path, "w", encoding="utf-8").write(text.replace(old, new, 1))
PYEOF

echo "Synced Lantern dashboard into $WWW_DIR:"
ls -1 "$WWW_DIR"
echo "Mobile bootstrap injected (api.js, settings.js, mobile.js before app.js)."
