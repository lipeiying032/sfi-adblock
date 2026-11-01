#!/usr/bin/env bash
# Verify an unsigned IPA produced by the GitHub Actions workflow.
set -euo pipefail

IPA="${1:-sfi-adblock-unsigned.ipa}"
EXPECTED_BUNDLE_ID="${2:-io.nekohasekai.sfa.application}"

[[ -f "$IPA" ]] || { echo "missing $IPA" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
unzip -q "$IPA" -d "$WORK"

APP="$(find "$WORK/Payload" -maxdepth 1 -name '*.app' -print -quit)"
[[ -n "$APP" ]] || { echo "no Payload/*.app" >&2; exit 1; }

BUNDLE_ID="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$APP/Info.plist")"
EXEC="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$APP/Info.plist")"

echo "app:       $APP"
echo "bundle id: $BUNDLE_ID"
echo "executable:$EXEC"
lipo -info "$APP/$EXEC" || true
du -sh "$IPA"

[[ "$BUNDLE_ID" == "$EXPECTED_BUNDLE_ID" ]] || { echo "unexpected bundle id" >&2; exit 1; }
lipo -info "$APP/$EXEC" | grep -q arm64
echo "OK"
