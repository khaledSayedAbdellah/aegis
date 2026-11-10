#!/usr/bin/env bash
# Actual Flutter builds through `aegis run`: missing app, changed IPA build, reuse.
# The small native IPA is a metadata fixture, not a production security verdict.
set -euo pipefail
simulator=${1:?Supply a dedicated booted iOS Simulator UDID}
flutter_bin=${FLUTTER_BIN:-flutter}
dart_bin=${DART_BIN:-dart}
repo=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d /tmp/aegis-simulator-autobuild.XXXXXX)
printf 'Artifacts and logs: %s\n' "$work"
"$flutter_bin" create --platforms=ios --org org.aegis --project-name autobuild "$work/project" >"$work/create.log" 2>&1
mkdir -p "$work/Payload/Runner.app"
cat >"$work/main.c" <<'C'
int main(void) { return 0; }
C
xcrun --sdk iphoneos clang -target arm64-apple-ios16.0 "$work/main.c" -o "$work/Payload/Runner.app/Runner"
cat >"$work/project/aegis.yaml" <<YAML
ipa: $work/test.ipa
ios_simulator: $simulator
profile: l1+r
YAML
make_ipa() {
  cat >"$work/Payload/Runner.app/Info.plist" <<PLIST
<plist><dict>
<key>CFBundleIdentifier</key><string>org.aegis.autobuild</string>
<key>CFBundleExecutable</key><string>Runner</string>
<key>CFBundleVersion</key><string>$1</string>
<key>CFBundleShortVersionString</key><string>1.2.3</string>
</dict></plist>
PLIST
  (cd "$work" && zip -qr test.ipa Payload)
}
run_check() {
  local name=$1
  local code=0
  CI=true "$dart_bin" "$repo/bin/aegis.dart" run "$work/project" --mode ipa --ios-target simulator --offline --strict --lang en -f json -o "$work/$name" >"$work/$name.log" 2>&1 || code=$?
  cat "$work/$name.log"
  test "$code" -eq 2 # the synthetic signature and device-only checks remain incomplete
  python3 - "$work/$name.json" <<'PY'
import json, sys
report = json.load(open(sys.argv[1]))
probe = report['probe']
assert probe['ran'], probe
results = {r['id']: r for r in probe['checks']}
for check in ('ios-debugger', 'ios-hooking'):
    assert results[check]['status'] == 'notBlocked', results[check]
print('Verified LLDB and Frida after automatic Flutter build')
PY
}
make_ipa 41
run_check missing
grep -q 'building Simulator app 1.2.3+41' "$work/missing.log"
make_ipa 42
run_check changed
grep -q 'building Simulator app 1.2.3+42' "$work/changed.log"
run_check reuse
if grep -q 'building Simulator app' "$work/reuse.log"; then exit 1; fi
printf 'Missing app, changed build, and reuse passed. Reports: %s\n' "$work"
