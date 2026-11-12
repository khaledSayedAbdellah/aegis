#!/usr/bin/env bash
# Real IPA metadata audit and debugger probe using a disposable iOS app.
set -euo pipefail

simulator=${1:?Supply the UDID of a booted iOS Simulator}
dart_bin=${DART_BIN:-dart}
cd "$(dirname "$0")/.."
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/Payload/Probe.app" "$work/simulator/Probe.app"
bundle=org.aegis.iossmoke
cat > "$work/Info.plist" <<XML
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>$bundle</string>
  <key>CFBundleExecutable</key><string>Probe</string>
  <key>CFBundleName</key><string>Probe</string>
  <key>CFBundleDisplayName</key><string>Aegis iOS Smoke</string>
  <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>CFBundleShortVersionString</key><string>1.0</string>
  <key>MinimumOSVersion</key><string>16.0</string>
  <key>LSRequiresIPhoneOS</key><true/>
  <key>CFBundleSupportedPlatforms</key><array><string>iPhoneOS</string></array>
  <key>DTPlatformName</key><string>iphoneos</string>
  <key>UIDeviceFamily</key><array><integer>1</integer><integer>2</integer></array>
  <key>NSAppTransportSecurity</key><dict><key>NSAllowsArbitraryLoads</key><true/></dict>
  <key>UIFileSharingEnabled</key><true/>
</dict></plist>
XML
plutil -convert binary1 -o "$work/Payload/Probe.app/Info.plist" "$work/Info.plist"
cp "$work/Info.plist" "$work/simulator/Probe.app/Info.plist"
plutil -replace CFBundleSupportedPlatforms.0 -string iPhoneSimulator "$work/simulator/Probe.app/Info.plist"
plutil -replace DTPlatformName -string iphonesimulator "$work/simulator/Probe.app/Info.plist"
printf 'example-test-secret=sample\n' > "$work/Payload/Probe.app/.env"
cat > "$work/entitlements.plist" <<'XML'
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>get-task-allow</key><true/></dict></plist>
XML
cat > "$work/main.m" <<'OBJC'
#import <UIKit/UIKit.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include <sys/stat.h>

@interface ProbeDelegate : UIResponder <UIApplicationDelegate>
@property (strong, nonatomic) UIWindow *window;
@end

@implementation ProbeDelegate
- (BOOL)application:(UIApplication *)app didFinishLaunchingWithOptions:(NSDictionary *)opts {
    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    self.window.rootViewController = [[UIViewController alloc] init];
    [self.window makeKeyAndVisible];
#if PROTECT == 1 || PROTECT == 2
    [NSTimer scheduledTimerWithTimeInterval:0.25 repeats:YES block:^(NSTimer *timer) {
        int mib[] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid() };
        struct kinfo_proc info = {0};
        size_t size = sizeof(info);
        if (sysctl(mib, 4, &info, &size, NULL, 0) == 0 &&
            (info.kp_proc.p_flag & P_TRACED)) {
#if PROTECT == 1
            puts("AegisProbe debugger blocked");
            fflush(stdout);
#endif
            exit(7);
        }
    }];
#endif
#if PROTECT == 3 || PROTECT == 4 || PROTECT == 5
    [NSTimer scheduledTimerWithTimeInterval:1.0 repeats:NO block:^(NSTimer *timer) {
#if PROTECT == 3
        if ([[NSFileManager defaultManager] fileExistsAtPath:@"/Applications/Cydia.app"]) exit(7);
#elif PROTECT == 4
        struct stat info;
        if (access("/var/jb", F_OK) == 0 && stat("/var/jb", &info) == 0 && S_ISDIR(info.st_mode)) exit(7);
#else
        NSData *binary = [NSData dataWithContentsOfFile:[[NSBundle mainBundle] executablePath]];
        NSString *marker = [NSString stringWithFormat:@"%@.%@.", @"aegis", @"partial"];
        NSData *needle = [marker dataUsingEncoding:NSUTF8StringEncoding];
        if ([binary rangeOfData:needle options:0 range:NSMakeRange(0, binary.length)].location != NSNotFound) {
            puts("AegisProbe repackage blocked");
            fflush(stdout);
            exit(7);
        }
#endif
    }];
#endif
    return YES;
}
@end

int main(int argc, char **argv) {
    @autoreleasepool { return UIApplicationMain(argc, argv, nil, @"ProbeDelegate"); }
}
OBJC
xcrun --sdk iphoneos clang -target arm64-apple-ios16.0 -framework UIKit -fobjc-arc \
    "$work/main.m" -o "$work/Payload/Probe.app/Probe"
codesign --force --sign - --entitlements "$work/entitlements.plist" "$work/Payload/Probe.app"
(cd "$work"; zip -qr test.ipa Payload)
CI=true "$dart_bin" bin/aegis.dart "$work" --ipa "$work/test.ipa" --offline -f json -o "$work/static"
python3 - "$work/static.json" <<'PYTHON'
import json, sys
with open(sys.argv[1]) as report:
    audit = json.load(report)
binary = audit["binary"]
assert binary["kind"] == "IPA" and binary["packageName"] == "org.aegis.iossmoke", binary
assert binary["abis"] == ["arm64"] and binary["signatureVerified"] is False, binary
failed = {row["id"] for row in audit["rules"] if row["status"] == "failed"}
assert {"AEG-I01", "AEG-I03", "AEG-I04", "AEG-I05", "AEG-I06"} <= failed, audit
print("IPA checks:", sorted(failed))
PYTHON

debugger_cases="1 2 0"
if [[ "${AEGIS_SMOKE_PARTIAL_ONLY:-0}" == 1 ]]; then debugger_cases=""; fi
for protected in $debugger_cases; do
    xcrun --sdk iphonesimulator clang -target "$(uname -m)-apple-ios16.0-simulator" \
        -framework UIKit -fobjc-arc -DPROTECT="$protected" "$work/main.m" -o "$work/simulator/Probe.app/Probe"
    codesign --force --sign - "$work/simulator/Probe.app"
    code=0
    CI=true "$dart_bin" bin/aegis.dart probe "$work/test.ipa" --profile l1+r --lang en \
        --ios-simulator "$simulator" --ios-simulator-app "$work/simulator/Probe.app" \
        --only debugger >"$work/probe.txt" 2>&1 || code=$?
    cat "$work/probe.txt"
    if [[ "$protected" != 0 ]]; then
        test "$code" -eq 0
        grep -q 'Reacted: 1' "$work/probe.txt"
        if [[ "$protected" == 2 ]]; then
            grep -q 'LLDB recorded a normal exit' "$work/probe.txt"
        fi
    else
        test "$code" -eq 1
        grep -q 'No block observed: 1' "$work/probe.txt"
    fi
done

# Positive controls: real NSFileManager/POSIX calls (no AegisProbe markers),
# and a fixture that explicitly reports the changed CodeDirectory identifier.
for protected in 3 4 5; do
    xcrun --sdk iphonesimulator clang -target "$(uname -m)-apple-ios16.0-simulator" \
        -framework UIKit -fobjc-arc -DPROTECT="$protected" "$work/main.m" -o "$work/simulator/Probe.app/Probe"
    codesign --force --sign - "$work/simulator/Probe.app"
    only=jailbreak
    if [[ "$protected" == 5 ]]; then only=repackage; fi
    code=0
    CI=true "$dart_bin" bin/aegis.dart probe "$work/test.ipa" --profile l1+r --lang en \
        --ios-simulator "$simulator" --ios-simulator-app "$work/simulator/Probe.app" \
        --only "$only" >"$work/partial.txt" 2>&1 || code=$?
    cat "$work/partial.txt"
    test "$code" -eq 2
    grep -q 'Partial observation: app reacted' "$work/partial.txt"
    grep -q 'Full iOS conditions remain incomplete' "$work/partial.txt"
done
# Return to the unprotected fixture for the combined negative controls.
xcrun --sdk iphonesimulator clang -target "$(uname -m)-apple-ios16.0-simulator" \
    -framework UIKit -fobjc-arc -DPROTECT=0 "$work/main.m" -o "$work/simulator/Probe.app/Probe"
codesign --force --sign - "$work/simulator/Probe.app"
original_hash=$(shasum -a 256 "$work/simulator/Probe.app/Probe")

printf 'ipa: test.ipa\nprofile: l1+r\nios_simulator: %s\nios_simulator_app: simulator/Probe.app\n' \
    "$simulator" >"$work/aegis.yaml"
code=0
CI=true "$dart_bin" bin/aegis.dart run "$work" --mode ipa --ios-target simulator --strict --offline --lang en \
    -f json -o "$work/combined" || code=$?
test "$code" -eq 2
test "$original_hash" = "$(shasum -a 256 "$work/simulator/Probe.app/Probe")"
python3 - "$work/combined.json" <<'PYTHON'
import json, os, sys
with open(sys.argv[1]) as report:
    audit = json.load(report)
assert not audit["complete"], audit
probe = audit["probe"]
assert probe["platform"] == "ios-simulator" and probe["baselineAlive"], probe
checks = {check["id"]: check["status"] for check in probe["checks"]}
assert checks["jailbreak"] == checks["ios-repackage"] == "inconclusive", checks
assert checks["ios-debugger"] == "notBlocked", checks
assert checks["ios-hooking"] in {"notBlocked", "inconclusive"}, checks
if os.environ.get("AEGIS_SMOKE_IOS_FRIDA") == "1":
    assert checks["ios-hooking"] == "notBlocked", checks
for row in probe['checks']:
    if row['id'] in {'jailbreak', 'ios-repackage'}:
        assert row['coverage'] == 'partial' and row['partialStatus'] == 'notBlocked', row
        assert row['limitations'] and row['limitationsAr'], row
print("Strict iOS report:", checks)
print("Partial positive/negative controls passed; original Simulator executable unchanged")
PYTHON
