#!/usr/bin/env bash
# Builds a disposable native app and checks the real Android probe.
# Run only with an Android SDK/JDK and the dedicated aegis-probe AVD.
set -euo pipefail

sdk=${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}
: "${sdk:?Set ANDROID_SDK_ROOT or ANDROID_HOME}"
: "${JAVA_HOME:?Set JAVA_HOME to the JDK used by Android}"
build_tools=${BUILD_TOOLS:-"$sdk/build-tools/35.0.0"}
android_jar=${ANDROID_JAR:-"$sdk/platforms/android-35/android.jar"}
dart_bin=${DART_BIN:-dart}
cd "$(dirname "$0")/.."
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/classes" "$work/dex"
package=org.aegis.probesmoke.fixture
cat > "$work/AndroidManifest.xml" <<XML
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
          package="$package" android:versionCode="1">
    <uses-sdk android:minSdkVersion="28" android:targetSdkVersion="35"/>
    <application android:debuggable="true">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
    </application>
</manifest>
XML
"$JAVA_HOME/bin/keytool" -genkeypair -keystore "$work/original.jks" -alias smoke \
    -storepass smoke123 -keypass smoke123 -keyalg RSA -keysize 2048 -validity 1 \
    -dname 'CN=Aegis Smoke Test' >/dev/null 2>&1
original=$("$JAVA_HOME/bin/keytool" -exportcert -keystore "$work/original.jks" \
    -alias smoke -storepass smoke123 | openssl dgst -sha256 -binary | openssl base64 -A)

mode=${1:-all}
case "$mode" in all|debugger|hooking|paired|run|protected|protected-root|splits) ;; *) exit 2 ;; esac
outcomes=(blocked)
if [[ $mode == all ]]; then outcomes+=(not-blocked crash); fi
for outcome in "${outcomes[@]}"; do
    rm -f "$work/dex/classes.dex" "$work/unsigned.apk"
    if [[ $mode == protected || $mode == protected-root || $mode == splits ]]; then
        reaction='new Handler(getMainLooper()).postDelayed(() -> System.exit(7), 1200);'
    else
        reaction=$(cat <<REACTION
        if ("not-blocked".equals("$outcome")) {
            getPreferences(0).edit().putBoolean(check, true).apply();
        }
        Log.i("AegisProbe", check + " $outcome");
REACTION
)
    fi
    cat > "$work/MainActivity.java" <<JAVA
package $package;
import android.app.Activity;
import android.os.Bundle;
import android.os.Debug;
import android.os.Handler;
import android.util.Base64;
import android.util.Log;
import java.security.MessageDigest;
import java.io.BufferedReader;
import java.io.FileReader;
import android.os.Build;
import java.io.IOException;

public class MainActivity extends Activity {
    private void attempt(String check) {
        $reaction
    }

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        // Fixture signal for this user/userdebug pair. The probe independently
        // verifies root availability on each AVD before reading this outcome.
        if (("paired".equals("$mode") || "run".equals("$mode")) && "userdebug".equals(Build.TYPE)) {
            attempt("root");
        }
        if ("protected-root".equals("$mode") && Build.TAGS != null &&
                (Build.TAGS.contains("test-keys") || Build.TAGS.contains("dev-keys"))) {
            attempt("root");
        }
        try {
            byte[] cert = getPackageManager().getPackageInfo(getPackageName(), 0x08000000)
                .signingInfo.getApkContentsSigners()[0].toByteArray();
            String hash = Base64.encodeToString(MessageDigest.getInstance("SHA-256")
                .digest(cert), Base64.NO_WRAP);
            if (!hash.equals("$original")) {
                if ("$outcome".equals("crash")) {
                    throw new IllegalStateException("API key authorization failure");
                }
                attempt("repackage");
            }
        } catch (Exception e) { throw new RuntimeException(e); }
        Handler handler = new Handler(getMainLooper());
        handler.post(new Runnable() {
            @Override public void run() {
                if (Debug.isDebuggerConnected()) attempt("debugger");
                try (BufferedReader maps = new BufferedReader(new FileReader("/proc/self/maps"))) {
                    String line;
                    while ((line = maps.readLine()) != null) {
                        if (line.contains("frida-agent")) {
                            attempt("hooking");
                            break;
                        }
                    }
                } catch (IOException ignored) {}
                handler.postDelayed(this, 250);
            }
        });
    }
}
JAVA
    "$JAVA_HOME/bin/javac" --release 8 -cp "$android_jar" -d "$work/classes" "$work/MainActivity.java"
    "$build_tools/d8" --min-api 28 --lib "$android_jar" --output "$work/dex" \
        "$work/classes/org/aegis/probesmoke/fixture/"*.class
    "$build_tools/aapt2" link -I "$android_jar" --manifest "$work/AndroidManifest.xml" -o "$work/unsigned.apk"
    (cd "$work/dex"; zip -q "$work/unsigned.apk" classes.dex)
    "$build_tools/apksigner" sign --ks "$work/original.jks" --ks-pass pass:smoke123 \
        --out "$work/$outcome.apk" "$work/unsigned.apk"

    if [[ $mode != all ]]; then continue; fi
    code=0
    CI=true "$dart_bin" bin/aegis.dart probe "$work/$outcome.apk" --profile l1+r \
        --only repackage --lang en >"$work/probe.txt" 2>&1 || code=$?
    cat "$work/probe.txt"
    case "$outcome:$code" in
        blocked:0|not-blocked:1|crash:2) ;;
        *) echo "Unexpected probe result for $outcome (exit $code)" >&2; exit 1 ;;
    esac
    if [[ $outcome == crash ]]; then
        grep -q 'certificate-bound service failed' "$work/probe.txt"
    fi
done

if [[ $mode == protected-root ]]; then
    if grep -aqF 'AegisProbe' "$work/dex/classes.dex"; then exit 1; fi
    CI=true "$dart_bin" bin/aegis.dart probe "$work/blocked.apk" --profile l1+r \
        --only root --control-avd aegis-probe-control --root-avd aegis-probe --lang en \
        >"$work/probe.txt" 2>&1 || { cat "$work/probe.txt"; exit 1; }
    cat "$work/probe.txt"
    grep -q 'Reacted: 1' "$work/probe.txt"
    grep -q 'exited on its own' "$work/probe.txt"
    exit 0
fi

if [[ $mode == protected ]]; then
    if grep -aqF 'AegisProbe' "$work/dex/classes.dex"; then
        echo 'Protected smoke APK unexpectedly includes an AegisProbe marker' >&2
        exit 1
    fi
    printf 'name: aegis_protected_smoke\n' >"$work/pubspec.yaml"
    printf 'profile: l1+r\nlang: en\napk: blocked.apk\nfail_on: high\n' >"$work/aegis.yaml"
    code=0
    CI=true "$dart_bin" bin/aegis.dart run "$work" --mode apk --offline --strict \
        --no-open -f json -o "$work/protected-report" || code=$?
    test "$code" = 1
    python3 - "$work/protected-report.json" <<'PYTHON'
import json, sys
with open(sys.argv[1]) as report:
    audit = json.load(report)
probe = audit["probe"]
assert audit["complete"] and probe["baselineAlive"], probe
checks = {check["id"]: check for check in probe["checks"]}
for name in ("debugger", "hooking", "repackage"):
    check = checks[name]
    assert check["status"] == "blocked" and check["scope"] == "process", check
    assert "exited on its own" in check["evidence"], check
assert checks["root"]["status"] == "notBlocked", checks["root"]
print({name: check["status"] for name, check in checks.items()})
PYTHON
    exit 0
fi

if [[ $mode == run || $mode == splits ]]; then
    bundletool=${BUNDLETOOL_JAR:-"$HOME/.aegis/tools/bundletool-1.18.3.jar"}
    mkdir -p "$work/module/manifest" "$work/module/dex" "$work/res/values"
    printf '<resources><string name="smoke_name">Aegis</string></resources>' >"$work/res/values/strings.xml"
    if [[ $mode == splits ]]; then
        mkdir -p "$work/res/values-en"
        printf '<resources><string name="smoke_name">Aegis English</string></resources>' >"$work/res/values-en/strings.xml"
    fi
    "$build_tools/aapt2" compile --dir "$work/res" -o "$work/compiled.zip"
    "$build_tools/aapt2" link --proto-format -I "$android_jar" \
        --manifest "$work/AndroidManifest.xml" -o "$work/proto.apk" "$work/compiled.zip"
    unzip -p "$work/proto.apk" AndroidManifest.xml >"$work/module/manifest/AndroidManifest.xml"
    unzip -p "$work/proto.apk" resources.pb >"$work/module/resources.pb"
    cp "$work/dex/classes.dex" "$work/module/dex/"
    (cd "$work/module"; zip -qr "$work/base.zip" .)
    "$JAVA_HOME/bin/java" -jar "$bundletool" build-bundle --modules="$work/base.zip" \
        --output="$work/blocked.aab"
    printf 'name: aegis_probe_smoke\n' >"$work/pubspec.yaml"
    printf 'profile: l1+r\nlang: en\napk: blocked.apk\naab: blocked.aab\n' >"$work/aegis.yaml"

    fingerprint=$("$JAVA_HOME/bin/keytool" -exportcert -keystore "$work/original.jks" \
        -alias smoke -storepass smoke123 | openssl dgst -sha256 | awk '{print $NF}')
    if [[ $mode == splits ]]; then
        "$JAVA_HOME/bin/java" -jar "$bundletool" build-apks --bundle="$work/blocked.aab" \
            --output="$work/blocked.apks" --ks="$work/original.jks" --ks-key-alias=smoke \
            --ks-pass=pass:smoke123 --key-pass=pass:smoke123
        printf 'probe_apk: blocked.apks\nprobe_cert_sha256: "%s"\n' "$fingerprint" >>"$work/aegis.yaml"
        for artifact in blocked.apks play-splits; do
            companion=()
            if [[ $artifact == play-splits ]]; then companion=(--probe-apk "$work/$artifact"); fi
            CI=true "$dart_bin" bin/aegis.dart run "$work" --mode aab --offline --strict \
                ${companion[@]+"${companion[@]}"} --no-open -f json -o "$work/split-report" || {
                if [[ -f "$work/split-report.json" ]]; then cat "$work/split-report.json"; fi
                exit 1
            }
            python3 - "$work" "$artifact" "$fingerprint" <<'PYTHON'
import json, sys, zipfile
from pathlib import Path
work, artifact, fingerprint = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
with (work / "split-report.json").open() as report:
    audit = json.load(report)
probe = audit["probe"]
assert audit["complete"] and probe["baselineAlive"], probe
assert probe["app"] == artifact, probe
identity = probe["companionApk"]
assert identity["signatureVerified"] and identity["signerSha256"] == [fingerprint], identity
assert len(identity["controlApks"]) > 1 and len(identity["rootedApks"]) > 1, identity
checks = {check["id"]: check for check in probe["checks"]}
for name in ("debugger", "hooking", "repackage"):
    assert checks[name]["status"] == "blocked" and checks[name]["scope"] == "process", checks[name]
assert checks["root"]["status"] == "notBlocked", checks["root"]
print(artifact, "Split APKs:", identity["controlApks"], identity["rootedApks"])
print({name: check["status"] for name, check in checks.items()})
if artifact == "blocked.apks":
    selected = work / "play-splits"
    selected.mkdir()
    with zipfile.ZipFile(work / artifact) as archive:
        for apk in identity["controlApks"]:
            match, = [entry for entry in archive.namelist() if Path(entry).name == apk]
            (selected / apk).write_bytes(archive.read(match))
PYTHON
        done
        exit 0
    fi
    expect_rejected() {
        local message=$1 code=0
        shift
        CI=true "$dart_bin" bin/aegis.dart probe "$work/blocked.aab" --only root \
            --lang en "$@" >"$work/rejected.txt" 2>&1 || code=$?
        test "$code" = 2 && grep -Fq -- "$message" "$work/rejected.txt" || {
            cat "$work/rejected.txt"
            return 1
        }
    }
    expect_rejected 'APK signature verification failed' --probe-apk "$work/unsigned.apk"
    expect_rejected 'does not match --probe-cert-sha256' --probe-apk "$work/blocked.apk" \
        --probe-cert-sha256 "$(printf '%064d' 0)"

    printf 'probe_apk: blocked.apk\nprobe_cert_sha256: "%s"\n' "$fingerprint" >>"$work/aegis.yaml"
    kinds=(apk aab)
    if [[ ${2:-} == aab ]]; then kinds=(aab); fi
    for kind in "${kinds[@]}"; do
        CI=true "$dart_bin" bin/aegis.dart run "$work" --mode "$kind" --offline \
            --no-open --strict -f json -o "$work/$kind-report"
        python3 - "$work/$kind-report.json" "$kind" "$fingerprint" <<'PYTHON'
import json, sys
with open(sys.argv[1]) as report:
    audit = json.load(report)
assert audit["binary"]["kind"].lower() == sys.argv[2], audit["binary"]
probe = audit["probe"]
assert probe["ran"] and probe["baselineAlive"], probe
if sys.argv[2] == "aab":
    identity = probe["companionApk"]
    assert identity["signatureVerified"], identity
    assert identity["signerSha256"] == [sys.argv[3]], identity
    assert identity["expectedSignerSha256"] == sys.argv[3], identity
    assert identity["buildProvenance"] == "userSupplied", identity
checks = {check["id"]: check["status"] for check in probe["checks"]}
assert checks == dict.fromkeys(("root", "hooking", "debugger", "repackage"), "blocked"), probe
print(f"aegis run {sys.argv[2]}: {checks}")
PYTHON
    done
    exit 0
fi

check=debugger
avds=()
if [[ $mode == hooking ]]; then check=hooking; fi
if [[ $mode == paired ]]; then
    check=root,hooking
    avds=(--control-avd aegis-probe-control --root-avd aegis-probe)
fi
CI=true "$dart_bin" bin/aegis.dart probe "$work/blocked.apk" --profile l1+r \
    --only "$check" ${avds[@]+"${avds[@]}"} --lang en >"$work/probe.txt" 2>&1 || {
        cat "$work/probe.txt"
        exit 1
    }
cat "$work/probe.txt"
if [[ $mode == paired ]]; then
    grep -q 'Reacted: 2' "$work/probe.txt"
else
    grep -q 'Reacted: 1' "$work/probe.txt"
fi
