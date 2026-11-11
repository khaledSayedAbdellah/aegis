# Native Android and iOS projects

Aegis can run as a standalone Dart CLI against native project folders. Flutter
is not required for Kotlin/Java/Swift/Objective-C source inspection or native
Xcode Simulator builds.

```sh
aegis run /path/to/native-project --mode code
```

The project no longer needs `pubspec.yaml`. The loader discovers `.kt`, `.java`,
`.swift`, `.m`, `.mm` and `.h` files, Android main manifests/Gradle modules,
`Info.plist` and entitlements. Main Android modules and iOS plist inputs are
checked separately and findings retain their source paths and line numbers.
Artifact modes also inspect available native source alongside the supplied APK,
AAB or IPA. Artifact-only folders remain supported.

## Source checks and limits

- Existing Android rules inspect manifests, network configuration, release
  Gradle settings, backup flags, components, signing configuration and minimum SDK.
- Existing iOS rules inspect explicit plist and entitlement configuration.
- AEG-N01–N04 inspect explicit TLS bypass, unsafe WebView, weak crypto and
  insecure native storage patterns across the four languages.
- AEG-N08 detects recognizable credentials, JWTs and probable literal secrets;
  values are redacted. AEG-N09 finds sensitive identifiers passed to common logging
  calls, including basic Swift/Kotlin string interpolation.
- The six platform-protection families retain their existing scoped evidence and
  runtime behavior. Native source is available to the existing reference scans
  and tracker inventory. Flutter/Dart-only dependency and RASP-setup rules do not
  run against a native-only project.

Source matching is lexical, not a Kotlin/Java/Swift/Clang compiler or a complete
interprocedural data-flow analysis. Nested comments, raw Swift strings and
multiline text blocks are handled to avoid interpreting examples as code.
References alone do not establish working root/jailbreak/Frida protection;
runtime verdicts still come from the artifact probes. No new source rule changes
partial runtime failures or makes partial success count as full protection.

Discovery skips build outputs, Pods, Carthage, generated/vendor trees, common test
folders and symbolic links. `exclude` applies to native input discovery. It is
bounded to 30,000 entries, depth 24, 4 MiB per native source/config file and 64 MiB total input;
read/discovery limits leave affected source checks incomplete while keeping
confirmed findings. Native dependency advisories (Gradle/Maven, CocoaPods, Swift
Package Manager) are not part of the Pub dependency checks.

All discovered first-party source is reviewed, not just the selected build's
compiled source set. This can include code for multiple flavors or configurations.
Native source inspection does not evaluate Gradle scripts, merge flavor manifests,
resolve Xcode build variables or synthesize generated Info.plist files. Flavor
manifest inputs and missing/generated configuration remain incomplete instead of
being treated as a clean final configuration. Use APK/IPA mode for the packaged
configuration. Builds themselves can run their project's normal build scripts.

## Automatic native iOS Simulator build

From the native project folder, set the IPA path and dedicated Simulator UDID:

```yaml
ipa: dist/App.ipa
ios_simulator: <simulator-udid>
# Optional overrides, included by aegis init:
ios_xcode_project: <path-to-file> # .xcodeproj or .xcworkspace
ios_xcode_scheme: <scheme>
ios_xcode_configuration: Release
```

```sh
aegis run --mode ipa --ios-target simulator
```

If there is no matching `ios_simulator_app`, Aegis discovers Xcode containers,
prefers a workspace when present, and queries schemes/build settings for exactly
one iOS app matching the IPA bundle ID and executable. It then invokes
`xcodebuild` for the host Simulator architecture. Ambiguous selection or an
unresolved candidate is reported with the relevant YAML setting; it never picks
an arbitrary scheme. The optional project path is relative to `aegis.yaml`.
Flutter projects keep their existing Flutter build path and flavor/entrypoint
settings.

Native builds default to **Release**. `MARKETING_VERSION` and
`CURRENT_PROJECT_VERSION` are supplied from the IPA. The final `.app` must actually
match the IPA identifier, executable, version and build, and its Mach-O platform
must be iOS Simulator. A project that hardcodes different plist versions must
use the matching source/settings; Aegis does not rewrite the app identity after
building to conceal a mismatch.

Logs, generated products and build receipts live under
`.dart_tool/aegis/native-ios/`. Matching verified products can be reused;
changed build inputs or product contents invalidate the receipt. Failed or
interrupted output is marked unusable until a successful verified rebuild.
As with Flutter, a matching build number is not proof of identical source or
protection settings. Simulator findings describe that Simulator build.

A Mac, Xcode, an installed Simulator SDK/runtime and available project dependencies
are required. Aegis does not install CocoaPods dependencies, change signing teams,
request provisioning changes or modify macOS security. Simulator signing is local
ad-hoc signing. Device IPA signing and the original source project stay unchanged.

The opt-in integration test builds a real Swift/Objective-C app and verifies its
Simulator platform, identity, ad-hoc signature and reuse against synthetic IPA
identity metadata:

```sh
AEGIS_TEST_XCODE=1 dart test test/native_xcode_integration_test.dart
```
