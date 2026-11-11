# Cross-platform source inspection

Run from the project root or point Aegis at a monorepo root:

```sh
aegis run /path/to/project --mode code
```

No additional CLI switches, Flutter installation, `npm install`, Gradle execution
or project-specific account details are needed to read source. A Dart runtime is
required to run the installed CLI. These changes do not alter dynamic probes or
macOS security settings.

## Supported scope

| Source ecosystem | Inputs inspected |
| --- | --- |
| Flutter | Existing Dart, platform configuration and native-source checks |
| React Native / Expo | JS, JSX, TS, TSX and native Android/iOS bridge sources |
| Ionic / Capacitor, NativeScript, Cordova | The same standalone JS/TS patterns, plus discovered native inputs |
| KMP / Compose Multiplatform | Kotlin in `commonMain`, `androidMain`, `iosMain`, intermediate and other target source sets; Swift/Objective-C host sources when present |
| Native Android / iOS | Existing Kotlin, Java, Swift, Objective-C and platform configuration checks |

Discovery also reads `.mjs`, `.cjs`, `.mts` and `.cts`. Framework labels come from
package dependencies, explicit Kotlin Multiplatform Gradle plugin declarations
or conventional shared Kotlin source sets. A missing label does not prevent
supported source files from being inspected. Monorepo package folders within the
selected root are included; symlinks and external package paths are not followed.
Kotlin shared/iOS source alone does not imply an Android app. `androidMain`
manifests participate in Android configuration checks.

## Checks

| Rule | Added cross-platform patterns |
| --- | --- |
| AEG-N01 | Explicit JS/TS `rejectUnauthorized: false`, existing native TLS bypass patterns in applicable Kotlin code |
| AEG-N02 | Explicit unsafe WebView local-file access and `mixedContentMode="always"`/object equivalents |
| AEG-N03 | `CryptoJS.DES/TripleDES/RC4.encrypt`, existing explicit weak native cipher selections |
| AEG-N04 | Direct writes of sensitive identifiers to `AsyncStorage`, `localStorage` or `sessionStorage`; Kotlin/Native weak Keychain accessibility selections |
| AEG-N08 | Recognizable literal credentials and probable secrets, with values redacted |
| AEG-N09 | Sensitive identifiers in `console` logging, Kotlin `println` and existing native logging APIs |
| AEG-S01 | File counts by extension, detected frameworks, unsupported/unreadable inputs; informational discovery earns no security score |

JavaScript comments, quoted strings, regex literals, template literals and JSX
text are distinguished from executable expressions. Template/JSX expressions
are visited. Lexically ambiguous or unfinished syntax leaves checks incomplete;
verified findings remain failures and keep their score penalty. Read/discovery
limits also retain confirmed findings without granting full coverage.

These rules identify explicit source patterns and potential exposures. They do
not resolve imports/aliases, shadowing, types, reflection, obfuscated code,
interprocedural data flow, encryption wrappers or reachability in the chosen
build. A matching API name is not a verified runtime action. A safe alternative
or absence of a pattern does not prove all security controls work. AEG-S01's
inventory applies to discovered files, not a compiler-confirmed dependency graph.

Tests (`*.test.*`, `*.spec.*`, `__tests__`, `src/*Test`), declarations (`*.d.ts`
and module variants), common generated output, build caches, external dependencies
and symbolic links are excluded. The YAML `exclude` setting applies. Input limits
are 30,000 entries, directory depth 24, 4 MiB per file and 64 MiB total.

Vue/Svelte single-file components and C#/F#/C++/QML are currently unsupported:
.NET MAUI/Xamarin, Unity and Qt must not be described as fully supported. Their
discovered inputs make AEG-S01 incomplete, so the score is provisional. Supporting
a framework's JS/TS files does not mean all its templates/configuration are parsed.
npm/pnpm/yarn, Gradle/Maven and CocoaPods/SPM vulnerability advisories are not
covered by the existing Pub dependency audit. The coverage note states this.

Artifact checks remain independent of source language. Available sources also
accompany APK/AAB/IPA audits; runtime protection verdicts still require the
appropriate executed probes. A code-only scan cannot prove root, jailbreak,
Frida or signature-tampering defenses execute successfully.

## References

- [React Native: TypeScript and JavaScript](https://reactnative.dev/docs/typescript)
- [React Native: secrets and unencrypted Async Storage](https://reactnative.dev/docs/security)
- [Kotlin Multiplatform source sets](https://kotlinlang.org/docs/multiplatform-set-up-targets.html)
- [React Native WebView configuration](https://github.com/react-native-webview/react-native-webview/blob/master/docs/Reference.md)
