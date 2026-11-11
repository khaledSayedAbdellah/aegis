# Automatic platform protection checks

These checks run without application-specific credentials, selectors, URLs or a
scenario script. Static inspection is included in code/APK/AAB/IPA audits;
`aegis run` also collects available launch-time facts during the existing probes.
`--no-probe` disables runtime collection. No external scanning backend is used.

| Rule | Automatic inspection | Limits |
|---|---|---|
| AEG-P11 | Screen-protection references; visible native password-field metadata on iOS Simulator; Android target window flags and UI metadata | Attempts a launch-screen capture and, on iOS Simulator, observes background transition metadata; temporary captures are deleted. Does not classify captured data, record video or inspect actual app-switcher snapshot contents. Does not identify every sensitive screen. A flag/reference is not a leak-prevention verdict. |
| AEG-N05 | Parse all resolved Android backup XML variants, include/exclude rules and separate cloud/device-transfer flows; inspect iOS Simulator sandbox file exclusion attributes | Does not perform cloud backup/restore, read file contents, establish content sensitivity, or prove physical-device encryption. iOS exclusions are advisory. |
| AEG-N06 | Keychain/Keystore/biometric API references and explicit configuration; iOS Simulator Keychain attributes; Android Keystore access metadata when instrumentation is available | Never reads secret values or exports key material. Does not bypass authentication or prove cryptographic binding of business operations. Simulator results do not establish Secure Enclave behavior. |
| AEG-I12 | Main IPA's signed application-identifier and associated domains against public HTTPS AASA; inventory registered URL schemes | Does not open arbitrary links, execute business actions, evaluate every path/component, or prove Apple CDN/device routing. Offline/unreachable/malformed responses are incomplete, never mismatches. |
| AEG-N07 | WebView/native bridge/navigation API references; current native WebView configuration; iOS loaded HTTPS WebViews reporting insecure content | JavaScript or bridge presence alone is informational. No arbitrary remote content is loaded. Hidden/authenticated WebViews and origin/redirect/bridge authorization remain unverified. |
| AEG-A14 | Android obscured-touch/overlay references; visible clickable native views tested with clean, fully-obscured and partially-obscured synthetic events | Calls only `onFilterTouchEventForSecurity`, never dispatches a touch/click. Not an OS overlay experiment, Flutter-widget authorization test or sensitive-action verdict. Android only. |

Each rule ends in one of three states:

| State | When | Effect |
|---|---|---|
| Evidence only (status `evidenceOnly` in JSON, with a note) | No concrete finding, and no requested runtime observation was left unfinished | Outside the score and MASVS coverage. Does not make the audit incomplete, so `--strict` and `--update-baseline` are unaffected. |
| Failed | A concrete finding: AASA identity mismatch, or an observed loaded HTTPS WebView reporting insecure content | Counted in the score. If the runtime observation was also left unfinished, the rule is failed **and** marked as partial coverage. |
| Incomplete | A probe was requested, the probe target has an automatic collector for this control, and that collector returned no verified facts or stopped at one of its bounds | Listed under incomplete checks; `--strict` exits 2 and `--update-baseline` refuses. |

Empty counts, dependency presence and no visible failure never produce a pass:
these rules have no passing state. Static-only audits (`aegis`, `aegis run --mode
code`, `--no-probe`) request no runtime observation, so their references and
configuration are evidence only. Automatic collectors exist for these controls:

| Probe target | Launch observer (every probe run) | Instrumented observer (only once it started) |
|---|---|---|
| Android emulator | AEG-P11, AEG-N07, AEG-A14 | adds AEG-N06, alongside the Frida check |
| iOS Simulator | AEG-P11, AEG-N05, AEG-N06, AEG-I12, AEG-N07 | none |
| Physical iOS device | none | none |

The probe records which observers it started (`probe.platformObserverAttempts`
in JSON: `control`, `instrumented`). A launch observer that the run asked for
but never reached, or one that started and returned no verified facts, leaves
its controls incomplete; the evidence states which of the two happened. The
Android instrumented observer is optional, so AEG-N06 is requested there only
when that observer started: a run without a Frida check leaves it evidence only.

A collector bound affects only its own control: the view bound applies to
AEG-P11/N07/A14, the file bound to AEG-N05 and the key-query bound to AEG-N06.
Use the existing per-rule configuration to exclude checks outside an audit's scope.

## Runtime collection

On Android, the control emulator supplies window/UI metadata. If the standard
Frida probe establishes access to the rooted emulator, a bounded observer gathers
native view/security-filter and Keystore metadata there. Reports label this as
instrumented; control observations are retained separately in the probe result.
The synthetic touch filter comparison uses a clean event as a control and does
not call `dispatchTouchEvent`, `performClick` or an application transaction.
A Flutter surface may expose no clickable Android child views: that is a coverage
gap, not a successful anti-tapjacking result.

On iOS Simulator, a fresh original control build is installed after the resilience
experiments. A small shipped Objective-C observer is compiled with the Simulator
SDK, ad-hoc signed in the probe's temporary directory and loaded into that test
process. It reads visible native view metadata, regular sandbox file backup
attributes and Keychain **attributes only**, with authentication UI disabled.
The output is checked against a per-launch random nonce, bundle identifier and
PID. App data, key values, account names and UI text are not written to reports.
The observer backgrounds the test app by relaunching Settings inside the dedicated Simulator; it changes no setting. Both application and scene lifecycle notifications are observed, with a bounded wait for verified output. The test installation and temporary observer are removed by probe cleanup.

This observer is not injected into a physical iPhone: without a supported runtime
collector, the report explicitly retains static-only evidence. The observer can
itself trigger RASP or affect behavior. A missing/terminated observer on a target
that has one is incomplete, not a security failure. The instrumented launch is separate from the resilience
baseline so it cannot manufacture root/Frida/jailbreak verdicts.

Bounds: iOS views 5,000, filesystem enumeration 2,000 entries, reported Keychain
attribute records 1,000 per item class; Android view traversal 2,000, clickable
filter comparisons 200, Keystore aliases 200. Some platform APIs may enumerate
internally before these output limits are applied. AASA is limited to eight
public hosts, 1 MiB responses, verified HTTPS and no redirects/private IPs. XML
resources are limited to 64 variants and 1 MiB each. Limits or unresolved evidence
are reported; they cannot produce a pass.

No SIP, AMFI, Gatekeeper, macOS Keychain/trust store, host proxy or certificate
settings are changed. The tests use only the selected dedicated emulator/Simulator.

Reference layouts and behavior:
- [Android backup configuration](https://developer.android.com/identity/data/autobackup)
- [Android obscured-touch protection](https://developer.android.com/privacy-and-security/risks/tapjacking)
- [Apple associated domains](https://developer.apple.com/documentation/xcode/supporting-associated-domains)
- [OWASP backup exclusions](https://mas.owasp.org/MASWE-0006/)
- [OWASP key access controls](https://mas.owasp.org/MASWE-0016/)
