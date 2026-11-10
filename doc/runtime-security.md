# Extended MASVS checks and runtime scenarios

`aegis run` automatically includes the new static checks when their inputs are
available. Artifact modes inspect the final manifest; source-only checks remain
limited to source. `--offline` prevents association requests. No check alters
macOS security, the host proxy, SIP, Gatekeeper or the host certificate store.

| Rules | Scope |
| --- | --- |
| AEG-A11 | Android HTTP(S) link configuration, broad hosts, custom-scheme inventory |
| AEG-A12 | Effective exported-component permissions, inherited application permissions, provider read/write and weak path permissions |
| AEG-A13 | Public HTTPS `assetlinks.json`, package, relation and release signer matching; unavailable/offline/AAB upload signer stays incomplete |
| AEG-N01 | Explicit native TLS bypass patterns; compiled references are separate evidence |
| AEG-N02 | Native and Flutter WebView local-file and mixed-content settings |
| AEG-N03 | Explicit native weak cipher selections; ambiguous hash/random references are indicators |
| AEG-N04 | Weak Keychain accessibility, file protection and Android world-accessible storage; biometric ACL/logging/clipboard/SQLite references are indicators |
| AEG-I10 | Broad/sensitive iOS entitlements; macOS hardened-runtime flags are inventory, not assumed effective iOS weaknesses |
| AEG-I11 | Explicit ATS forward secrecy exceptions |
| AEG-B12 | ELF NX requests, W+X, RELRO, executable PIE, library paths and debug sections; canary/FORTIFY references are inventory |
| AEG-T01 | Tracker inventory; four built-in SDK signatures plus an optional literal signature catalog |
| AEG-R09 | Scenario-based interception with substituted TLS certificates |
| AEG-R10 | Scenario-based synthetic marker search in app files, process logs and clipboard |

Static analysis is bounded. Unreadable binaries, unknown permissions and missing
release signer evidence must not turn into successful verification. Android
compiled code is inspected for references, **not decompiled/data-flow analyzed**.
Native source patterns are intentionally narrow. API presence does not establish
reachability, sensitive use, successful mitigation or a vulnerability.

`securityEvidence` in JSON and the additional evidence section in HTML/Markdown
are outside score and MASVS coverage. Tracker presence does not establish data
collection or consent violations. Built-in signatures identify Firebase Analytics,
Meta App Events, AppsFlyer and Adjust; this is not the full Exodus database.

Optional `tracker_signatures` JSON extends the inventory with literal code
signatures (no downloaded executable regular expressions):

```json
[{"name":"Example analytics SDK","prefixes":["com/example/analytics/","ExampleAnalytics"]}]
```

## Runtime setup

These tests need a developer-owned scenario that exercises the actual application
and asserts its outcome. Aegis cannot infer login details or treat simply launching
the app as proof that a protected operation completed. `init` includes all the
settings with runtime execution disabled until configured. When probes are
requested but no scenario is configured, R09/R10 are incomplete; `--no-probe`
disables them along with resilience probes. Strict mode treats incompleteness as
an incomplete audit.

Use a separate Python environment with a recent supported Python version:

```sh
python3 -m venv .venv-aegis-runtime
.venv-aegis-runtime/bin/python -m pip install mitmproxy frida-tools
```

The driver was integration-tested with mitmproxy 12.3.1. Frida must match the
server/Gadget in your target; use the Aegis-pinned version from `aegis doctor` when
sharing that environment. Frida bridges are read from installed `frida-tools`.
No proxy CA is installed on the Mac. Do not use production accounts or real secrets.

```yaml
runtime_security:
  enabled: true
  platform: android  # or ios-simulator / ios-device; must match run's target
  device: emulator-5554
  command: [.venv-aegis-runtime/bin/python, tool/security_scenario.py]
  timeout_seconds: 120
  hosts: [api.example.com]
  pinned_hosts: [api.example.com]
  marker_env: {password: AEGIS_TEST_PASSWORD}
  trusted_ca_dir: <path-to-file>
  python: .venv-aegis-runtime/bin/python
  adb: adb
  mitmdump: .venv-aegis-runtime/bin/mitmdump
```

Export a unique synthetic value of 12–1024 characters in each named environment
variable. Values never enter the report; only marker labels and channel names do.
Use a dedicated Aegis emulator (`aegis-probe*`) for Android. iOS targets must be
dedicated test targets. The driver verifies application identifier and build
before and after the baseline; it does not prove that an installed IPA is
byte-identical to the archived IPA. Simulator builds are different binaries.

For AAB, the scenario must install the matching signed companion APK/APKS using
your existing delivery setup. Aegis does not install an AAB directly. The baseline
must leave the target app running so its data can be collected.

## Scenario contract

`command` is an argument list executed without a shell from the project directory.
It is **your trusted test code**, and runs with your user permissions. It receives:

- `AEGIS_PHASE`: `prepare`, `baseline`, `untrusted`, `trusted`, then `cleanup`.
- `AEGIS_DEVICE`, `AEGIS_PLATFORM`, `AEGIS_APP_ID`, `AEGIS_BUILD`, `AEGIS_ARTIFACT`.
- `AEGIS_PROXY`: empty for baseline; `127.0.0.1:PORT` for interception phases.
- `AEGIS_CA_CERT`: temporary test-proxy CA certificate path during interception.
- Your synthetic marker environment variables.

Each successful phase must exit 0 and print one JSON object on its final stdout
line: `{"completed":true}`. The baseline additionally returns
`"reached_hosts":["api.example.com"]` **only after the test asserts a fresh successful
application operation against those endpoints**. Aegis relies on these assertions;
a mocked response or cached page is not an adequate baseline. Stdout/stderr from
the runner is bounded and never copied into reports.

`prepare` installs/launches the intended build. Your existing Appium, Maestro,
Flutter integration-test or other UI runner can supply these assertions. During
proxy phases it must route only the test target to `AEGIS_PROXY`, restart relevant
connections, exercise the same operation, and remove the routing afterwards.
For an Android emulator, `adb reverse tcp:PORT tcp:PORT` can expose the host loopback
proxy; save the existing target proxy setting before changing it. Flutter's Dart
network stack may ignore the Android system proxy: verify your test routing covers
that stack. Missing traffic is never a successful pinning result.

For an iOS Simulator or physical device, configure routing in the dedicated test
environment. Aegis does **not** change the Mac's system proxy to make Simulator
traffic flow through it. A physical device needs a developer-provided tunnel to
the loopback proxy. If routing is unavailable, the test remains incomplete.

`untrusted` uses a fresh private CA on every run. **Do not trust that CA** in this
phase. A recorded HTTPS request establishes acceptance of that substituted
certificate on the exercised path. `trusted` runs only when `trusted_ca_dir`
contains a dedicated mitmproxy `mitmproxy-ca.pem`. The scenario must arrange trust
on the test target (never the host), and restore it. Acceptance by a configured
`pinned_host` shows that identity pinning did not reject this replacement on that
path. Trust and routing are scenario preconditions; a failure to configure them
cannot prove successful pinning.

`cleanup` is attempted even when a phase fails. It must restore target proxy,
reverse tunnels and any test-target CA changes. A failed cleanup is recorded as
incomplete, not hidden. Scenario timeouts terminate their process group; collectors
have separate deadlines. Do not spawn detached persistent services from scenarios.

## What the results prove

R09 retains accepted interception findings, including when a subsequent scenario
assertion fails. No captured request is **inconclusive**, because routing, RASP,
caching or an unexercised code path can cause silence. The overall network check
stays incomplete rather than claiming exhaustive TLS/pinning coverage.

R10 scans bounded snapshots of process logs, clipboard and app files after the
baseline. Android uses `run-as` or a rooted dedicated emulator for the sandbox and
Frida for clipboard. Simulator uses its app container, logs and clipboard. Physical
iOS requires working Frida access for sandbox/clipboard; process logs are currently
unavailable in that collector, so the result is partial. A stock device without
instrumentation cannot expose the sandbox automatically. Missing channels and
collector limits are reported as incomplete.

Marker searches include UTF-8, UTF-16 and Base64. A match is reported with the value
redacted. A negative result applies only to the configured markers, collected
channels and executed scenario; it does not prove that all sensitive data is safe.
Transient leaks, encrypted/encoded formats not inspected, inaccessible Keychain
items and operations not executed remain outside this test's coverage.

## Validation

```sh
dart analyze
dart test
PYTHONDONTWRITEBYTECODE=1 python3 test/runtime_driver_test.py -v
# Optional real TLS transport integration (synthetic clients, no real app):
AEGIS_TEST_MITMDUMP="$PWD/.venv-aegis-runtime/bin/mitmdump" \
  .venv-aegis-runtime/bin/python test/runtime_driver_test.py -v
```

The real proxy integration uses a local fixture response and tests both clients
that accept a substituted certificate and clients that reject it. Device identity
and application scenario in that test are synthetic; this is not a successful
runtime assessment of your application.
