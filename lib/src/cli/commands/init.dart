import 'dart:convert';
import 'dart:io';

import 'package:aegis/aegis.dart';
import 'package:args/args.dart';
import 'package:path/path.dart' as p;

import '../arguments.dart';
import '../terminal.dart';

const _appTypes = [
  ('l1', 'Normal app, no sensitive data', 'تطبيق عادي، مفيهوش بيانات حساسة'),
  (
    'l2',
    'Personal or business data (accounts, HR, health)',
    'بيانات شخصية أو بيانات شغل (حسابات، HR، صحة)'
  ),
  ('l2+r', 'Banking, payments or government', 'بنوك أو مدفوعات أو جهات حكومية'),
  (
    'l1+r',
    'Game or app that must resist tampering',
    'لعبة أو تطبيق لازم يقاوم التعديل والغش'
  ),
];

Future<void> initCommand(ArgResults args) async {
  if (args['help'] as bool) {
    stdout.writeln(
        'Usage: aegis init [project-path] [--profile P] [--lang en|ar] [--force]\n');
    stdout.writeln('Writes aegis.yaml so that "aegis run" needs no options.\n');
    stdout.writeln(initParser().usage);
    return;
  }
  final root = args.rest.isEmpty ? '.' : args.rest.first;
  final file = File(p.join(root, AegisConfig.fileName));
  if (file.existsSync() && !(args['force'] as bool)) {
    stderr.writeln(
        '${file.path} already exists. Edit it, or use --force to overwrite it.');
    exit(2);
  }
  final lang = (args['lang'] as String?) ?? systemLang();

  var profile = args['profile'] as String?;
  if (profile != null && ProfileSet.tryParse(profile) == null) {
    stderr.writeln(
        'Unknown profile "$profile". Use l1, l2, l1+r, l2+r or a preset like banking.');
    exit(2);
  }
  if (profile == null) {
    if (!stdin.hasTerminal) {
      profile = 'l1';
    } else {
      stdout.writeln(terminalText.aegisWhatKindOfAppIsIt);
      for (var i = 0; i < _appTypes.length; i++) {
        final (id, en, _) = _appTypes[i];
        stdout.writeln('  ${i + 1}) $en  ($id)');
      }
      while (profile == null) {
        stdout.write(terminalText.aegisChoose1(value1: _appTypes.length));
        // Arabic keyboards send ٣ instead of 3, and some terminals send bytes
        // that are not valid UTF-8; neither should crash the prompt.
        String? line;
        try {
          line = stdin.readLineSync(
              encoding: const Utf8Codec(allowMalformed: true));
        } catch (_) {
          line = null;
        }
        if (line == null) {
          stderr.writeln('No answer: use aegis init --profile l1|l2|l2+r|l1+r');
          exit(2);
        }
        final n = parseMenuChoice(line, _appTypes.length);
        if (n != null) profile = _appTypes[n - 1].$1;
      }
    }
  }

  file.writeAsStringSync('''
# aegis settings: https://github.com/khaledSayedAbdellah/aegis
# All supported YAML settings. Replace <...> values for the checks you use.
# Unfilled placeholders are treated as unset, including optional iOS targets.
# File paths can be absolute or relative to this project.

# Audit policy: l1, l2, l1+r, l2+r, or a preset such as banking.
profile: $profile
lang: $lang  # Report files only; terminal output is always English.
fail_on: high
min_score: null  # No minimum score threshold; set a number from 0 to 100.
scan_packages: true
exclude: []  # Example: [lib/generated/**]
rules: {}  # Example: {AEG-D07: false, AEG-C02: medium}
baseline: aegis-baseline.json  # Used when the file exists.

# Release artifacts for aegis run --mode apk|aab|ipa.
apk: <path-to-file>
aab: <path-to-file>
ipa: <path-to-file>

# AAB runtime probe: signed APK, APKS archive, or device-specific APK directory.
probe_apk: <path-to-file>
probe_cert_sha256: <sha256-fingerprint>

# Physical iOS targets. For stock-device Frida, use a Development IPA
# and run aegis setup --ios. Choose simulator or device for each IPA run.
ios_control_device: <stock-device-udid>
ios_jailbreak_device: <jailbroken-device-udid>
ios_resigned_ipa: <path-to-file>

# Simulator Frida/LLDB probes. Select a dedicated booted Simulator.
# run automatically builds a matching app from Flutter or native Xcode source.
ios_simulator: <simulator-udid>
ios_simulator_app: <path-to-file>  # Optional .app directory; automatic if unset.
ios_simulator_flavor: <flavor>  # Optional; uses the project's build settings.
ios_simulator_target: <path-to-file>  # Optional Dart entry point; automatic if unset.
ios_xcode_project: <path-to-file>  # Native .xcodeproj/.xcworkspace; discovered if unset.
ios_xcode_scheme: <scheme>  # Native scheme; matched to the IPA if unset.
ios_xcode_configuration: Release  # Native Simulator build configuration.

# Generic screen/backup/key-access/links/WebView/tapjacking checks run automatically.
# No app-specific settings are needed; see doc/platform-protection.md for limits.

# Optional literal tracker signature catalog (JSON); built-in inventory always runs.
tracker_signatures: <path-to-file>

# Opt-in application-specific network/storage scenario. No host security changes.
# See doc/runtime-security.md. command is an argument list, never a shell string.
# It runs only when enabled here AND `aegis run --runtime-scenario` is passed.
runtime_security:
  enabled: false
  platform: <platform>  # android, ios-simulator, or ios-device; must match run.
  device: <device-id>
  command: []  # Example: [python3, tool/security_scenario.py]
  timeout_seconds: 120  # Per scenario phase.
  hosts: []  # Exact HTTPS hosts exercised and asserted by the baseline scenario.
  pinned_hosts: []  # Subset of hosts for trusted replacement-certificate checks.
  marker_env: {}  # Example: {password: AEGIS_TEST_PASSWORD}; synthetic values only.
  trusted_ca_dir: <path-to-file>  # Directory containing a dedicated test proxy CA.
  python: python3
  adb: adb
  mitmdump: mitmdump
''');
  stdout.writeln(
      terminalText.aegisWroteNext1AegisSetupOncePer(value1: file.path));
}
