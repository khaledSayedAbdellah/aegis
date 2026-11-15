/// Writes doc/maswe-coverage.md: which OWASP MASWE weaknesses aegis's rules
/// check, read from each rule's metadata.
///
/// Usage: dart run tool/maswe_coverage.dart [--check]
library;

import 'dart:io';

import 'package:aegis/src/rules/ipa_rules.dart';
import 'package:aegis/src/rules/probe_rules.dart';
import 'package:aegis/src/rules/registry.dart';
import 'package:aegis/src/rules/rule.dart';
import 'package:aegis/src/rules/runtime_security_rules.dart';

const output = 'doc/maswe-coverage.md';

/// The MASWE list as published at https://mas.owasp.org/MASWE/ (read
/// 2026-11-15): id, MASVS category, title.
const maswe = <(String, String, String)>[
  (
    'MASWE-0001',
    'STORAGE',
    'Sensitive Data Stored Unencrypted in Private Storage'
  ),
  (
    'MASWE-0002',
    'STORAGE',
    'Sensitive Data Stored Unencrypted Outside of Private Storage'
  ),
  (
    'MASWE-0003',
    'STORAGE',
    'Cryptographic Keys Stored Outside of Platform Keystore'
  ),
  ('MASWE-0004', 'STORAGE', 'Sensitive Data Hardcoded in the App Package'),
  ('MASWE-0005', 'STORAGE', 'Insertion of Sensitive Data into Logs'),
  ('MASWE-0006', 'STORAGE', 'Sensitive Data Not Excluded From Backup'),
  ('MASWE-0007', 'CRYPTO', 'Improper Encryption'),
  ('MASWE-0008', 'CRYPTO', 'Improper Hashing'),
  ('MASWE-0009', 'CRYPTO', 'Improper Use of Message Authentication Code (MAC)'),
  ('MASWE-0010', 'CRYPTO', 'Improper Generation of Cryptographic Signatures'),
  ('MASWE-0011', 'CRYPTO', 'Improper Verification of Cryptographic Signature'),
  ('MASWE-0012', 'CRYPTO', 'Improper Random Number Generation'),
  ('MASWE-0013', 'CRYPTO', 'Improper Cryptographic Key Generation'),
  ('MASWE-0014', 'CRYPTO', 'Improper Cryptographic Key Derivation'),
  ('MASWE-0015', 'CRYPTO', 'Cryptographic Key Rotation Not Implemented'),
  ('MASWE-0016', 'CRYPTO', 'Cryptographic Key Access Not Restricted'),
  ('MASWE-0017', 'CRYPTO', 'Device Secure Lock Not Enforced'),
  (
    'MASWE-0018',
    'AUTH',
    'Lack of Authentication or Authorization on App Components'
  ),
  ('MASWE-0019', 'AUTH', 'Lack of Auto-fill Support for Credential Providers'),
  ('MASWE-0020', 'AUTH', 'Local Authentication Can Be Bypassed'),
  (
    'MASWE-0021',
    'AUTH',
    'Fallback to Non-biometric Credentials Allowed for Sensitive Transactions'
  ),
  (
    'MASWE-0022',
    'AUTH',
    'Crypto Keys Not Invalidated on New Biometric Enrollment'
  ),
  (
    'MASWE-0023',
    'AUTH',
    'Step-Up Authentication Not Implemented for Sensitive Actions'
  ),
  ('MASWE-0024', 'AUTH', 'Sensitive Data Accessible After Session Termination'),
  ('MASWE-0025', 'AUTH', 'Lack of Non-Repudiation for Critical Actions'),
  ('MASWE-0026', 'NETWORK', 'Network Traffic Not Encrypted'),
  ('MASWE-0027', 'NETWORK', 'Insecure Certificate Validation'),
  ('MASWE-0028', 'NETWORK', 'Insecure Identity Pinning'),
  ('MASWE-0029', 'PLATFORM', 'Insecure Deep Links'),
  ('MASWE-0030', 'PLATFORM', 'Improper Use of the Clipboard'),
  ('MASWE-0031', 'PLATFORM', 'Allowing Untrusted App Extensions'),
  ('MASWE-0032', 'PLATFORM', 'Insecure Intents'),
  (
    'MASWE-0033',
    'PLATFORM',
    'Sensitive Native Functionality Exposed in WebViews'
  ),
  (
    'MASWE-0034',
    'PLATFORM',
    'WebViews Allow Access to Local Resources with Untrusted Content'
  ),
  ('MASWE-0035', 'PLATFORM', 'WebViews Loading Untrusted Content'),
  (
    'MASWE-0036',
    'PLATFORM',
    'Unnecessary Exposure of Sensitive Data via the User Interface'
  ),
  (
    'MASWE-0037',
    'PLATFORM',
    'Unnecessary Exposure of Sensitive Data via Notifications'
  ),
  (
    'MASWE-0038',
    'PLATFORM',
    'Insufficient Protection of Sensitive Data from Screenshots or Screen Recordings'
  ),
  ('MASWE-0039', 'PLATFORM', 'App Vulnerable to Overlay Attacks'),
  (
    'MASWE-0040',
    'PLATFORM',
    'Sensitive Data Leaked via Accessibility Services'
  ),
  ('MASWE-0041', 'CODE', 'Running on a Recent Platform Version Not Ensured'),
  ('MASWE-0042', 'CODE', 'Latest Platform Version Not Targeted'),
  ('MASWE-0043', 'CODE', 'Enforced Updating Not Implemented'),
  ('MASWE-0044', 'CODE', 'Dependencies with Known Vulnerabilities'),
  ('MASWE-0045', 'CODE', 'Compiler-Provided Security Features Not Used'),
  ('MASWE-0046', 'CODE', 'Use of Deprecated APIs or Functionality'),
  (
    'MASWE-0047',
    'CODE',
    'Using Non-Standard APIs for Security-Critical Functionality'
  ),
  ('MASWE-0048', 'CODE', 'Malicious Code Included in the App'),
  ('MASWE-0049', 'CODE', 'Unsafe Dynamic Code Loading'),
  ('MASWE-0050', 'CODE', 'Unsafe Handling of Untrusted Data'),
  ('MASWE-0051', 'RESILIENCE', 'Root/Jailbreak Detection Not Implemented'),
  (
    'MASWE-0052',
    'RESILIENCE',
    'App Virtualization Environment Detection Not Implemented'
  ),
  (
    'MASWE-0053',
    'RESILIENCE',
    'Emulated or Virtual Device Detection Not Implemented'
  ),
  ('MASWE-0054', 'RESILIENCE', 'Device Attestation Not Implemented'),
  ('MASWE-0055', 'RESILIENCE', 'Malware Detection Not Implemented'),
  ('MASWE-0056', 'RESILIENCE', 'App Attestation Not Implemented'),
  ('MASWE-0057', 'RESILIENCE', 'App Resources Integrity Not Verified'),
  ('MASWE-0058', 'RESILIENCE', 'Runtime Code Integrity Not Verified'),
  ('MASWE-0059', 'RESILIENCE', 'Code Obfuscation Not Implemented'),
  ('MASWE-0060', 'RESILIENCE', 'Resource Obfuscation Not Implemented'),
  ('MASWE-0061', 'RESILIENCE', 'Debug Artifacts Not Removed'),
  ('MASWE-0062', 'RESILIENCE', 'No Application-Level Payload Encryption'),
  ('MASWE-0063', 'RESILIENCE', 'Debug Mechanisms Not Disabled'),
  ('MASWE-0064', 'RESILIENCE', 'Debugger Detection Not Implemented'),
  (
    'MASWE-0065',
    'RESILIENCE',
    'Dynamic Analysis Tools Detection Not Implemented'
  ),
  ('MASWE-0066', 'PRIVACY', 'Inadequate Permission Management'),
  (
    'MASWE-0067',
    'PRIVACY',
    'Lack of Anonymization or Pseudonymisation Measures'
  ),
  ('MASWE-0068', 'PRIVACY', 'Incorrect Use of Identifiers for User Tracking'),
  ('MASWE-0069', 'PRIVACY', 'Usage of Non-Privacy-Preserving Functionality'),
  (
    'MASWE-0070',
    'PRIVACY',
    'Inadequate Awareness for Privacy Relevant Actions'
  ),
  ('MASWE-0071', 'PRIVACY', 'Inadequate Defaults for Privacy Relevant Actions'),
  ('MASWE-0072', 'PRIVACY', 'Inadequate Privacy Policy'),
  ('MASWE-0073', 'PRIVACY', 'Inadequate Data Collection Declarations'),
  ('MASWE-0074', 'PRIVACY', 'Inadequate Tracking Domains Declarations'),
  ('MASWE-0075', 'PRIVACY', 'Non-Reproducible Builds'),
  ('MASWE-0076', 'PRIVACY', 'Lack of Proper Data Management Controls'),
  ('MASWE-0077', 'PRIVACY', 'Inadequate Data Visibility Controls'),
  ('MASWE-0078', 'PRIVACY', 'Inadequate or Ambiguous User Consent Mechanisms'),
];

const _categories = [
  'STORAGE',
  'CRYPTO',
  'AUTH',
  'NETWORK',
  'PLATFORM',
  'CODE',
  'RESILIENCE',
  'PRIVACY',
];

/// Every rule aegis can run, once each.
List<Rule> everyRule() {
  final seen = <String>{};
  return [
    ...allRules,
    ...apkRules,
    ...ipaRules,
    ...extendedRules,
    ...runtimeSecurityRules,
    ...probeRules,
    ...iosProbeRules,
  ].where((r) => seen.add(r.meta.id)).toList();
}

/// MASWE id -> ids of the rules that cite it.
Map<String, List<String>> coverage([List<Rule>? rules]) {
  final out = <String, List<String>>{};
  for (final r in rules ?? everyRule()) {
    for (final id in r.meta.maswe) {
      (out[id] ??= []).add(r.meta.id);
    }
  }
  for (final ids in out.values) {
    ids.sort();
  }
  return out;
}

String generate([List<Rule>? rules]) {
  final covered = coverage(rules);
  final b = StringBuffer()
    ..writeln('# MASWE coverage')
    ..writeln()
    ..writeln('Which [OWASP MASWE](https://mas.owasp.org/MASWE/) weaknesses '
        'aegis checks, from the MASWE ids each rule cites. A listed rule '
        'checks part of the weakness, not necessarily all of it. The manual '
        'checks (`AEG-M01` to `AEG-M08`) are not mapped here.')
    ..writeln()
    ..writeln('Generated by `dart run tool/maswe_coverage.dart`; do not edit '
        'by hand.')
    ..writeln();
  final total = maswe.where((w) => covered.containsKey(w.$1)).length;
  b
    ..writeln(
        '**$total of ${maswe.length} weaknesses have at least one rule.**')
    ..writeln()
    ..writeln('| MASVS | Covered | Weaknesses |')
    ..writeln('|---|---|---|');
  for (final c in _categories) {
    final all = maswe.where((w) => w.$2 == c);
    final n = all.where((w) => covered.containsKey(w.$1)).length;
    b.writeln('| [$c](#${c.toLowerCase()}) | $n | ${all.length} |');
  }
  for (final c in _categories) {
    b
      ..writeln()
      ..writeln('## $c')
      ..writeln()
      ..writeln('| MASWE | Weakness | aegis rules |')
      ..writeln('|---|---|---|');
    for (final w in maswe.where((w) => w.$2 == c)) {
      final rules = covered[w.$1];
      b.writeln('| [${w.$1}](https://mas.owasp.org/MASWE/MASVS-$c/${w.$1}/) '
          '| ${w.$3} '
          '| ${rules == null ? 'not covered' : rules.join(', ')} |');
    }
  }
  return b.toString();
}

void main(List<String> args) {
  final known = maswe.map((w) => w.$1).toSet();
  final unknown = coverage().keys.where((id) => !known.contains(id)).toList();
  if (unknown.isNotEmpty) {
    stderr.writeln('Rules cite MASWE ids that are not in the list: '
        '${unknown.join(', ')}');
    exit(1);
  }
  final text = generate();
  final file = File(output);
  if (args.contains('--check')) {
    if (!file.existsSync() || file.readAsStringSync() != text) {
      stderr.writeln('$output is out of date. '
          'Run: dart run tool/maswe_coverage.dart');
      exit(1);
    }
    stdout.writeln('$output is up to date.');
    return;
  }
  file.writeAsStringSync(text);
  stdout.writeln('Wrote $output.');
}
