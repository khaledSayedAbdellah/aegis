import 'dart:convert';
import 'dart:io';

import 'package:aegis/aegis.dart';

import 'package:test/test.dart';

/// The names `package:aegis/aegis.dart` exports, by source file. Changing
/// this list changes the public API, which semver covers from 1.0.0: an
/// added name is a minor release, a removed or renamed one a major release.
const exported = {
  'src/baseline.dart': ['Baseline', 'BaselineEntry', 'defaultBaselineFile'],
  'src/changed_lines.dart': ['ChangedLines'],
  'src/config.dart': ['AegisConfig'],
  'src/rules/custom_rules.dart': ['CustomRuleSpec'],
  'src/engine.dart': [
    'AuditReport',
    'BinaryInfo',
    'CertificateInfo',
    'runAudit'
  ],
  'src/masvs.dart': [
    'MasvsControl',
    'ManualCheck',
    'masvsControls',
    'manualChecks'
  ],
  'src/model.dart': ['*'],
  'src/probe/probe_model.dart': [
    'ProbeApkIdentity', 'ProbeCheck', 'ProbeOutcome', 'ProbeReport', //
    'ProbeResult', 'ProbeStatus', 'probeChecks',
  ],
  'src/reporters/azure.dart': ['renderAzure'],
  'src/reporters/console.dart': ['ConsoleReporter'],
  'src/reporters/html.dart': ['renderHtml'],
  'src/reporters/json.dart': ['renderJson', 'renderSarif', 'reportToJson'],
  'src/reporters/markdown.dart': ['renderMarkdown'],
  'src/rules/registry.dart': ['allRules', 'apkRules'],
  'src/rules/rule.dart': ['Rule', 'RuleCheck'],
  'src/scoring.dart': ['Score', 'Coverage', 'CategoryScore'],
  'src/version.dart': ['aegisVersion'],
  'src/security/evidence.dart': ['SecurityEvidence'],
  'src/security/runtime_security.dart': ['RuntimeSecurityResult'],
};

void main() {
  test('the public API is exactly the documented list', () {
    final text = File('lib/aegis.dart').readAsStringSync();
    final found = <String, List<String>>{
      for (final m in RegExp(r"export '([^']+)'(?:\s+show\s+([^;]+))?;")
          .allMatches(text))
        m[1]!: m[2] == null
            ? ['*']
            : (m[2]!.split(',').map((s) => s.trim()).toList()..sort()),
    };
    final want = {
      for (final e in exported.entries) e.key: [...e.value]..sort()
    };
    expect(found, want,
        reason: 'The public API changed. That is a semver change: update '
            'this list and say so in the CHANGELOG.');
  });

  test('the CLI and tools do not need the public library for internals', () {
    // The CLI reaches internal code directly, so the public API only holds
    // what users of the library need.
    final text = File('lib/aegis.dart').readAsStringSync();
    for (final internal in [
      'ApkContext', 'IpaContext', 'SigningCert', 'parseMenuChoice', //
      'findBuiltBinary', 'ProbeRule',
    ]) {
      expect(text, isNot(contains(internal)), reason: internal);
    }
  });

  test('the JSON report says which layout it uses', () async {
    final dir = Directory.systemTemp.createTempSync('aegis_json_');
    addTearDown(() => dir.deleteSync(recursive: true));
    File('${dir.path}/pubspec.yaml').writeAsStringSync('name: app\n');
    final report = await runAudit(dir.path, offline: true);
    final json = jsonDecode(renderJson(report)) as Map;
    expect(json['formatVersion'], 1);
    expect(json['tool'], 'aegis');
  });
}
