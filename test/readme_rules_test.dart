import 'dart:io';

import 'package:aegis/aegis.dart';
import 'package:aegis/src/rules/ipa_rules.dart';
import 'package:aegis/src/rules/probe_rules.dart'
    show iosProbeRules, probeRules;
import 'package:aegis/src/rules/registry.dart' show extendedRules;
import 'package:aegis/src/rules/runtime_security_rules.dart';
import 'package:test/test.dart';

void main() {
  test('every rule has a row in the README rule tables', () {
    final readme = File('README.md').readAsStringSync();
    final rows = RegExp(r'^\| (AEG-[A-Z]\d+) \|', multiLine: true)
        .allMatches(readme)
        .map((m) => m[1]!)
        .toSet();
    final ids = {
      for (final r in [
        ...allRules,
        ...apkRules,
        ...ipaRules,
        ...probeRules,
        ...iosProbeRules,
        ...extendedRules,
        ...runtimeSecurityRules,
      ])
        r.meta.id
    };
    expect(ids.difference(rows), isEmpty,
        reason: 'add a row for each to the README');
    expect(rows.difference(ids), isEmpty,
        reason: 'README rows for rules that no longer exist');
  });
}
