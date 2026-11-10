import 'dart:io';

import 'package:aegis/aegis.dart';
import 'package:aegis/src/probe/ios_runner.dart';
import 'package:aegis/src/probe/ios_simulator_partial.dart';
import 'package:aegis/src/probe/probe_report.dart';
import 'package:aegis/src/probe/probe_model.dart' show checkById;
import 'package:path/path.dart' as p;
import 'package:test/test.dart';

import 'ipa_test.dart' show fixture;

void main() {
  late Directory work;
  setUp(() {
    work = Directory.systemTemp.createTempSync('aegis-ios-partial-test-');
    addTearDown(() => work.deleteSync(recursive: true));
  });

  test('partial outcomes remain incomplete in rules, strict and every report',
      () async {
    final ipa = fixture(work);
    for (final observed in ProbeStatus.values) {
      final runtime = ProbeReport(
          app: 'Simulator.app',
          platform: 'ios-simulator',
          baselineAlive: true,
          results: [
            ProbeResult(checkById('baseline'), ProbeStatus.notBlocked),
            for (final check in iosProbeChecks
                .where((c) => c.id == 'jailbreak' || c.id == 'ios-repackage'))
              ProbeResult.partial(check,
                  observation: observed,
                  evidence: 'verified scoped observation',
                  note: check.id == 'jailbreak' ? jailbreakLimit : signingLimit,
                  noteAr: check.id == 'jailbreak'
                      ? jailbreakLimitAr
                      : signingLimitAr),
          ]);
      final outcome = ProbeOutcome.ran(runtime);
      expect(outcome.incomplete, isTrue);
      expect(probeExitCode(runtime, resilienceProfile: true), 2);
      expect(runtime.notBlocked, isEmpty);
      expect(runtime.blocked, isEmpty);
      final report = await runAudit(work.path,
          ipaPath: ipa.path,
          offline: true,
          config: AegisConfig(profile: ProfileSet.tryParse('l1+r')!),
          probe: outcome);
      expect(report.complete, isFalse);
      for (final id in ['AEG-R05', 'AEG-R08']) {
        final rule = report.results.singleWhere((r) => r.meta.id == id);
        expect(rule.status, RuleStatus.incomplete);
        expect(rule.findings, isEmpty);
      }
      final json = reportToJson(report)['probe'] as Map;
      for (final check in json['checks'] as List) {
        expect(check['status'], 'inconclusive');
        expect(check['partialStatus'], observed.name);
        expect(check['coverage'], 'partial');
        expect(check['limitations'], isNotEmpty);
        expect(check['limitationsAr'], isNotEmpty);
      }
      expect(
          renderHtml(report, lang: 'ar'), contains('اختبار جزئي على المحاكي'));
      expect(renderHtml(report, lang: 'ar'),
          contains('لا يختبر شهادة Apple مختلفة'));
      expect(renderMarkdown(report), contains('Partial observation:'));
      expect(renderProbe(runtime, lang: 'ar', resilienceProfile: true),
          contains('فحوصات iOS الكاملة تظل غير مكتملة'));
    }
  });

  test('indicator proof ignores another PID or run, missing files and symlinks',
      () {
    final proof = File(p.join(work.path, 'proof'));
    final session = IndicatorSession(proof, 'fresh', {});
    expect(session.events(15), isEmpty);
    proof.writeAsStringSync(
        'stale:15:ready\nfresh:16:ready\nfresh:15:ready\nfresh:15:query:/var/jb\n');
    expect(session.events(15), ['ready', 'query:/var/jb']);
    if (!Platform.isWindows) {
      final link = Link(p.join(work.path, 'link'))..createSync(proof.path);
      expect(
          IndicatorSession(File(link.path), 'fresh', {}).events(15), isEmpty);
    }
    proof.writeAsStringSync('x' * 65537);
    expect(session.events(15), isEmpty);
  });
}
