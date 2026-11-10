import 'dart:io';

import 'package:aegis/aegis.dart';
import 'package:aegis/src/probe/ios_runner.dart';
import 'package:aegis/src/probe/ios_simulator_partial.dart';
import 'package:aegis/src/probe/probe_report.dart';
import 'package:aegis/src/l10n/messages.g.dart';
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

  test('Simulator verdicts are visible and scoped, with full coverage incomplete',
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
        expect(rule.status, observed == ProbeStatus.notBlocked ? RuleStatus.failed : RuleStatus.incomplete);
        expect(rule.status == RuleStatus.incomplete || rule.incomplete, isTrue);
        expect(rule.findings, observed == ProbeStatus.notBlocked ? hasLength(1) : isEmpty);
        expect(rule.meta.title.en, contains('Simulator'));
        if (observed == ProbeStatus.notBlocked) {
          expect(rule.findings.single.message, contains('Simulator scenario'));
          expect(rule.findings.single.snippet, 'verified scoped observation');
          final verdict = id == 'AEG-R05'
              ? Ar.simulatorJailbreakNotBlocked : Ar.simulatorSigningNotBlocked;
          expect(rule.noteOf('ar'), startsWith(verdict));
          expect(rule.noteOf('ar'), contains('حدود التغطية:'));
        } else {
          expect(rule.noteOf('ar'), isNot(contains(Ar.simulatorSigningNotBlocked)));
          expect(rule.noteOf('ar'), isNot(contains(Ar.simulatorJailbreakNotBlocked)));
        }
      }
      final json = reportToJson(report)['probe'] as Map;
      for (final check in json['checks'] as List) {
        expect(check['status'], observed.name);
        expect(check['scope'], 'ios-simulator');
        expect(check['fullConditionStatus'], 'inconclusive');
        expect(check['partialStatus'], observed.name);
        expect(check['coverage'], 'partial');
        expect(check['limitations'], isNotEmpty);
        expect(check['limitationsAr'], isNotEmpty);
      }
      expect(
          renderHtml(report, lang: 'ar'), contains('على المحاكي'));
      expect(renderHtml(report, lang: 'ar'),
          contains('لا يختبر شهادة Apple مختلفة'));
      expect(renderMarkdown(report), contains('Simulator verdict:'));
      final scoped = runtime.scored.first;
      expect(probeResultMark(scoped), probeMark(observed));
      if (observed == ProbeStatus.notBlocked) {
        expect(renderHtml(report, lang: 'ar'), contains(Ar.simulatorSigningNotBlocked));
        expect(renderHtml(report, lang: 'ar'), contains(Ar.simulatorJailbreakNotBlocked));
        final ruleJson = (reportToJson(report)['rules'] as List)
            .cast<Map>().singleWhere((r) => r['id'] == 'AEG-R08');
        expect(ruleJson['status'], 'failed');
        expect(ruleJson['noteAr'], startsWith(Ar.simulatorSigningNotBlocked));
        expect(ruleJson['incomplete'], isTrue);
        expect(renderMarkdown(report, lang: 'ar'), contains(Ar.simulatorSigningNotBlocked));
        expect(renderMarkdown(report), contains(En.simulatorSigningGapFinding));
        expect(renderSarif(report), contains(En.simulatorSigningGapTitle));
        expect(report.coverage.controls.singleWhere((c) => c.control.id == 'MASVS-RESILIENCE-1').ruleIds, isNot(contains('AEG-R05')));
      }
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
