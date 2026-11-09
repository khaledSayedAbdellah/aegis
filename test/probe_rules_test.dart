import 'package:aegis/aegis.dart';
import 'package:test/test.dart';

const fixtures = 'test/fixtures/apk';

ProbeReport report(Map<String, ProbeStatus> checks,
        {bool baselineAlive = true, String? emulatorError, String app = '/b/app-prod-release-1.2.3.apk'}) =>
    ProbeReport(
      app: app,
      baselineAlive: baselineAlive,
      emulatorError: emulatorError,
      results: [
        ProbeResult(probeChecks.first, ProbeStatus.notBlocked, evidence: 'stayed alive 8s'),
        for (final e in checks.entries)
          ProbeResult(probeChecks.firstWhere((c) => c.id == e.key), e.value,
              evidence: e.value == ProbeStatus.notBlocked ? 'app kept running normally' : 'app exited',
              note: e.value == ProbeStatus.inconclusive ? 'release builds are not debuggable' : null),
      ],
    );

Future<AuditReport> audit(ProbeOutcome? probe, {String profile = 'l2+r'}) => runAudit(fixtures,
    apkPath: '$fixtures/secure.apk',
    config: AegisConfig(profile: ProfileSet.tryParse(profile)!),
    offline: true,
    probe: probe);

RuleResult? rule(AuditReport r, String id) {
  for (final x in r.results) {
    if (x.meta.id == id) return x;
  }
  return null;
}

void main() {
  test('every probe rule has its own pass title and a RESILIENCE control', () {
    for (final r in probeRules) {
      expect(r.meta.passTitle.en, isNot(r.meta.title.en), reason: r.meta.id);
      expect(r.meta.masvs.single, startsWith('MASVS-RESILIENCE-'), reason: r.meta.id);
      expect(r.meta.profiles, {MasProfile.r});
    }
  });

  test('a run that never tried the probe has no R rules (plain CI)', () async {
    final r = await audit(null);
    expect(r.results.where((x) => x.meta.id.startsWith('AEG-R')), isEmpty);
    expect(r.probe, isNull);
  });

  test('blocked → passed, not blocked → finding, inconclusive → incomplete', () async {
    final r = await audit(ProbeOutcome.ran(report({
      'root': ProbeStatus.notBlocked,
      'hooking': ProbeStatus.blocked,
      'debugger': ProbeStatus.inconclusive,
      'repackage': ProbeStatus.notBlocked,
    })));
    expect(rule(r, 'AEG-R01')!.status, RuleStatus.failed);
    expect(rule(r, 'AEG-R02')!.status, RuleStatus.passed);
    expect(rule(r, 'AEG-R03')!.status, RuleStatus.incomplete);
    expect(rule(r, 'AEG-R03')!.note, contains('not debuggable'));
    expect(rule(r, 'AEG-R04')!.status, RuleStatus.failed);

    final f = rule(r, 'AEG-R01')!.findings.single;
    expect(f.message, contains('rooted emulator'));
    expect(f.messageAr, isNotEmpty);
    expect(f.file, 'app-prod-release-1.2.3.apk!/runtime');
    expect(r.probe!.report, isNotNull);
  });

  test('R findings count in the score', () async {
    final clean = await audit(ProbeOutcome.ran(report({
      'root': ProbeStatus.blocked, 'hooking': ProbeStatus.blocked, 'repackage': ProbeStatus.blocked,
    })));
    final gaps = await audit(ProbeOutcome.ran(report({
      'root': ProbeStatus.notBlocked, 'hooking': ProbeStatus.notBlocked, 'repackage': ProbeStatus.notBlocked,
    })));
    expect(gaps.score.value, lessThan(clean.score.value));
  });

  test('outside a MAS-R profile the R rules are out of profile', () async {
    final r = await audit(ProbeOutcome.ran(report({'root': ProbeStatus.notBlocked})), profile: 'l2');
    expect(rule(r, 'AEG-R01')!.status, RuleStatus.outOfProfile);
  });

  test('probe completion is independent of MAS-R and ignores inapplicable checks', () async {
    final undecided = await audit(
        ProbeOutcome.ran(report({'root': ProbeStatus.inconclusive})),
        profile: 'l1');
    expect(rule(undecided, 'AEG-R01')!.status, RuleStatus.outOfProfile);
    expect(undecided.complete, isFalse);

    final completed = report({'root': ProbeStatus.blocked});
    completed.results.add(ProbeResult(
        probeChecks.firstWhere((check) => check.id == 'debugger'),
        ProbeStatus.inconclusive,
        applicable: false));
    final r = await audit(ProbeOutcome.ran(completed), profile: 'l1');
    expect(r.complete, isTrue);
  });

  test('an automatic process verdict produces a scoped MAS-R finding', () async {
    final runtime = report({});
    runtime.results.add(ProbeResult(
        probeChecks.firstWhere((check) => check.id == 'root'),
        ProbeStatus.notBlocked,
        evidence: 'The same app process stayed alive after the condition was verified.',
        processOnly: true));
    final r = await audit(ProbeOutcome.ran(runtime));
    expect(r.complete, isTrue);
    final root = rule(r, 'AEG-R01')!;
    expect(root.status, RuleStatus.failed);
    expect(root.findings.single.message, contains('No process-level block'));
    expect(r.countAtLeast(Severity.high), greaterThan(0));
    expect(renderHtml(r, lang: 'ar'), contains('نفس عملية التطبيق فضلت شغّالة'));
    final probe = reportToJson(r)['probe'] as Map<String, Object?>;
    final checks = probe['checks'] as List;
    expect(checks.single['status'], 'notBlocked');
    expect(checks.single['scope'], 'process');
  });

  test('skipped / emulator error / dead baseline → incomplete with the reason', () async {
    final skipped = await audit(const ProbeOutcome.skipped('no emulator tools (run aegis setup)'));
    expect(rule(skipped, 'AEG-R01')!.status, RuleStatus.incomplete);
    expect(rule(skipped, 'AEG-R01')!.note, contains('aegis setup'));

    final broken = await audit(ProbeOutcome.ran(
        report({'root': ProbeStatus.inconclusive}, emulatorError: 'emulator did not boot')));
    expect(rule(broken, 'AEG-R01')!.note, contains('did not boot'));

    final dead = await audit(ProbeOutcome.ran(report({}, baselineAlive: false)));
    expect(rule(dead, 'AEG-R04')!.note, contains('control launch'));
  });

  test('the same gap in a build with another version still matches the baseline', () async {
    final a = await audit(ProbeOutcome.ran(report({'root': ProbeStatus.notBlocked},
        app: '/b/app-prod-release-1.2.3.apk')));
    final b = await audit(ProbeOutcome.ran(report({'root': ProbeStatus.notBlocked},
        app: '/b/app-prod-release-1.2.4.apk')));
    final fa = Baseline.fingerprint(rule(a, 'AEG-R01')!.findings.single);
    final fb = Baseline.fingerprint(rule(b, 'AEG-R01')!.findings.single);
    expect(fa, fb);
  });

  group('reports', () {
    Future<AuditReport> gaps() => audit(ProbeOutcome.ran(report({
          'root': ProbeStatus.notBlocked,
          'hooking': ProbeStatus.blocked,
          'debugger': ProbeStatus.inconclusive,
        })));

    test('every format shows the probe section with each check', () async {
      final r = await gaps();
      final console = ConsoleReporter(color: false).render(r);
      final md = renderMarkdown(r);
      final html = renderHtml(r);
      for (final out in [console, md, html]) {
        expect(out, contains('Resilience probe'));
        expect(out, contains('app-prod-release-1.2.3.apk'));
        expect(out, contains('AEG-R01'));
        expect(out, contains('MASTG-TEST-'));
        expect(out, contains('not debuggable'));
      }
      expect(md, contains('| Check |'));
      expect(html, contains('class="probe"'));
      expect(renderMarkdown(r, lang: 'ar'), contains('اختبار الحماية'));
    });

    test('JSON carries the probe outcome per check', () async {
      final j = reportToJson(await gaps());
      final probe = j['probe'] as Map<String, Object?>;
      expect(probe['ran'], isTrue);
      expect(probe['baselineAlive'], isTrue);
      final checks = (probe['checks'] as List).cast<Map<String, Object?>>();
      final root = checks.firstWhere((c) => c['id'] == 'root');
      expect(root['status'], 'notBlocked');
      expect(root['rule'], 'AEG-R01');
      expect(root['masvs'], 'MASVS-RESILIENCE-1');
      expect(checks.firstWhere((c) => c['id'] == 'debugger')['note'], contains('debuggable'));
    });

    test('a skipped probe says why, in every format', () async {
      final r = await audit(const ProbeOutcome.skipped('no emulator tools (run aegis setup)'));
      expect(ConsoleReporter(color: false).render(r), contains('aegis setup'));
      expect(renderMarkdown(r), contains('aegis setup'));
      expect(renderHtml(r), contains('aegis setup'));
      final probe = reportToJson(r)['probe'] as Map<String, Object?>;
      expect(probe['ran'], isFalse);
      expect(probe['skipped'], contains('aegis setup'));
    });

    test('a run without the probe has no probe section', () async {
      final r = await audit(null);
      expect(ConsoleReporter(color: false).render(r), isNot(contains('Resilience probe')));
      expect(renderMarkdown(r), isNot(contains('Resilience probe')));
      expect(reportToJson(r).containsKey('probe'), isFalse);
    });
  });
}
