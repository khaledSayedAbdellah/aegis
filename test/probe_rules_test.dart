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

  test('blocked → passed, not blocked → finding, inconclusive → not applicable', () async {
    final r = await audit(ProbeOutcome.ran(report({
      'root': ProbeStatus.notBlocked,
      'hooking': ProbeStatus.blocked,
      'debugger': ProbeStatus.inconclusive,
      'repackage': ProbeStatus.notBlocked,
    })));
    expect(rule(r, 'AEG-R01')!.status, RuleStatus.failed);
    expect(rule(r, 'AEG-R02')!.status, RuleStatus.passed);
    expect(rule(r, 'AEG-R03')!.status, RuleStatus.notApplicable);
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

  test('skipped / emulator error / dead baseline → not applicable with the reason', () async {
    final skipped = await audit(const ProbeOutcome.skipped('no emulator tools (run aegis setup)'));
    expect(rule(skipped, 'AEG-R01')!.status, RuleStatus.notApplicable);
    expect(rule(skipped, 'AEG-R01')!.note, contains('aegis setup'));

    final broken = await audit(ProbeOutcome.ran(
        report({'root': ProbeStatus.inconclusive}, emulatorError: 'emulator did not boot')));
    expect(rule(broken, 'AEG-R01')!.note, contains('did not boot'));

    final dead = await audit(ProbeOutcome.ran(report({}, baselineAlive: false)));
    expect(rule(dead, 'AEG-R04')!.note, contains('clean emulator'));
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
}
