import 'package:aegis/src/probe/probe_model.dart';
import 'package:aegis/src/probe/probe_report.dart';
import 'package:test/test.dart';

ProbeReport report(Map<String, ProbeStatus> scored, {bool baselineAlive = true}) =>
    ProbeReport(app: 'build/app-release.apk', baselineAlive: baselineAlive, results: [
      ProbeResult(checkById('baseline'),
          baselineAlive ? ProbeStatus.notBlocked : ProbeStatus.inconclusive),
      for (final e in scored.entries) ProbeResult(checkById(e.key), e.value),
    ]);

void main() {
  group('exit code', () {
    test('baseline dead → 2', () {
      expect(
          probeExitCode(report({'root': ProbeStatus.inconclusive}, baselineAlive: false),
              resilienceProfile: true),
          2);
    });

    test('everything inconclusive → 2', () {
      expect(
          probeExitCode(report({'root': ProbeStatus.inconclusive, 'hooking': ProbeStatus.inconclusive}),
              resilienceProfile: true),
          2);
    });

    test('a gap under a resilience profile → 1', () {
      expect(
          probeExitCode(report({'root': ProbeStatus.blocked, 'hooking': ProbeStatus.notBlocked}),
              resilienceProfile: true),
          1);
    });

    test('the same gap without a resilience profile → 0', () {
      expect(
          probeExitCode(report({'hooking': ProbeStatus.notBlocked}), resilienceProfile: false),
          0);
    });

    test('automatic continued execution counts as a scoped MAS-R finding', () {
      final observed = report({});
      observed.results.add(ProbeResult(
          checkById('root'), ProbeStatus.notBlocked, processOnly: true));
      expect(probeExitCode(observed, resilienceProfile: true), 1);
      expect(renderProbe(observed, resilienceProfile: true),
          contains('No block observed: 1'));
    });

    test('all reacted → 0', () {
      expect(
          probeExitCode(report({'root': ProbeStatus.blocked, 'hooking': ProbeStatus.blocked}),
              resilienceProfile: true),
          0);
    });
  });

  group('render', () {
    test('shows marks, MASVS tags and a profile finding', () {
      final out = renderProbe(
          report({'root': ProbeStatus.blocked, 'hooking': ProbeStatus.notBlocked}),
          resilienceProfile: true);
      expect(out, contains('app-release.apk'));
      expect(out, contains('MASVS-RESILIENCE-4'));
      expect(out, contains('✅'));
      expect(out, contains('❌'));
      expect(out, contains('this is a finding'));
    });

    test('a gap is informational without a resilience profile', () {
      final out = renderProbe(report({'hooking': ProbeStatus.notBlocked}),
          resilienceProfile: false);
      expect(out, contains('Informational'));
    });

    test('baseline dead explains why, in Arabic too', () {
      final out = renderProbe(report({'root': ProbeStatus.inconclusive}, baselineAlive: false),
          lang: 'ar', resilienceProfile: true);
      expect(out, contains('إيموليتر'));
    });
  });
}
