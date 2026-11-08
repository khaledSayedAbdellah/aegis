import 'package:aegis/src/probe/observation.dart';
import 'package:aegis/src/probe/probe_model.dart';
import 'package:test/test.dart';

void main() {
  group('statusOf', () {
    test('alive before and after, no crash → notBlocked', () {
      expect(
          statusOf(const Observation(setupOk: true, aliveBefore: true, aliveAfter: true)),
          ProbeStatus.notBlocked);
    });

    test('gone after the condition → blocked', () {
      expect(
          statusOf(const Observation(setupOk: true, aliveBefore: true, aliveAfter: false)),
          ProbeStatus.blocked);
    });

    test('still running but crash logged → blocked', () {
      expect(
          statusOf(const Observation(
              setupOk: true, aliveBefore: true, aliveAfter: true, appDeathLogged: true)),
          ProbeStatus.blocked);
    });

    test('setup failed or never alive → inconclusive', () {
      expect(statusOf(const Observation(setupOk: false, aliveBefore: true, aliveAfter: true)),
          ProbeStatus.inconclusive);
      expect(statusOf(const Observation(setupOk: true, aliveBefore: false, aliveAfter: false)),
          ProbeStatus.inconclusive);
      expect(statusOf(const Observation.inconclusive()), ProbeStatus.inconclusive);
    });
  });

  group('logcatShowsAppDeath', () {
    const pkg = 'com.example.app';
    test('matches a FATAL for the package', () {
      const log = 'E AndroidRuntime: FATAL EXCEPTION: main\n'
          'E AndroidRuntime: Process: com.example.app, PID: 9123';
      expect(logcatShowsAppDeath(log, pid: 9123, package: pkg), isTrue);
    });

    test('matches ActivityManager killing the app by pid', () {
      const log = 'I ActivityManager: Killing 9123:com.example.app/u0a123 (adj 0)';
      expect(logcatShowsAppDeath(log, pid: 9123, package: pkg), isTrue);
    });

    test('ignores a crash in another app', () {
      const log = 'E AndroidRuntime: FATAL EXCEPTION: main\n'
          'E AndroidRuntime: Process: com.other.app, PID: 5555';
      expect(logcatShowsAppDeath(log, pid: 9123, package: pkg), isFalse);
    });

    test('a pid substring does not count', () {
      // 91230 contains "9123" but is a different pid, and no package mention.
      const log = 'I ActivityManager: Killing 91230:com.other/u0a1 (adj 0)';
      expect(logcatShowsAppDeath(log, pid: 9123, package: pkg), isFalse);
    });
  });

  test('ProbeReport groups scored results, excludes baseline', () {
    final report = ProbeReport(app: 'app.apk', baselineAlive: true, results: [
      ProbeResult(checkById('baseline'), ProbeStatus.notBlocked),
      ProbeResult(checkById('root'), ProbeStatus.blocked),
      ProbeResult(checkById('hooking'), ProbeStatus.notBlocked),
      ProbeResult(checkById('repackage'), ProbeStatus.inconclusive),
    ]);
    expect(report.scored.length, 3);
    expect(report.blocked.map((r) => r.check.id), ['root']);
    expect(report.notBlocked.map((r) => r.check.id), ['hooking']);
    expect(report.inconclusive.map((r) => r.check.id), ['repackage']);
  });
}
