import 'package:aegis/src/probe/observation.dart';
import 'package:aegis/src/probe/probe_model.dart';
import 'package:test/test.dart';

void main() {
  test('matches app events by process and check and detects conflicts', () {
    const event = '11-08 15:29:21.344  91  91 I AegisProbe: root blocked';
    expect(appProbeVerdict(event, 'com.app', 'root', pid: 91), ProbeStatus.blocked);
    expect(appProbeVerdict(event, 'com.app', 'root', pid: 92), isNull);
    expect(appProbeVerdict(event, 'com.app', 'hooking', pid: 91), isNull);
    expect(appProbeVerdict('$event\n${event.replaceAll('blocked', 'not-blocked')}',
        'com.app', 'root', pid: 91), ProbeStatus.inconclusive);
  });

  test('self-exit evidence requires a fresh record for the exact process', () {
    const record = '  timestamp=2026-11-09 22:16:00.123 pid=91 realUid=10014\n'
        '  process=com.app reason=1 (EXIT_SELF) subreason=0 (UNKNOWN) status=7';
    expect(observedSelfExit('', record, 'com.app', 91), isTrue);
    expect(observedSelfExit(record, record, 'com.app', 91), isFalse);
    expect(observedSelfExit('', record, 'com.app', 92), isFalse);
    expect(observedSelfExit('', record, 'com.app.other', 91), isFalse);
    expect(observedSelfExit('', record.replaceFirst('reason=1', 'reason=4'), 'com.app', 91), isFalse);
  });

  group('logcatShowsAppDeath (app-scoped)', () {
    const pkg = 'com.example.app';
    // threadtime line: "date time PID TID LEVEL Tag: msg"
    String tt(int pid, String rest) => '11-08 15:29:21.344  $pid  $pid $rest';

    test('a FATAL block for the package counts', () {
      final log = '${tt(9123, 'E AndroidRuntime: FATAL EXCEPTION: main')}\n'
          '${tt(9123, 'E AndroidRuntime: Process: com.example.app, PID: 9123')}';
      expect(logcatShowsAppDeath(log, pid: 9123, package: pkg), isTrue);
    });

    test('ActivityManager killing the app by package counts', () {
      final log = tt(564, 'I ActivityManager: Killing 9123:com.example.app/u0a123 (adj 0)');
      expect(logcatShowsAppDeath(log, pid: 9123, package: pkg), isTrue);
    });

    test('a FATAL in another app does not count', () {
      final log = '${tt(5555, 'E AndroidRuntime: FATAL EXCEPTION: main')}\n'
          '${tt(5555, 'E AndroidRuntime: Process: com.other.app, PID: 5555')}';
      expect(logcatShowsAppDeath(log, pid: 9123, package: pkg), isFalse);
    });

    test('an install-time Killing of ANOTHER package is ignored', () {
      final log = tt(564, 'I ActivityManager: Killing 91230:com.other/u0a1 (adj 0)');
      expect(logcatShowsAppDeath(log, pid: 9123, package: pkg), isFalse);
    });

    test('a Killing of the app "due to install" is ignored (OS, not the app)', () {
      final log = tt(564, 'I ActivityManager: Killing 9123:com.example.app/u0a123 (adj 0): due to install');
      expect(logcatShowsAppDeath(log, pid: 9123, package: pkg), isFalse);
    });
  });

  group('classifyRepackageReaction (app lines only)', () {
    const pkg = 'com.example.app';
    String tt(int pid, String rest) => '11-08 15:29:21.344  $pid  $pid $rest';

    test('the app logging a Google API key error → bound service', () {
      final log = tt(9123, 'E Maps: Authorization failure. API_KEY is not authorized');
      expect(classifyRepackageReaction(log, package: pkg, pid: 9123), CrashCause.boundService);
    });

    test('the app reading its own signature → integrity check', () {
      final log = tt(9123, 'D Guard: getPackageInfo GET_SIGNATURES; signature mismatch');
      expect(classifyRepackageReaction(log, package: pkg, pid: 9123), CrashCause.integrityCheck);
    });

    test('a signature line from the INSTALLER (not the app) is ignored', () {
      // PackageManager / Play Protect under system pids, not the app's.
      final log = '${tt(564, 'W PackageManager: Package com.example.app signatures do not match')}\n'
          '${tt(1200, 'I PlayProtect: verifying signingInfo for com.example.app')}';
      expect(classifyRepackageReaction(log, package: pkg, pid: 9123), CrashCause.unknown);
    });

    test('both kinds in the app log → unknown', () {
      final log = tt(9123, 'E x: getPackageInfo ... API_KEY not authorized');
      expect(classifyRepackageReaction(log, package: pkg, pid: 9123), CrashCause.unknown);
    });
  });

  group('appStarted / appPids', () {
    const pkg = 'com.example.app';
    test('Start proc gives the pid even if the passed pid is stale', () {
      const log = '11-08 15:29:21.344   564   678 I ActivityManager: Start proc '
          '6301:com.example.app/u0a123 for next-top-activity';
      expect(appStarted(log, pkg), isTrue);
      expect(appPids(log, pkg), contains(6301));
    });
    test('no trace of the app → not started', () {
      expect(appStarted('11-08 … I ActivityManager: idle', pkg), isFalse);
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
