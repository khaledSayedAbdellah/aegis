import 'package:aegis/src/probe/device.dart';
import 'package:aegis/src/probe/probe_model.dart';
import 'package:aegis/src/probe/probe_runner.dart';
import 'package:test/test.dart';

/// A scripted emulator. [aliveQueue] feeds successive isAlive() calls; when it
/// runs out, [defaultAlive] is returned.
class FakeDevice implements ProbeDevice {
  String? bootError;
  String? installError;
  String? fridaError;
  String? attachError;
  bool rooted = false;
  int launches = 0;
  String? debuggerError;
  String? resignError;
  List<bool> aliveQueue = [];
  bool defaultAlive = true;
  int pidValue = 1234;
  String logcatText = '';
  String? fridaLog;
  final calls = <String>[];
  List<int?> pidReads = [];
  List<String?> exits = [];

  @override
  Future<String?> bootEmulator(
      {int timeoutSeconds = 420,
      void Function(String)? log,
      String? logPath}) async {
    calls.add('boot');
    return bootError;
  }

  @override
  Future<String?> setAdbRoot(bool enabled) async {
    calls.add(enabled ? 'root' : 'unroot');
    return null;
  }

  @override
  Future<bool> rootAvailable() async => rooted;
  @override
  Future<void> forceStop(String package) async => calls.add('force-stop');

  @override
  Future<String?> install(String apk) async {
    calls.add('install');
    return installError;
  }

  @override
  Future<String?> installApks(List<String> apks) async {
    calls.add('install-multiple');
    return installError;
  }

  @override
  Future<void> uninstall(String package) async {}
  @override
  Future<String> launch(String package) async {
    calls.add('launch');
    launches++;
    return '';
  }

  @override
  Future<int?> pidOf(String package) async =>
      pidReads.isEmpty ? pidValue : pidReads.removeAt(0);
  @override
  Future<bool> isAlive(String package) async =>
      aliveQueue.isNotEmpty ? aliveQueue.removeAt(0) : defaultAlive;
  @override
  Future<int?> waitForProcess(String package,
          {int timeoutSeconds = 40}) async =>
      (aliveQueue.isNotEmpty ? aliveQueue.removeAt(0) : defaultAlive)
          ? pidValue
          : null;
  @override
  Future<void> clearLogcat() async {}
  @override
  Future<String> logcat() async =>
      (calls.contains('frida-attach') ? fridaLog : null) ??
      (launches > 1 || rooted ? logcatText : '');

  @override
  Future<String?> exitInfo(String package) async =>
      exits.isEmpty ? null : exits.removeAt(0);

  @override
  Future<String?> startFridaServer() async {
    calls.add('frida-server');
    return fridaError;
  }

  @override
  Future<void> stopFridaServer() async => calls.add('stop-frida');

  @override
  Future<String?> fridaAttach(String package, Duration wait) async {
    calls.add('frida-attach');
    return attachError;
  }

  @override
  Future<String?> attachDebugger(String package) async {
    calls.add('debugger');
    return debuggerError;
  }

  @override
  Future<void> clearDebugApp() async {}
  @override
  Future<String?> resignWithNewKey(String apk, String out, String ks) async {
    calls.add('resign');
    return resignError;
  }
}

/// A scripted emulator that also has the automatic platform observers.
class ObservingDevice extends FakeDevice implements PlatformObserver {
  Map<String, Object?> control = {'verified': true};
  Map<String, Object?> instrumented = {};
  bool failControl = false;

  @override
  Future<Map<String, Object?>> platformObservation(
      String package, int pid) async {
    calls.add('observe');
    if (failControl) throw StateError('adb unavailable');
    return control;
  }

  @override
  Future<Map<String, Object?>> instrumentedPlatformObservation(
      String package) async {
    calls.add('observe-instrumented');
    return instrumented;
  }
}

ProbeRunner runner(FakeDevice d, [FakeDevice? root]) =>
    ProbeRunner(d, rootDevice: root, wait: Duration.zero, sleep: (_) async {});

Future<ProbeReport> run(FakeDevice d, {Set<String>? only, FakeDevice? root}) =>
    runner(d, root)
        .run(appPath: 'app.apk', package: 'com.x', workDir: '/tmp', only: only);

ProbeStatus statusOfId(ProbeReport r, String id) =>
    r.results.firstWhere((x) => x.check.id == id).status;

void main() {
  test('Frida uses the rooted device and leaves repackaging on the control',
      () async {
    final control = FakeDevice();
    final rooted = FakeDevice()
      ..fridaLog =
          '11-08 15:29:21.344  1234  1234 I AegisProbe: hooking blocked';
    final result =
        await run(control, root: rooted, only: {'hooking', 'repackage'});
    expect(statusOfId(result, 'hooking'), ProbeStatus.blocked);
    expect(rooted.calls,
        containsAllInOrder(['boot', 'install', 'launch', 'frida-attach']));
    expect(control.calls, isNot(contains('frida-attach')));
    expect(control.calls, isNot(contains('root')));
    expect(control.calls, contains('resign'));
    expect(rooted.calls, isNot(contains('resign')));
  });

  group('automatic observer attempts', () {
    test('a device without observers records none', () async {
      final r = await run(FakeDevice(), only: {'hooking'});
      expect(r.platformObserverAttempts, isEmpty);
    });
    test('the launch observer is recorded even when it fails', () async {
      final ok = await run(ObservingDevice(), only: {'repackage'});
      expect(ok.platformObserverAttempts, {'control'});
      expect(ok.platformObservations['verified'], isTrue);
      final failed =
          await run(ObservingDevice()..failControl = true, only: {'repackage'});
      expect(failed.platformObserverAttempts, {'control'});
      expect(failed.platformObservations, isEmpty);
    });
    test('the instrumented observer is recorded only with a Frida check',
        () async {
      final device = ObservingDevice();
      final r = await run(device, only: {'hooking'});
      expect(device.calls, contains('observe-instrumented'));
      expect(r.platformObserverAttempts, {'control', 'instrumented'});
      // It returned nothing, so the stock launch facts stay as they were.
      expect(r.platformObservations.containsKey('control'), isFalse);
    });
    test('a dead baseline starts no observer', () async {
      final r = await run(ObservingDevice()..aliveQueue = [false]);
      expect(r.platformObserverAttempts, isEmpty);
    });
  });

  test('boot failure → every scored check inconclusive', () async {
    final r = await run(FakeDevice()..bootError = 'no emulator');
    expect(r.baselineAlive, isFalse);
    expect(r.scored.every((x) => x.status == ProbeStatus.inconclusive), isTrue);
    expect(r.results.first.note, contains('no emulator'));
  });

  test('install failure → inconclusive', () async {
    final r = await run(FakeDevice()..installError = 'INSTALL_FAILED');
    expect(r.scored.every((x) => x.status == ProbeStatus.inconclusive), isTrue);
  });

  test('app dies on the clean emulator → baseline gate, all inconclusive',
      () async {
    final r = await run(FakeDevice()..aliveQueue = [false]);
    expect(r.baselineAlive, isFalse);
    expect(r.scored.every((x) => x.status == ProbeStatus.inconclusive), isTrue);
    expect(r.results.first.note, contains('control launch'));
  });

  test(
      'a plain APK yields process-level not-blocked verdicts for verified conditions',
      () async {
    final r = await run(FakeDevice(), root: FakeDevice()..rooted = true);
    expect(r.baselineAlive, isTrue);
    expect(
        r.notBlocked
            .where((result) => result.processOnly)
            .map((result) => result.check.id),
        unorderedEquals(['root', 'debugger', 'hooking', 'repackage']));
    expect(r.inconclusive, isEmpty);
    expect(r.notBlocked.length, 4);
  });

  test('conflicting app events stay inconclusive despite a live process',
      () async {
    final device = FakeDevice()
      ..fridaLog =
          '11-08 15:29:21.344  1234  1234 I AegisProbe: hooking blocked\n'
              '11-08 15:29:21.345  1234  1234 I AegisProbe: hooking not-blocked';
    final r = await run(device, only: {'hooking'});
    expect(statusOfId(r, 'hooking'), ProbeStatus.inconclusive);
    expect(r.scored.single.note, contains('conflicting outcomes'));
  });

  test('root requires a separate device and an app-specific verdict', () async {
    final control = FakeDevice();
    final rooted = FakeDevice()
      ..rooted = true
      ..logcatText =
          '11-08 15:29:21.344  1234  1234 I AegisProbe: root blocked';
    final r = await run(control, root: rooted, only: {'root'});
    expect(statusOfId(r, 'root'), ProbeStatus.blocked);
    expect(control.launches, 1);
    expect(rooted.launches, 1);
  });

  test('a rooted control invalidates the root comparison', () async {
    final r = await run(FakeDevice()..rooted = true, only: {'root'});
    expect(statusOfId(r, 'root'), ProbeStatus.inconclusive);
  });

  test('a fast startup self-exit under root is detected without an app event',
      () async {
    final rooted = FakeDevice()
      ..rooted = true
      ..aliveQueue = [false]
      ..pidReads = [null]
      ..logcatText = '11-08 15:29:21.344  99  99 I ActivityManager: '
          'Start proc 1234:com.x/u0a123'
      ..exits = [
        '',
        '  timestamp=2026-11-09 22:16:00.123 pid=1234 realUid=10014\n'
            '  process=com.x reason=1 (EXIT_SELF) subreason=0 (UNKNOWN) status=7',
      ];
    final r = await run(FakeDevice(), root: rooted, only: {'root'});
    expect(r.scored.single.status, ProbeStatus.blocked);
    expect(r.scored.single.processOnly, isTrue);
    expect(r.scored.single.evidence, contains('exited on its own'));
  });

  test('Android crash records do not count as a protective self-exit',
      () async {
    final d = FakeDevice()
      ..pidReads = [1234, null]
      ..exits = [
        '',
        '  timestamp=2026-11-09 22:16:00.123 pid=1234 realUid=10014\n'
            '  process=com.x reason=4 (CRASH) subreason=0 (UNKNOWN) status=0',
      ];
    final r = await run(d, only: {'repackage'});
    expect(r.scored.single.status, ProbeStatus.inconclusive);
  });

  test('a crash without an app verdict stays inconclusive', () async {
    final d = FakeDevice()
      ..pidValue = 9123
      ..logcatText = 'E AndroidRuntime: FATAL EXCEPTION: main\n'
          'E AndroidRuntime: Process: com.x, PID: 9123';
    final r = await run(d, only: {'hooking'});
    expect(statusOfId(r, 'hooking'), ProbeStatus.inconclusive);
    expect(d.calls, contains('frida-server'));
  });

  test(
      'frida-server is stopped before the baseline and right after the Frida check',
      () async {
    final d = FakeDevice();
    await run(d, only: {'hooking', 'debugger'});
    final c = d.calls;
    // Stopped before anything is launched…
    expect(c.indexOf('stop-frida'), lessThan(c.indexOf('launch')));
    // …and again after the Frida check, before the debugger check.
    expect(c.lastIndexOf('stop-frida'), greaterThan(c.indexOf('frida-attach')));
    expect(c.indexOf('debugger'), lessThan(c.indexOf('frida-attach')));
  });

  test('frida-server failing to start → hooking inconclusive', () async {
    final r =
        await run(FakeDevice()..fridaError = 'push failed', only: {'hooking'});
    expect(statusOfId(r, 'hooking'), ProbeStatus.inconclusive);
  });

  test('a failed Frida attachment cannot produce a verdict', () async {
    final d = FakeDevice()
      ..attachError = 'transport disconnected'
      ..logcatText =
          '11-08 15:29:21.344  1234  1234 I AegisProbe: hooking blocked';
    final r = await run(d, only: {'hooking'});
    expect(statusOfId(r, 'hooking'), ProbeStatus.inconclusive);
    expect(r.scored.single.note, contains('transport disconnected'));
  });

  test('the app can report an allowed operation after a verified attachment',
      () async {
    final d = FakeDevice()
      ..logcatText =
          '11-08 15:29:21.344  1234  1234 I AegisProbe: hooking not-blocked';
    final r = await run(d, only: {'hooking'});
    expect(statusOfId(r, 'hooking'), ProbeStatus.notBlocked);
  });

  test('repackage: re-sign failure is inconclusive, not a pass', () async {
    final r = await run(FakeDevice()..resignError = 'apksigner missing',
        only: {'repackage'});
    expect(statusOfId(r, 'repackage'), ProbeStatus.inconclusive);
  });

  test('repackage: install-time Killing/signature noise is NOT a reaction',
      () async {
    // The classic false positive: the re-install logs a system kill and a
    // PackageManager signature mismatch, but the app itself runs fine.
    final d = FakeDevice()
      ..pidValue = 9123
      ..logcatText =
          '11-08 15:40:00.000   564   678 I ActivityManager: Killing 9123:com.x/u0a1 (adj 0): due to install\n'
              '11-08 15:40:00.100   900   900 W PackageManager: Package com.x signatures do not match; ignoring!\n'
              '11-08 15:40:01.000  9123  9123 I flutter: app running';
    final r = await run(d, only: {'repackage'});
    expect(statusOfId(r, 'repackage'), ProbeStatus.notBlocked);
    expect(r.scored.single.processOnly, isTrue);
  });

  test('repackage: a signature-related crash alone is inconclusive', () async {
    final d = FakeDevice()
      ..pidValue = 9123
      ..logcatText =
          '11-08 15:40:01.000  9123  9123 E AndroidRuntime: FATAL EXCEPTION: main\n'
              '11-08 15:40:01.000  9123  9123 E AndroidRuntime: Process: com.x, PID: 9123\n'
              '11-08 15:40:01.000  9123  9123 E AndroidRuntime: java.lang.SecurityException: signature mismatch';
    final r = await run(d, only: {'repackage'});
    final res = r.results.firstWhere((x) => x.check.id == 'repackage');
    expect(res.status, ProbeStatus.inconclusive);
    expect(res.note, contains('integrity'));
  });

  test('only-filter runs just the asked checks', () async {
    final r = await run(FakeDevice(), only: {'root'});
    expect(r.scored.map((x) => x.check.id), ['root']);
  });
}
