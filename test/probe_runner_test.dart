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
  String? debuggerError;
  String? resignError;
  List<bool> aliveQueue = [];
  bool defaultAlive = true;
  int pidValue = 1234;
  String logcatText = '';
  final calls = <String>[];

  @override
  Future<String?> bootEmulator(
      {int timeoutSeconds = 420, void Function(String)? log, String? logPath}) async {
    calls.add('boot');
    return bootError;
  }

  @override
  Future<void> adbRoot() async => calls.add('root');

  @override
  Future<String?> install(String apk) async {
    calls.add('install');
    return installError;
  }

  @override
  Future<void> uninstall(String package) async {}
  @override
  Future<String> launch(String package) async {
    calls.add('launch');
    return '';
  }
  @override
  Future<int?> pidOf(String package) async => pidValue;
  @override
  Future<bool> isAlive(String package) async =>
      aliveQueue.isNotEmpty ? aliveQueue.removeAt(0) : defaultAlive;
  @override
  Future<int?> waitForProcess(String package, {int timeoutSeconds = 40}) async =>
      (aliveQueue.isNotEmpty ? aliveQueue.removeAt(0) : defaultAlive) ? pidValue : null;
  @override
  Future<void> clearLogcat() async {}
  @override
  Future<String> logcat() async => logcatText;
  @override
  Future<String?> startFridaServer() async {
    calls.add('frida-server');
    return fridaError;
  }

  @override
  Future<void> stopFridaServer() async => calls.add('stop-frida');

  @override
  Future<String?> fridaAttach(String package) async {
    calls.add('frida-attach');
    return null;
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

ProbeRunner runner(FakeDevice d) =>
    ProbeRunner(d, wait: Duration.zero, sleep: (_) async {});

Future<ProbeReport> run(FakeDevice d, {Set<String>? only}) =>
    runner(d).run(appPath: 'app.apk', package: 'com.x', workDir: '/tmp', only: only);

ProbeStatus statusOfId(ProbeReport r, String id) =>
    r.results.firstWhere((x) => x.check.id == id).status;

void main() {
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

  test('app dies on the clean emulator → baseline gate, all inconclusive', () async {
    final r = await run(FakeDevice()..aliveQueue = [false]);
    expect(r.baselineAlive, isFalse);
    expect(r.scored.every((x) => x.status == ProbeStatus.inconclusive), isTrue);
    expect(r.results.first.note, contains('emulator detection'));
  });

  test('a plain app blocks nothing → all notBlocked', () async {
    final r = await run(FakeDevice()); // defaultAlive true throughout
    expect(r.baselineAlive, isTrue);
    for (final id in ['root', 'debugger', 'hooking', 'repackage']) {
      expect(statusOfId(r, id), ProbeStatus.notBlocked, reason: id);
    }
  });

  test('root detection: app exits under root → blocked', () async {
    // only=root → isAlive order: baseline, root-before, root-after.
    final r = await run(FakeDevice()..aliveQueue = [true, true, false], only: {'root'});
    expect(statusOfId(r, 'root'), ProbeStatus.blocked);
  });

  test('a crash in logcat counts as blocked even if still alive', () async {
    final d = FakeDevice()
      ..pidValue = 9123
      ..logcatText = 'E AndroidRuntime: FATAL EXCEPTION: main\n'
          'E AndroidRuntime: Process: com.x, PID: 9123';
    final r = await run(d, only: {'hooking'});
    expect(statusOfId(r, 'hooking'), ProbeStatus.blocked);
    expect(d.calls, contains('frida-server'));
  });

  test('frida-server is stopped before the baseline and right after the Frida check', () async {
    final d = FakeDevice();
    await run(d, only: {'hooking', 'debugger'});
    final c = d.calls;
    // Stopped before anything is launched…
    expect(c.indexOf('stop-frida'), lessThan(c.indexOf('launch')));
    // …and again after the Frida check, before the debugger check.
    expect(c.lastIndexOf('stop-frida'), greaterThan(c.indexOf('frida-attach')));
    expect(c.lastIndexOf('stop-frida'), lessThan(c.indexOf('debugger')));
  });

  test('frida-server failing to start → hooking inconclusive', () async {
    final r = await run(FakeDevice()..fridaError = 'push failed', only: {'hooking'});
    expect(statusOfId(r, 'hooking'), ProbeStatus.inconclusive);
  });

  test('repackage: re-sign failure is inconclusive, not a pass', () async {
    final r = await run(FakeDevice()..resignError = 'apksigner missing', only: {'repackage'});
    expect(statusOfId(r, 'repackage'), ProbeStatus.inconclusive);
  });

  test('repackage: install-time Killing/signature noise is NOT a reaction', () async {
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
  });

  test('repackage: the app crashing with a signature check → blocked + integrity', () async {
    final d = FakeDevice()
      ..pidValue = 9123
      ..logcatText =
          '11-08 15:40:01.000  9123  9123 E AndroidRuntime: FATAL EXCEPTION: main\n'
          '11-08 15:40:01.000  9123  9123 E AndroidRuntime: Process: com.x, PID: 9123\n'
          '11-08 15:40:01.000  9123  9123 E AndroidRuntime: java.lang.SecurityException: signature mismatch';
    final r = await run(d, only: {'repackage'});
    final res = r.results.firstWhere((x) => x.check.id == 'repackage');
    expect(res.status, ProbeStatus.blocked);
    expect(res.note, contains('integrity'));
  });

  test('only-filter runs just the asked checks', () async {
    final r = await run(FakeDevice(), only: {'root'});
    expect(r.scored.map((x) => x.check.id), ['root']);
  });
}
