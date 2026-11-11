/// The one place `aegis probe` touches the emulator and the SDK tools
/// (doc/plans/probe.md §5). Everything goes through [Host], so the runner can
/// be driven by a fake. Tool paths come from the toolchain (verified against
/// disk; `~/.aegis/tools.json` is only a cache).
///
/// `Device` sets up standard OWASP MASTG conditions on the developer's own
/// app and reads back what happened. It does not try to defeat or evade any
/// particular protection — it observes whether the app reacts.
library;

import 'dart:convert';
import 'dart:isolate';
import 'package:path/path.dart' as p;
import '../security/android_platform.dart';

import 'host.dart';
import 'jdwp.dart';
import 'pins.dart' as pins;
import 'toolchain.dart';

/// Resolved paths of the tools the probe drives.
class ProbeTools {
  ProbeTools({
    this.adb,
    this.emulator,
    this.apksigner,
    this.javaHome,
    this.keytool,
    this.frida,
    this.fridaServer,
    required this.avdName,
  });

  final String? adb;
  final String? emulator;
  final String? apksigner;
  final String? javaHome;
  final String? keytool;
  final String? frida;
  final String? fridaServer;
  final String avdName;

  /// Tools needed by the selected checks.
  List<String> missing({Set<String>? only}) => [
        if (adb == null) 'adb',
        if (emulator == null) 'emulator',
        if ((only == null || only.contains('repackage')) && apksigner == null) 'apksigner',
        if ((only == null || only.contains('hooking')) && frida == null) 'frida',
        if ((only == null || only.contains('hooking')) && fridaServer == null) 'frida-server',
        if ((only == null || only.contains('repackage')) && keytool == null) 'keytool',
      ];

  static Future<ProbeTools> resolve(Host host, Toolchain t) async {
    final root = (await t.findSdkRoot())?.path;
    final java = (await t.findJavaHome())?.home;
    final buildTools = root == null ? null : (await t.checkBuildTools(root)).path;
    String exe(String n) => host.os == 'windows' ? '$n.exe' : n;
    String bat(String n) => host.os == 'windows' ? '$n.bat' : n;
    final ctx = host.os == 'windows' ? p.windows : p.posix;
    String? under(String? base, List<String> parts) =>
        base == null ? null : ctx.joinAll([base, ...parts]);
    String? ifExists(String? path) =>
        path != null && host.fileExists(path) ? path : null;

    return ProbeTools(
      adb: ifExists(under(root, ['platform-tools', exe('adb')])),
      emulator: ifExists(under(root, ['emulator', exe('emulator')])),
      apksigner: ifExists(buildTools == null ? null : ctx.join(buildTools, bat('apksigner'))),
      javaHome: java,
      keytool: ifExists(under(java, ['bin', exe('keytool')])),
      frida: ifExists(t.venvExe('frida')),
      fridaServer: ifExists(t.fridaServerPath),
      avdName: pins.avdName,
    );
  }
}

/// What the runner needs from the device, so it can be driven by a fake.
abstract interface class ProbeDevice {
  Future<String?> bootEmulator(
      {int timeoutSeconds, void Function(String)? log, String? logPath});
  Future<String?> setAdbRoot(bool enabled);
  Future<bool> rootAvailable();
  Future<String?> install(String apk);
  Future<String?> installApks(List<String> apks);
  Future<void> uninstall(String package);
  Future<void> forceStop(String package);
  Future<String> launch(String package);
  Future<int?> pidOf(String package);
  Future<bool> isAlive(String package);
  Future<int?> waitForProcess(String package, {int timeoutSeconds});
  Future<void> clearLogcat();
  Future<String> logcat();
  Future<String?> exitInfo(String package);
  Future<String?> startFridaServer();
  Future<void> stopFridaServer();
  Future<String?> fridaAttach(String package, Duration wait);
  Future<String?> attachDebugger(String package);
  Future<void> clearDebugApp();
  Future<String?> resignWithNewKey(String apk, String outApk, String keystore);
}

/// Automatic launch-only inspection of the running app. Kept apart from
/// [ProbeDevice] so resilience checks do not depend on it.
abstract interface class PlatformObserver {
  Future<Map<String, Object?>> platformObservation(String package, int pid);
  Future<Map<String, Object?>> instrumentedPlatformObservation(String package);
}

/// A finished adb/emulator/frida action. Thin wrapper over [Proc].
class Device implements ProbeDevice, PlatformObserver {
  Device(this.host, this.tools, {String? avdName}) : avdName = avdName ?? tools.avdName;
  final String avdName;
  final Host host;
  final ProbeTools tools;

  String? _serial;
  JdwpSession? _debugger;
  int? _debuggerPort;

  List<String> _adb(List<String> args) {
    final serial = _serial;
    if (serial == null) throw StateError('No verified probe emulator is selected');
    return [tools.adb!, '-s', serial, ...args];
  }

  Future<void> _selectEmulator() async {
    final devices = await _run([tools.adb!, 'devices']);
    if (devices == null || !devices.ok) return;
    final matches = <String>[];
    for (final line in devices.stdout.split('\n')) {
      final match = RegExp(r'^(emulator-\d+)\s+device\s*$').firstMatch(line);
      if (match == null) continue;
      final serial = match[1]!;
      final name = await _run([tools.adb!, '-s', serial, 'emu', 'avd', 'name']);
      if (name?.ok == true && name!.out.split('\n').first.trim() == avdName) {
        matches.add(serial);
      }
    }
    if (matches.length > 1) throw StateError('Multiple $avdName emulators are connected');
    _serial = matches.firstOrNull;
  }

  Future<Proc?> _run(List<String> cmd,
          {Duration timeout = const Duration(seconds: 30)}) =>
      host.run(cmd.first, cmd.sublist(1), timeout: timeout);

  /// Automatic, noninteractive inspection of the currently running control app.
  @override
  Future<Map<String, Object?>> platformObservation(String package, int pid) async {
    if (await pidOf(package) != pid) return {};
    final windows = await _run(_adb(['shell', 'dumpsys', 'window', 'windows']));
    if (windows?.ok != true || windows!.stdout.length > 2 * 1024 * 1024) return {};
    final dump = '/data/local/tmp/aegis-platform-$pid.xml';
    String? hierarchy;
    try {
      final saved = await _run(_adb(['shell', 'uiautomator', 'dump', dump]), timeout: const Duration(seconds: 15));
      if (saved?.ok == true) {
        final read = await _run(_adb(['shell', 'cat', dump]));
        if (read?.ok == true && read!.stdout.length <= 2 * 1024 * 1024) hierarchy = read.stdout;
      }
    } finally {
      await _run(_adb(['shell', 'rm', '-f', dump]));
    }
    if (await pidOf(package) != pid) return {};
    final facts = inspectAndroidPlatform(package, windows.stdout, hierarchy);
    final shot = '/data/local/tmp/aegis-platform-$pid.png';
    try {
      final captured = await _run(_adb(['shell', 'screencap', '-p', shot]), timeout: const Duration(seconds: 15));
      final size = await _run(_adb(['shell', 'stat', '-c', '%s', shot]));
      final length = int.tryParse(size?.out ?? '');
      if (captured?.ok == true && length != null && length >= 24 && length <= 32 * 1024 * 1024) {
        (facts['screen'] as Map)['screenshotsCaptured'] = 1;
      }
    } finally { await _run(_adb(['shell', 'rm', '-f', shot])); }
    return {...facts,
      'verified': true, 'scope': 'launch-only', 'instrumented': false};
  }

  @override
  Future<Map<String, Object?>> instrumentedPlatformObservation(String package) async {
    final pid = await pidOf(package);
    if (pid == null || tools.frida == null) return {};
    final uri = await Isolate.resolvePackageUri(Uri.parse('package:aegis/src/security/android_platform_observer.py'));
    if (uri == null) return {};
    final forwarded = await _run(_adb(['forward','tcp:0','tcp:27042']));
    final port = int.tryParse(forwarded?.out ?? '');
    if (forwarded?.ok != true || port == null) return {};
    try {
      final python = p.join(p.dirname(tools.frida!), host.os == 'windows' ? 'python.exe' : 'python');
      final result = await host.run(python, [uri.toFilePath(), '$port', '$pid', package], timeout: const Duration(seconds: 30));
      if (result?.ok != true || result!.stdout.length > 1024 * 1024 || await pidOf(package) != pid) return {};
      final value = jsonDecode(result.out);
      if (value is! Map<String, dynamic> || value['verified'] != true || value['pid'] != pid || value['bundle'] != package) return {};
      return value;
    } catch (_) { return {}; }
    finally { await _run(_adb(['forward','--remove','tcp:$port'])); }
  }

  // --- emulator -----------------------------------------------------------

  /// Boots the `aegis-probe` AVD headless and waits for it to finish booting.
  /// The emulator runs for the whole probe, so it is started detached (never
  /// awaited) and boot is detected by polling. Returns null on success.
  @override
  Future<String?> bootEmulator(
      {int timeoutSeconds = 420, void Function(String)? log, String? logPath}) async {
    if (tools.emulator == null || tools.adb == null) return 'emulator or adb not found';
    await _selectEmulator();
    if (await _bootCompleted()) {
      log?.call('emulator already running');
      return null;
    }
    log?.call('starting the emulator…');
    if (_serial == null) {
      final available = await _run([tools.emulator!, '-list-avds']);
      if (available?.ok != true || !available!.out.split(RegExp(r'\s+')).contains(avdName)) {
        return 'AVD $avdName is unavailable';
      }
      await host.spawn(
        tools.emulator!,
        [
          '-avd', avdName,
          '-no-window', '-no-snapshot', '-no-boot-anim',
          '-gpu', 'swiftshader_indirect', '-netdelay', 'none', '-no-audio',
        ],
        logPath: logPath);
    }
    for (var i = 0; i * 3 < timeoutSeconds; i++) {
      await Future<void>.delayed(const Duration(seconds: 3));
      if (_serial == null) await _selectEmulator();
      if (await _bootCompleted()) {
        log?.call('emulator booted');
        return null;
      }
      if (i > 0 && i % 10 == 0) log?.call('still booting… (${i * 3}s)');
    }
    // Timed out: say what adb sees and the tail of the emulator's own output.
    final devices = await _run([tools.adb!, 'devices']);
    final buf = StringBuffer('emulator did not finish booting in ${timeoutSeconds}s');
    if (devices != null) buf.write('\n  adb devices: ${devices.out.replaceAll('\n', ' ')}');
    if (logPath != null && host.fileExists(logPath)) {
      final tail = host.readText(logPath).trim().split('\n');
      final last = tail.length > 6 ? tail.sublist(tail.length - 6) : tail;
      if (last.join().isNotEmpty) buf.write('\n  emulator log:\n    ${last.join('\n    ')}');
    }
    return buf.toString();
  }

  /// True once `sys.boot_completed` is 1 (adb returns non-zero while there is
  /// no device, so this stays false until the emulator is up).
  Future<bool> _bootCompleted() async {
    if (_serial == null) return false;
    final r = await _run(_adb(['shell', 'getprop', 'sys.boot_completed']));
    return r != null && r.ok && r.out.trim() == '1';
  }

  /// Switches adbd privileges and verifies the effective shell UID.
  @override
  Future<String?> setAdbRoot(bool enabled) async {
    final action = enabled ? 'root' : 'unroot';
    final command = await _run(_adb([action]));
    if (command?.ok != true) return 'adb $action failed: ${command?.text ?? 'adb unavailable'}';
    for (var i = 0; i < 10; i++) {
      final uid = await _run(_adb(['shell', 'id', '-u']));
      final number = int.tryParse(uid?.out ?? '');
      if (uid?.ok == true && number != null && (number == 0) == enabled) return null;
      await Future<void>.delayed(const Duration(milliseconds: 500));
    }
    return 'Could not verify adb $action';
  }

  @override
  Future<bool> rootAvailable() async {
    final result = await _run(_adb(['shell',
      r'if [ "$(id -u)" = 0 ] || [ "$(su 0 id -u 2>/dev/null)" = 0 ]; '
      'then echo root; else echo shell; fi']));
    if (result?.ok != true || !{'root', 'shell'}.contains(result!.out)) {
      throw StateError('Could not verify root availability');
    }
    return result.out == 'root';
  }

  // --- app lifecycle ------------------------------------------------------

  @override
  Future<String?> install(String apk) => installApks([apk]);

  @override
  Future<String?> installApks(List<String> apks) async {
    final command = apks.length == 1 ? 'install' : 'install-multiple';
    final r = await _run(_adb([command, '-r', '-t', ...apks]),
        timeout: const Duration(minutes: 2));
    if (r == null) return 'could not run adb';
    return r.ok ? null : 'adb $command failed: ${r.text.trim()}';
  }

  Future<int> sdkVersion() async {
    final result = await _run(_adb(['shell', 'getprop', 'ro.build.version.sdk']));
    final version = int.tryParse(result?.out ?? '');
    if (result?.ok != true || version == null || version < 1) {
      throw const FormatException('Could not read the emulator SDK version.');
    }
    return version;
  }

  Future<void> extractApkSet(String bundletool, String archive, String directory) async {
    final serial = _serial;
    final javaHome = tools.javaHome;
    if (serial == null || javaHome == null) {
      throw StateError('A verified emulator and Java are required to extract an APK set');
    }
    final path = host.os == 'windows' ? p.windows : p.posix;
    final java = path.join(javaHome, 'bin', host.os == 'windows' ? 'java.exe' : 'java');
    final spec = path.join(directory, 'device.json');
    host.mkdirs(directory);
    Future<void> bundle(List<String> args) async {
      final result = await _run([java, '-jar', bundletool, ...args],
          timeout: const Duration(minutes: 2));
      if (result?.ok != true) {
        throw FormatException('bundletool ${args.first} failed: ${result?.text ?? 'could not run Java'}');
      }
    }

    await bundle(['get-device-spec', '--adb=${tools.adb}', '--device-id=$serial', '--output=$spec']);
    await bundle(['extract-apks', '--apks=$archive', '--device-spec=$spec', '--output-dir=$directory']);
  }

  @override
  Future<void> uninstall(String package) async =>
      _run(_adb(['uninstall', package]));

  @override
  Future<void> forceStop(String package) async {
    final result = await _run(_adb(['shell', 'am', 'force-stop', package]));
    if (result?.ok != true) throw StateError('Could not stop $package');
  }

  /// Launches the app's main activity. Resolves the LAUNCHER activity and
  /// starts it with `am start -W` (which prints `Status: ok` or `Error:`),
  /// falling back to monkey. Returns the launcher's own output.
  @override
  Future<String> launch(String package) async {
    final resolve = await _run(_adb([
      'shell', 'cmd', 'package', 'resolve-activity', '--brief',
      '-a', 'android.intent.action.MAIN',
      '-c', 'android.intent.category.LAUNCHER', package,
    ]));
    String? component;
    if (resolve != null && resolve.ok) {
      for (final line in resolve.out.split('\n')) {
        final t = line.trim();
        if (t.startsWith('$package/') && RegExp(r'^[A-Za-z0-9_.$/]+$').hasMatch(t)) {
          component = t;
          break;
        }
      }
    }
    if (component == null) {
      final m = await _run(_adb(['shell', 'monkey', '-p', package, '1']));
      return 'monkey: ${m?.text.trim() ?? 'failed'}';
    }
    final start = await _run(_adb(['shell', 'am', 'start', '-W', '-n', "'$component'"]));
    return 'am start $component → ${start?.text.trim() ?? 'failed'}';
  }

  /// The app's pid, or null when it isn't running. Falls back to `ps` when
  /// `pidof` is unavailable or empty.
  @override
  Future<int?> pidOf(String package) async {
    final r = await _run(_adb(['shell', 'pidof', package]));
    if (r != null && r.ok) {
      final pid = int.tryParse(r.out.trim().split(RegExp(r'\s+')).first);
      if (pid != null) return pid;
    }
    final ps = await _run(_adb(['shell', 'ps', '-A']));
    if (ps != null && ps.ok) {
      for (final line in ps.stdout.split('\n')) {
        final cols = line.trim().split(RegExp(r'\s+'));
        if (cols.length >= 2 && cols.last == package) {
          final pid = int.tryParse(cols[1]);
          if (pid != null) return pid;
        }
      }
    }
    if (ps?.ok != true) throw StateError('Could not query the process for $package');
    return null;
  }

  @override
  Future<bool> isAlive(String package) async => (await pidOf(package)) != null;

  /// Polls until the app's process appears, or null after [timeoutSeconds].
  /// A first launch after install can take much longer than a single check.
  @override
  Future<int?> waitForProcess(String package, {int timeoutSeconds = 40}) async {
    for (var i = 0; i * 2 < timeoutSeconds; i++) {
      final pid = await pidOf(package);
      if (pid != null) return pid;
      await Future<void>.delayed(const Duration(seconds: 2));
    }
    return null;
  }

  @override
  Future<void> clearLogcat() async {
    final result = await _run(_adb(['logcat', '-c']));
    if (result?.ok != true) throw StateError('Could not clear logcat');
  }

  /// The current logcat buffer (`-d` dumps and exits).
  @override
  Future<String> logcat() async {
    final r = await _run(_adb(['logcat', '-d', '-v', 'threadtime']));
    if (r?.ok != true) throw StateError('Could not read logcat');
    return r!.stdout;
  }

  // --- conditions ---------------------------------------------------------

  /// Pushes frida-server to the device and starts it in the background.
  /// Returns null on success.
  @override
  Future<String?> startFridaServer() async {
    if (tools.fridaServer == null) return 'frida-server not found';
    const remote = '/data/local/tmp/frida-server';
    final push = await _run(_adb(['push', tools.fridaServer!, remote]));
    if (push == null || !push.ok) return 'adb push failed: ${push?.text.trim()}';
    final chmod = await _run(_adb(['shell', 'chmod', '755', remote]));
    if (chmod?.ok != true) return 'Could not make frida-server executable';
    final start = await _run(_adb(['shell', 'nohup $remote >/dev/null 2>&1 &']));
    if (start?.ok != true) return 'Could not start frida-server';
    for (var i = 0; i < 10; i++) {
      final server = await _run(_adb(['shell', 'pidof', 'frida-server']));
      if (server?.ok == true && server!.out.isNotEmpty) return null;
      await Future<void>.delayed(const Duration(milliseconds: 500));
    }
    return 'frida-server did not start';
  }

  @override
  Future<String?> exitInfo(String package) async {
    final result = await _run(_adb(['shell', 'dumpsys', 'activity', 'exit-info', package]));
    return result?.ok == true ? result!.stdout : null;
  }

  @override
  Future<String?> fridaAttach(String package, Duration wait) async {
    if (tools.frida == null || _serial == null) return 'Frida or the selected emulator is unavailable';
    final pid = await pidOf(package);
    if (pid == null) return 'App process is unavailable for Frida';
    final forward = await _run(_adb(['forward', 'tcp:0', 'tcp:27042']));
    final port = int.tryParse(forward?.out ?? '');
    if (forward?.ok != true || port == null) return 'Could not forward the Frida server port';
    try {
      const marker = 'AEGIS_FRIDA_ATTACHED';
      final seconds = wait.inSeconds.clamp(1, 60).toString();
      final result = await host.run(tools.frida!, [
        '-H', '127.0.0.1:$port', '-p', '$pid', '-q', '-t', seconds,
        '-e', 'console.log("$marker")',
      ], timeout: wait + const Duration(seconds: 30));
      if (result?.stdout.split('\n').any((line) => line.trim() == marker) == true) return null;
      return 'Frida attachment could not be verified: ${result?.text ?? 'Frida unavailable'}';
    } finally {
      await _run(_adb(['forward', '--remove', 'tcp:$port']));
    }
  }

  @override
  Future<String?> attachDebugger(String package) async {
    final pid = await pidOf(package);
    if (pid == null) return 'App process is unavailable for JDWP';
    var error = 'Could not forward the app JDWP port';
    // ADB can allocate the forward before ART has registered its transport.
    // Reopen it on a failed handshake instead of keeping a stale connection.
    for (var attempt = 0; attempt < 3; attempt++) {
      await Future<void>.delayed(const Duration(seconds: 1));
      if (await pidOf(package) != pid) return 'App process changed before JDWP attached';
      final forward = await _run(_adb(['forward', 'tcp:0', 'jdwp:$pid']));
      final port = int.tryParse(forward?.out ?? '');
      if (forward?.ok != true || port == null) continue;
      _debuggerPort = port;
      try {
        _debugger = await JdwpSession.connect(port);
        return null;
      } catch (e) {
        error = 'JDWP attachment could not be verified: $e';
        await clearDebugApp();
      }
    }
    return error;
  }

  @override
  Future<void> stopFridaServer() async {
    final pid = await _run(_adb(['shell', 'pidof', 'frida-server']));
    if (pid?.exitCode == 1 && pid!.text.isEmpty) return;
    if (pid?.ok != true) throw StateError('Could not check for a running frida-server');
    final result = await _run(_adb(['shell', 'pkill', '-x', 'frida-server']));
    if (result?.ok != true) throw StateError('Could not stop frida-server');
  }

  @override
  Future<void> clearDebugApp() async {
    try {
      await _debugger?.close();
    } finally {
      final port = _debuggerPort;
      _debugger = null;
      _debuggerPort = null;
      if (port != null) await _run(_adb(['forward', '--remove', 'tcp:$port']));
    }
  }

  // --- repackaging (integrity condition) ----------------------------------

  /// Re-signs [apk] with a throwaway debug key into [outApk], so the app's
  /// signing certificate differs from the original — the tamper signal that
  /// MASVS-RESILIENCE-2 is about. Returns null on success.
  @override
  Future<String?> resignWithNewKey(String apk, String outApk, String keystore) async {
    if (tools.keytool == null || tools.apksigner == null) {
      return 'keytool/apksigner not found';
    }
    final keyErr = await _ensureKeystore(keystore);
    if (keyErr != null) return keyErr;
    // Copy, then sign in place with the different key.
    host.writeBytes(outApk, host.readBytes(apk));
    final sign = await _run([
      tools.apksigner!, 'sign',
      '--ks', keystore, '--ks-pass', 'pass:aegisprobe', '--key-pass', 'pass:aegisprobe',
      outApk,
    ]);
    if (sign == null || !sign.ok) return 'apksigner failed: ${sign?.text.trim()}';
    return null;
  }

  /// A throwaway signing key at [keystore] (created when missing).
  Future<String?> _ensureKeystore(String keystore) async {
    if (tools.keytool == null) return 'keytool not found';
    if (host.fileExists(keystore)) return null;
    final gen = await _run([
      tools.keytool!, '-genkeypair', '-v',
      '-keystore', keystore, '-storepass', 'aegisprobe', '-keypass', 'aegisprobe',
      '-alias', 'aegis', '-keyalg', 'RSA', '-keysize', '2048', '-validity', '365',
      '-dname', 'CN=aegis probe',
    ]);
    if (gen == null || !gen.ok) return 'keytool failed: ${gen?.text.trim()}';
    return null;
  }

}
