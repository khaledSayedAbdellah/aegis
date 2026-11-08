/// The one place `aegis probe` touches the emulator and the SDK tools
/// (docs/plans/probe.md §5). Everything goes through [Host], so the runner can
/// be driven by a fake. Tool paths come from the toolchain (verified against
/// disk; `~/.aegis/tools.json` is only a cache).
///
/// `Device` sets up standard OWASP MASTG conditions on the developer's own
/// app and reads back what happened. It does not try to defeat or evade any
/// particular protection — it observes whether the app reacts.
library;

import 'dart:typed_data';

import 'package:path/path.dart' as p;

import '../binary/zip.dart';

import 'host.dart';
import 'pins.dart' as pins;
import 'toolchain.dart';

/// Resolved paths of the tools the probe drives.
class ProbeTools {
  ProbeTools({
    this.adb,
    this.emulator,
    this.apksigner,
    this.zipalign,
    this.keytool,
    this.frida,
    this.fridaServer,
    this.bundletool,
    required this.avdName,
  });

  final String? adb;
  final String? emulator;
  final String? apksigner;
  final String? zipalign;
  final String? keytool;
  final String? frida;
  final String? fridaServer;
  final String? bundletool;
  final String avdName;

  /// The `java` launcher beside [keytool] (`<jdk>/bin/keytool` → `.../java`).
  String? get java {
    if (keytool == null) return null;
    final ctx = keytool!.contains('\\') ? p.windows : p.posix;
    final name = keytool!.endsWith('.exe') ? 'java.exe' : 'java';
    return ctx.join(ctx.dirname(keytool!), name);
  }

  /// Tools missing for a working probe (bundletool only matters for `.aab`).
  List<String> missing({bool needsBundletool = false}) => [
        if (adb == null) 'adb',
        if (emulator == null) 'emulator',
        if (apksigner == null) 'apksigner',
        if (frida == null) 'frida',
        if (fridaServer == null) 'frida-server',
        if (keytool == null) 'keytool',
        if (needsBundletool && bundletool == null) 'bundletool',
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
      zipalign: ifExists(buildTools == null ? null : ctx.join(buildTools, exe('zipalign'))),
      keytool: ifExists(under(java, ['bin', exe('keytool')])),
      frida: ifExists(t.venvExe('frida')),
      fridaServer: ifExists(t.fridaServerPath),
      bundletool: ifExists(t.bundletoolPath),
      avdName: pins.avdName,
    );
  }
}

/// What the runner needs from the device, so it can be driven by a fake.
abstract interface class ProbeDevice {
  Future<String?> bootEmulator(
      {int timeoutSeconds, void Function(String)? log, String? logPath});
  Future<void> adbRoot();
  Future<String?> install(String apk);
  Future<void> uninstall(String package);
  Future<String> launch(String package);
  Future<int?> pidOf(String package);
  Future<bool> isAlive(String package);
  Future<int?> waitForProcess(String package, {int timeoutSeconds});
  Future<void> clearLogcat();
  Future<String> logcat();
  Future<String?> startFridaServer();
  Future<void> stopFridaServer();
  Future<String?> fridaAttach(String package);
  Future<String?> attachDebugger(String package);
  Future<void> clearDebugApp();
  Future<String?> resignWithNewKey(String apk, String outApk, String keystore);
}

/// A finished adb/emulator/frida action. Thin wrapper over [Proc].
class Device implements ProbeDevice {
  Device(this.host, this.tools);
  final Host host;
  final ProbeTools tools;

  List<String> _adb(List<String> args) => [tools.adb!, ...args];

  Future<Proc?> _run(List<String> cmd,
          {Map<String, String>? env, String? input}) =>
      host.run(cmd.first, cmd.sublist(1), environment: env, input: input);

  // --- emulator -----------------------------------------------------------

  /// Boots the `aegis-probe` AVD headless and waits for it to finish booting.
  /// The emulator runs for the whole probe, so it is started detached (never
  /// awaited) and boot is detected by polling. Returns null on success.
  @override
  Future<String?> bootEmulator(
      {int timeoutSeconds = 420, void Function(String)? log, String? logPath}) async {
    if (tools.emulator == null) return 'emulator not found';
    if (await _bootCompleted()) {
      log?.call('emulator already running');
      return null;
    }
    log?.call('starting the emulator…');
    await host.spawn(
        tools.emulator!,
        [
          '-avd', tools.avdName,
          '-no-window', '-no-snapshot', '-no-boot-anim',
          '-gpu', 'swiftshader_indirect', '-netdelay', 'none', '-no-audio',
        ],
        logPath: logPath);
    for (var i = 0; i * 3 < timeoutSeconds; i++) {
      await Future<void>.delayed(const Duration(seconds: 3));
      if (await _bootCompleted()) {
        log?.call('emulator booted');
        return null;
      }
      if (i > 0 && i % 10 == 0) log?.call('still booting… (${i * 3}s)');
    }
    // Timed out: say what adb sees and the tail of the emulator's own output.
    final devices = await _run(_adb(['devices']));
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
    final r = await _run(_adb(['shell', 'getprop', 'sys.boot_completed']));
    return r != null && r.ok && r.out.trim() == '1';
  }

  /// Puts the dev emulator in a rooted state (google_apis images allow it).
  @override
  Future<void> adbRoot() async {
    await _run(_adb(['root']));
    await _run(_adb(['wait-for-device']));
  }

  // --- app lifecycle ------------------------------------------------------

  @override
  Future<String?> install(String apk) async {
    final r = await _run(_adb(['install', '-r', '-t', apk]));
    if (r == null) return 'could not run adb';
    return r.ok ? null : 'adb install failed: ${r.text.trim()}';
  }

  @override
  Future<void> uninstall(String package) async =>
      _run(_adb(['uninstall', package]));

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
        if (t.startsWith('$package/')) {
          component = t;
          break;
        }
      }
    }
    if (component == null) {
      final m = await _run(_adb(['shell', 'monkey', '-p', package, '1']));
      return 'monkey: ${m?.text.trim() ?? 'failed'}';
    }
    final start = await _run(_adb(['shell', 'am', 'start', '-W', '-n', component]));
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
  Future<void> clearLogcat() async => _run(_adb(['logcat', '-c']));

  /// The current logcat buffer (`-d` dumps and exits).
  @override
  Future<String> logcat() async {
    final r = await _run(_adb(['logcat', '-d']));
    return r?.stdout ?? '';
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
    await _run(_adb(['shell', 'chmod', '755', remote]));
    // Background it so adb returns; su is available on the rooted dev image.
    await _run(_adb(['shell', 'su', '0', 'sh', '-c', 'nohup $remote >/dev/null 2>&1 &']));
    return null;
  }

  /// Attaches a Frida session to the running app, to see whether the app
  /// detects instrumentation. Returns null when a session was established.
  @override
  Future<String?> fridaAttach(String package) async {
    if (tools.frida == null) return 'frida not found';
    // -U USB/emulator, attach by name, run a one-line script and detach.
    final r = await host.run(tools.frida!,
        ['-U', '-n', package, '-q', '-e', 'true'],
        environment: null);
    if (r == null) return 'could not run frida';
    // A non-zero exit here usually means the app refused/killed the session,
    // which is itself a reaction; the runner judges by the app's state.
    return null;
  }

  /// Marks the app to wait for a debugger and opens a JDWP channel, to see
  /// whether the app detects the debugger.
  @override
  Future<String?> attachDebugger(String package) async {
    await _run(_adb(['shell', 'am', 'set-debug-app', '-w', package]));
    await launch(package);
    final pid = await pidOf(package);
    if (pid == null) return 'app not running';
    final fwd = await _run(_adb(['forward', 'tcp:8700', 'jdwp:$pid']));
    return fwd != null && fwd.ok ? null : 'could not open a JDWP channel';
  }

  /// Stops a frida-server left running on the device (by this probe or an
  /// earlier one), so it can't influence the checks that don't involve it.
  @override
  Future<void> stopFridaServer() async {
    await _run(_adb(['shell', 'su', '0', 'pkill', '-f', 'frida-server']));
  }

  @override
  Future<void> clearDebugApp() async =>
      _run(_adb(['shell', 'am', 'clear-debug-app']));

  // --- repackaging (integrity condition) ----------------------------------

  /// Re-signs [apk] with a throwaway debug key into [outApk], so the app's
  /// signing certificate differs from the original — the tamper signal that
  /// MASVS-RESILIENCE-2 is about. Returns null on success.
  @override
  Future<String?> resignWithNewKey(String apk, String outApk, String keystore) async {
    if (tools.keytool == null || tools.apksigner == null) {
      return 'keytool/apksigner not found';
    }
    if (!host.fileExists(keystore)) {
      final gen = await _run([
        tools.keytool!, '-genkeypair', '-v',
        '-keystore', keystore, '-storepass', 'aegisprobe', '-keypass', 'aegisprobe',
        '-alias', 'aegis', '-keyalg', 'RSA', '-keysize', '2048', '-validity', '365',
        '-dname', 'CN=aegis probe',
      ]);
      if (gen == null || !gen.ok) return 'keytool failed: ${gen?.text.trim()}';
    }
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

  /// Builds a universal APK from an `.aab` with bundletool into [outApk]
  /// (via the [outApks] set). bundletool signs it with the debug keystore, so
  /// it never carries the release signature. Returns null on success, else
  /// the reason.
  Future<String?> aabToApk(String aab, String outApks, String outApk) async {
    if (tools.bundletool == null) return 'bundletool not found (run "aegis setup --aab")';
    if (tools.java == null) return 'java not found';
    final r = await _run([
      tools.java!, '-jar', tools.bundletool!,
      'build-apks', '--mode=universal', '--overwrite',
      '--bundle=$aab', '--output=$outApks',
    ]);
    if (r == null) return 'could not run java';
    if (!r.ok) return 'bundletool failed: ${r.text.trim()}';
    if (!host.fileExists(outApks)) return 'bundletool wrote nothing';
    final universal =
        ZipReader(Uint8List.fromList(host.readBytes(outApks))).read('universal.apk');
    if (universal == null) return 'no universal.apk in the bundletool output';
    host.writeBytes(outApk, universal);
    return null;
  }
}
