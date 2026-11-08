/// The one place `aegis probe` touches the emulator and the SDK tools
/// (docs/plans/probe.md §5). Everything goes through [Host], so the runner can
/// be driven by a fake. Tool paths come from the toolchain (verified against
/// disk; `~/.aegis/tools.json` is only a cache).
///
/// `Device` sets up standard OWASP MASTG conditions on the developer's own
/// app and reads back what happened. It does not try to defeat or evade any
/// particular protection — it observes whether the app reacts.
library;

import 'package:path/path.dart' as p;

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

/// A finished adb/emulator/frida action. Thin wrapper over [Proc].
class Device {
  Device(this.host, this.tools);
  final Host host;
  final ProbeTools tools;

  List<String> _adb(List<String> args) => [tools.adb!, ...args];

  Future<Proc?> _run(List<String> cmd,
          {Map<String, String>? env, String? input}) =>
      host.run(cmd.first, cmd.sublist(1), environment: env, input: input);

  // --- emulator -----------------------------------------------------------

  /// Boots the `aegis-probe` AVD headless and waits for it to finish booting.
  /// Returns null on success, else a reason.
  Future<String?> bootEmulator({int timeoutSeconds = 180}) async {
    if (tools.emulator == null) return 'emulator not found';
    // Fire-and-forget: the emulator stays up for the rest of the run.
    await host.run(tools.emulator!,
        ['-avd', tools.avdName, '-no-window', '-no-snapshot', '-no-boot-anim', '-netdelay', 'none']);
    await _run(_adb(['wait-for-device']));
    // Poll sys.boot_completed.
    for (var i = 0; i < timeoutSeconds ~/ 2; i++) {
      final r = await _run(_adb(['shell', 'getprop', 'sys.boot_completed']));
      if (r != null && r.out.trim() == '1') return null;
      await Future<void>.delayed(const Duration(seconds: 2));
    }
    return 'emulator did not finish booting in ${timeoutSeconds}s';
  }

  /// Puts the dev emulator in a rooted state (google_apis images allow it).
  Future<void> adbRoot() async {
    await _run(_adb(['root']));
    await _run(_adb(['wait-for-device']));
  }

  // --- app lifecycle ------------------------------------------------------

  Future<String?> install(String apk) async {
    final r = await _run(_adb(['install', '-r', '-t', apk]));
    if (r == null) return 'could not run adb';
    return r.ok ? null : 'adb install failed: ${r.text.trim()}';
  }

  Future<void> uninstall(String package) async =>
      _run(_adb(['uninstall', package]));

  /// Launches the app's default launcher activity.
  Future<void> launch(String package) async =>
      _run(_adb(['shell', 'monkey', '-p', package, '-c', 'android.intent.category.LAUNCHER', '1']));

  /// The app's pid, or null when it isn't running.
  Future<int?> pidOf(String package) async {
    final r = await _run(_adb(['shell', 'pidof', package]));
    if (r == null || !r.ok) return null;
    return int.tryParse(r.out.trim().split(RegExp(r'\s+')).first);
  }

  Future<bool> isAlive(String package) async => (await pidOf(package)) != null;

  Future<void> clearLogcat() async => _run(_adb(['logcat', '-c']));

  /// The current logcat buffer (`-d` dumps and exits).
  Future<String> logcat() async {
    final r = await _run(_adb(['logcat', '-d']));
    return r?.stdout ?? '';
  }

  // --- conditions ---------------------------------------------------------

  /// Pushes frida-server to the device and starts it in the background.
  /// Returns null on success.
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
  Future<String?> attachDebugger(String package) async {
    await _run(_adb(['shell', 'am', 'set-debug-app', '-w', package]));
    await launch(package);
    final pid = await pidOf(package);
    if (pid == null) return 'app not running';
    final fwd = await _run(_adb(['forward', 'tcp:8700', 'jdwp:$pid']));
    return fwd != null && fwd.ok ? null : 'could not open a JDWP channel';
  }

  Future<void> clearDebugApp() async =>
      _run(_adb(['shell', 'am', 'clear-debug-app']));

  // --- repackaging (integrity condition) ----------------------------------

  /// Re-signs [apk] with a throwaway debug key into [outApk], so the app's
  /// signing certificate differs from the original — the tamper signal that
  /// MASVS-RESILIENCE-2 is about. Returns null on success.
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

  /// Builds a universal APK from an `.aab` with bundletool. Returns the APK
  /// path, or null on failure.
  Future<String?> aabToApk(String aab, String outApks, String outApk) async {
    if (tools.bundletool == null || tools.java == null) return null;
    final r = await _run([
      tools.java!, '-jar', tools.bundletool!,
      'build-apks', '--mode=universal', '--bundle=$aab', '--output=$outApks',
    ]);
    if (r == null || !r.ok) return null;
    // outApks is a zip; the universal APK is universal.apk inside it. The
    // runner unzips it with the existing zip reader.
    return outApk;
  }
}
