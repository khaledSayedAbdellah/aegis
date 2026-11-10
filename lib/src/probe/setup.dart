/// `aegis setup`: installs what `aegis doctor` reports as missing. Anything
/// already present is skipped and counted as installed.
///
/// [buildPlan] is pure (no I/O): it decides, from the current checks, what to
/// install, in what order, and what is blocked by a missing dependency. The
/// installers (step 5) live lower in this file and go through [Host].
library;

import 'dart:convert';

import 'package:archive/archive.dart' show XZDecoder;
import 'package:path/path.dart' as p;

import '../version.dart';
import 'host.dart';
import 'pins.dart' as pins;
import 'toolchain.dart';

/// What happened to one step.
class StepOutcome {
  StepOutcome(this.id, {this.error, this.skipped = false, this.skippedFor});
  final String id;

  /// null on success, else a short reason.
  final String? error;
  final bool skipped;

  /// When [skipped]: the failed dependencies that caused it.
  final List<String>? skippedFor;

  bool get ok => !skipped && error == null;
}

/// One thing to install. [id] is a [ToolCheck.id].
class SetupStep {
  const SetupStep(this.id);
  final String id;
}

/// What setup will do, decided from the checks alone.
class SetupPlan {
  SetupPlan({
    required this.steps,
    required this.present,
    required this.manual,
    required this.optional,
    required this.blocked,
  });

  /// Installable now, in install order.
  final List<SetupStep> steps;

  /// Already there: skipped.
  final List<ToolCheck> present;

  /// Missing, only the person can install them.
  final List<ToolCheck> manual;

  /// Not needed now (bundletool without `--aab`).
  final List<ToolCheck> optional;

  /// Installable, but a dependency is missing and not installed this run:
  /// id → the missing dependency ids.
  final Map<String, List<String>> blocked;

  bool get nothingToDo => steps.isEmpty;

  /// True when, after the steps run, every required tool should be present.
  bool get coversEverything => manual.isEmpty && blocked.isEmpty;
}

/// Install order; a step may depend only on present tools or earlier steps.
const installOrder = [
  'platform-tools',
  'build-tools',
  'emulator',
  'system-image',
  'control-image',
  'avd',
  'control-avd',
  'frida',
  'frida-server',
  'ios-gadget',
  'ios-simulator-gadget',
  'bundletool',
];

class Setup {
  Setup(this.toolchain);

  final Toolchain toolchain;
  Host get host => toolchain.host;

  /// Pure: build the plan from [checks]. A dependency satisfied by an earlier
  /// step in the same plan does not block a later one.
  SetupPlan buildPlan(List<ToolCheck> checks) {
    final byId = {for (final c in checks) c.id: c};
    final present = checks.where((c) => c.ok).toList();
    final manual = checks.where((c) => c.state == ToolState.manual).toList();
    final optional = checks.where((c) => c.state == ToolState.optional).toList();
    final willHave = {for (final c in present) c.id};
    final steps = <SetupStep>[];
    final blocked = <String, List<String>>{};
    for (final id in installOrder) {
      final c = byId[id];
      if (c == null || c.state != ToolState.installable) continue;
      final missing = [
        for (final n in toolNeeds[id] ?? const <String>[])
          if (!willHave.contains(n)) n
      ];
      if (missing.isNotEmpty) {
        blocked[id] = missing;
        continue;
      }
      steps.add(SetupStep(id));
      willHave.add(id);
    }
    return SetupPlan(
        steps: steps,
        present: present,
        manual: manual,
        optional: optional,
        blocked: blocked);
  }

  /// The sdkmanager package name for a step, or null when it isn't one.
  String? sdkmanagerPackage(String id) => switch (id) {
        'platform-tools' => 'platform-tools',
        'build-tools' => 'build-tools;${pins.buildToolsVersion}',
        'emulator' => 'emulator',
        'system-image' => toolchain.systemImagePackage,
        'control-image' => toolchain.controlImagePackage,
        _ => null,
      };

  /// Every sdkmanager package the plan needs, so one call accepts the
  /// licenses once.
  List<String> sdkmanagerPackages(SetupPlan plan) => [
        for (final s in plan.steps)
          if (sdkmanagerPackage(s.id) case final pkg?) pkg
      ];

  /// `~/.aegis/tools.json` content: the present tools and their paths, so
  /// `aegis probe` doesn't search again. A cache, not the truth.
  String toolsJson(List<ToolCheck> checks) {
    final tools = <String, Object?>{
      for (final c in checks)
        if (c.ok && c.path != null)
          c.id: {
            'path': c.path,
            if (c.version != null) 'version': c.version,
          },
    };
    final doc = {
      'schema': 1,
      'aegis': aegisVersion,
      'tools': tools,
    };
    return '${const JsonEncoder.withIndent('  ').convert(doc)}\n';
  }

  void writeToolsJson(List<ToolCheck> checks) =>
      host.writeText(toolchain.toolsJsonPath, toolsJson(checks));

  // --- execution ----------------------------------------------------------

  /// Installs everything in [plan]. The SDK packages go in one sdkmanager
  /// call; a step whose dependency failed is skipped. [log] receives progress
  /// lines for the captured steps (downloads); sdkmanager and pip stream to
  /// the terminal themselves.
  Future<List<StepOutcome>> execute(SetupPlan plan,
      {void Function(String id)? onStep, void Function(String)? log}) async {
    log ??= (_) {};
    final outcomes = <StepOutcome>[];
    final failed = <String>{};

    final sdkIds = [
      for (final s in plan.steps)
        if (sdkmanagerPackage(s.id) != null) s.id
    ];
    if (sdkIds.isNotEmpty) {
      for (final id in sdkIds) {
        onStep?.call(id);
      }
      final err = await installSdk(sdkmanagerPackages(plan), log: log);
      for (final id in sdkIds) {
        outcomes.add(StepOutcome(id, error: err));
        if (err != null) failed.add(id);
      }
    }

    for (final s in plan.steps) {
      if (sdkmanagerPackage(s.id) != null) continue;
      final blockedBy = [
        for (final n in toolNeeds[s.id] ?? const <String>[])
          if (failed.contains(n)) n
      ];
      if (blockedBy.isNotEmpty) {
        outcomes.add(StepOutcome(s.id, skipped: true, skippedFor: blockedBy));
        failed.add(s.id);
        continue;
      }
      onStep?.call(s.id);
      final err = await install(s.id, log: log);
      outcomes.add(StepOutcome(s.id, error: err));
      if (err != null) failed.add(s.id);
    }
    return outcomes;
  }

  /// One sdkmanager call for [packages]; the user accepts the licenses on the
  /// terminal. Returns null on success, else a reason.
  Future<String?> installSdk(List<String> packages,
      {void Function(String)? log}) async {
    if (packages.isEmpty) return null;
    final root = (await toolchain.findSdkRoot())?.path;
    if (root == null) return 'Android SDK not found';
    final sm = toolchain.sdkTool(root, 'sdkmanager');
    if (sm == null) return 'sdkmanager not found';
    final code = await host.runAttached(sm, ['--sdk_root=$root', ...packages],
        environment: await _javaEnv());
    if (code == null) return 'could not run sdkmanager';
    if (code != 0) {
      return 'sdkmanager exited $code (if it asked about licenses, run: '
          '"$sm" --licenses)';
    }
    return null;
  }

  /// Installs one non-sdkmanager step. Returns null on success, else a reason.
  Future<String?> install(String id, {void Function(String)? log}) async {
    log ??= (_) {};
    try {
      return switch (id) {
        'avd' => await _createAvd(),
        'control-avd' => await _createAvd(control: true),
        'frida' => await _installFrida(log),
        'frida-server' => await _installFridaServer(log),
        'ios-gadget' => await _installIosGadget(toolchain.iosGadgetPath,
            pins.iosGadgetUrl, pins.iosGadgetPin, log),
        'ios-simulator-gadget' => await _installIosGadget(
            toolchain.iosSimulatorGadgetPath, pins.iosSimulatorGadgetUrl,
            pins.iosSimulatorGadgetPin, log),
        'bundletool' => await verifiedDownload(
            pins.bundletoolUrl, toolchain.bundletoolPath, pins.bundletoolPin, log),
        'platform-tools' ||
        'build-tools' ||
        'emulator' ||
        'system-image' ||
        'control-image' =>
          await installSdk([sdkmanagerPackage(id)!], log: log),
        _ => 'unknown step: $id',
      };
    } catch (e) {
      return '$e';
    }
  }

  Future<String?> _createAvd({bool control = false}) async {
    final name = control ? pins.controlAvdName : pins.avdName;
    final image = control ? toolchain.controlImagePackage : toolchain.systemImagePackage;
    final root = (await toolchain.findSdkRoot())?.path;
    final avdmanager = root == null ? null : toolchain.sdkTool(root, 'avdmanager');
    if (avdmanager == null) return 'avdmanager not found';
    // "no" declines the custom-hardware-profile question. No --force, so an
    // existing AVD of this name is never overwritten.
    final r = await host.run(
        avdmanager,
        ['create', 'avd', '-n', name, '-k', image, '-d', pins.avdDevice],
        environment: await _javaEnv(),
        input: 'no\n');
    if (r == null) return 'could not run avdmanager';
    if (!r.ok) return 'avdmanager exited ${r.exitCode}: ${r.text.trim()}';
    final home = toolchain.avdHome;
    if (control && home != null) {
      host.writeText(p.join(home, '$name.avd', '.aegis-created'), '');
    }
    return null;
  }

  Future<String?> _installFrida(void Function(String) log) async {
    final py = (await toolchain.checkPython()).path;
    if (py == null) return 'Python not found';
    final venvPython = toolchain.venvExe('python');
    if (!host.fileExists(venvPython) && !host.fileExists('${venvPython}3')) {
      log('python -m venv ${toolchain.tilde(toolchain.venvDir)}');
      final code = await host.runAttached(py, ['-m', 'venv', toolchain.venvDir]);
      if (code != 0) return 'could not create the venv (exit $code)';
    }
    // The venv's pip comes from the system Python and can be too old for the
    // current Frida wheels (Xcode's Python 3.9 ships pip 21). Upgrade it inside
    // the venv only.
    log('pip install --upgrade pip');
    final pipCode = await host.runAttached(
        venvPython, ['-m', 'pip', 'install', '--upgrade', 'pip']);
    if (pipCode != 0) return 'could not upgrade pip in the venv (exit $pipCode)';
    log('pip install frida==${pins.fridaVersion} frida-tools==${pins.fridaToolsVersion}');
    final code = await host.runAttached(venvPython, [
      '-m', 'pip', 'install', '--upgrade',
      'frida==${pins.fridaVersion}', 'frida-tools==${pins.fridaToolsVersion}',
    ]);
    return code == 0 ? null : 'pip install failed (exit $code)';
  }

  Future<String?> _installFridaServer(void Function(String) log) async {
    final dest = toolchain.fridaServerPath;
    final xz = '$dest.xz';
    final url = pins.fridaServerUrl(toolchain.fridaArch);
    final verifyErr =
        await verifiedDownload(url, xz, pins.fridaServerPin(toolchain.fridaArch), log);
    if (verifyErr != null) return verifyErr;
    final bytes = XZDecoder().decodeBytes(host.readBytes(xz));
    host.writeBytes(dest, bytes);
    host.deleteFile(xz);
    host.makeExecutable(dest);
    return null;
  }

  Future<String?> _installIosGadget(
      String dest, String url, pins.Pinned pin, void Function(String) log) async {
    final staged = '$dest.${DateTime.now().microsecondsSinceEpoch}.tmp';
    final xz = '$staged.xz';
    try {
      final error = await verifiedDownload(url, xz, pin, log);
      if (error != null) return error;
      host.writeBytes(staged, XZDecoder().decodeBytes(host.readBytes(xz)));
      host.rename(staged, dest);
      return null;
    } finally {
      host.deleteFile(xz);
      host.deleteFile(staged);
    }
  }

  /// Downloads [url] to [dest] and checks its SHA-256 against [pin];
  /// a mismatch deletes the file and fails. Returns null on success.
  Future<String?> verifiedDownload(
      String url, String dest, pins.Pinned pin, void Function(String) log) async {
    log('download $url');
    final err = await host.download(url, dest);
    if (err != null) return err;
    final got = host.sha256File(dest);
    if (got != pin.sha256) {
      host.deleteFile(dest);
      return 'checksum mismatch for ${p.basename(dest)}\n'
          '      expected ${pin.sha256}\n      got      $got';
    }
    log('verified sha256');
    return null;
  }

  /// Deletes what aegis installed under `~/.aegis` (the Frida venv, the tools
  /// folder, tools.json), the `aegis-probe` AVD and a control AVD it created.
  /// Never touches Java, the
  /// Android SDK or its packages — those are the user's, not aegis's. Returns
  /// the paths/items removed.
  Future<List<String>> remove() async {
    final removed = <String>[];
    for (final path in [toolchain.venvDir, toolchain.toolsDir, toolchain.toolsJsonPath]) {
      if (host.fileExists(path) || host.dirExists(path)) {
        host.deletePath(path);
        removed.add(toolchain.tilde(path));
      }
    }
    final avdHome = toolchain.avdHome;
    if (avdHome == null) return removed;
    final controlDir = p.join(avdHome, '${pins.controlAvdName}.avd');
    final ownsControl = host.fileExists(p.join(controlDir, '.aegis-created'));
    for (final name in [pins.avdName, if (ownsControl) pins.controlAvdName]) {
      final avdDir = p.join(avdHome, '$name.avd');
      if (!host.dirExists(avdDir)) continue;
      final root = (await toolchain.findSdkRoot())?.path;
      final avdmanager = root == null ? null : toolchain.sdkTool(root, 'avdmanager');
      if (avdmanager != null) {
        final result = await host.run(avdmanager, ['delete', 'avd', '-n', name],
            environment: await _javaEnv());
        if (result?.ok != true) continue;
      } else {
        host.deletePath(avdDir);
        host.deleteFile(p.join(avdHome, '$name.ini'));
      }
      removed.add('AVD $name');
    }
    return removed;
  }

  /// JAVA_HOME for sdkmanager/avdmanager, which need a JDK (often only in
  /// Android Studio's JBR, not on PATH).
  Future<Map<String, String>?> _javaEnv() async {
    final jdk = await toolchain.findJavaHome();
    return jdk == null ? null : {'JAVA_HOME': jdk.home};
  }
}
