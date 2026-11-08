/// `aegis setup`: installs what `aegis doctor` reports as missing. Anything
/// already present is skipped and counted as installed.
///
/// [buildPlan] is pure (no I/O): it decides, from the current checks, what to
/// install, in what order, and what is blocked by a missing dependency. The
/// installers (step 5) live lower in this file and go through [Host].
library;

import 'dart:convert';

import 'package:archive/archive.dart' show XZDecoder;

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
  'avd',
  'frida',
  'frida-server',
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
        'frida' => await _installFrida(log),
        'frida-server' => await _installFridaServer(log),
        'bundletool' => await _download(pins.bundletoolUrl, toolchain.bundletoolPath, log),
        'platform-tools' ||
        'build-tools' ||
        'emulator' ||
        'system-image' =>
          await installSdk([sdkmanagerPackage(id)!], log: log),
        _ => 'unknown step: $id',
      };
    } catch (e) {
      return '$e';
    }
  }

  Future<String?> _createAvd() async {
    final root = (await toolchain.findSdkRoot())?.path;
    final avdmanager = root == null ? null : toolchain.sdkTool(root, 'avdmanager');
    if (avdmanager == null) return 'avdmanager not found';
    // "no" declines the custom-hardware-profile question. No --force, so an
    // existing AVD of this name is never overwritten.
    final r = await host.run(
        avdmanager,
        ['create', 'avd', '-n', pins.avdName, '-k', toolchain.systemImagePackage, '-d', pins.avdDevice],
        environment: await _javaEnv(),
        input: 'no\n');
    if (r == null) return 'could not run avdmanager';
    return r.ok ? null : 'avdmanager exited ${r.exitCode}: ${r.text.trim()}';
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
    log('download $url');
    final err = await host.download(url, xz);
    if (err != null) return err;
    final bytes = XZDecoder().decodeBytes(host.readBytes(xz));
    host.writeBytes(dest, bytes);
    host.deleteFile(xz);
    host.makeExecutable(dest);
    return null;
  }

  Future<String?> _download(String url, String dest, void Function(String) log) async {
    log('download $url');
    return host.download(url, dest);
  }

  /// JAVA_HOME for sdkmanager/avdmanager, which need a JDK (often only in
  /// Android Studio's JBR, not on PATH).
  Future<Map<String, String>?> _javaEnv() async {
    final jdk = await toolchain.findJavaHome();
    return jdk == null ? null : {'JAVA_HOME': jdk.home};
  }
}
