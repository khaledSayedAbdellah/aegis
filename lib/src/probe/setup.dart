/// `aegis setup`: installs what `aegis doctor` reports as missing. Anything
/// already present is skipped and counted as installed.
///
/// [buildPlan] is pure (no I/O): it decides, from the current checks, what to
/// install, in what order, and what is blocked by a missing dependency. The
/// installers (step 5) live lower in this file and go through [Host].
library;

import 'dart:convert';

import '../version.dart';
import 'host.dart';
import 'pins.dart' as pins;
import 'toolchain.dart';

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
}
