import 'dart:convert';
import 'dart:io';

import 'package:args/args.dart';

import '../../probe/host.dart';
import '../../probe/messages.dart';
import '../../probe/setup.dart';
import '../../probe/setup_platform.dart';
import '../../probe/toolchain.dart';
import '../arguments.dart';
import '../terminal.dart';
import '../tool_output.dart';

Future<int> setupCommand(ArgResults a) async {
  final text = terminalText;
  final m = Msg(terminalLang);
  if (a['help'] as bool) {
    stdout.writeln(
        'Usage: aegis setup [--android | --ios | --both | --remove] [--yes] [--lang en|ar]\n');
    stdout.writeln(text.setupHelpScope);
    stdout.writeln(text.setupHelpConfirmation);
    stdout.writeln(
        '--remove deletes what aegis installed (never your Java or Android SDK).\n');
    stdout.writeln(toolsParser(setup: true).usage);
    return 0;
  }
  SetupTarget? target;
  try {
    target = setupTargetFromFlags(
        android: a['android'] as bool,
        ios: a['ios'] as bool,
        both: a['both'] as bool,
        aab: a['aab'] as bool);
    if (a['remove'] as bool && target != null) {
      throw const FormatException('Separate removal from installation.');
    }
  } on FormatException {
    stderr.writeln(text.setupPlatformConflict);
    return 2;
  }
  if (a['remove'] as bool) {
    final removed = await Setup(Toolchain(SystemHost())).remove();
    if (removed.isEmpty) {
      stdout.writeln(m.nothingToRemove);
    } else {
      stdout.writeln(m.removed);
      for (final r in removed) {
        stdout.writeln('  🗑  $r');
      }
    }
    return 0;
  }
  if (target == null) {
    if (!stdin.hasTerminal) {
      stderr.writeln(text.setupPlatformRequired);
      return 2;
    }
    stdout.writeln(text.setupChoosePlatform);
    stdout.writeln('  1) Android (APK + AAB)');
    stdout.writeln('  2) iOS');
    stdout.writeln('  3) Both (Android + iOS)');
    while (target == null) {
      stdout.write(text.setupPlatformPrompt);
      String? answer;
      try {
        answer =
            stdin.readLineSync(encoding: const Utf8Codec(allowMalformed: true));
      } catch (_) {}
      if (answer == null ||
          ['q', 'quit', 'cancel'].contains(answer.trim().toLowerCase())) {
        stdout.writeln(m.cancelled);
        return 1;
      }
      target = parseSetupTarget(answer);
      if (target == null) stdout.writeln(text.setupInvalidPlatform);
    }
  }
  String? os;
  try {
    os = Platform.operatingSystem;
  } catch (_) {}
  final results = await runSetupPlatforms(target,
      hostOs: os,
      prepare: (platform) async {
        stdout.writeln(
            '\n${text.setupPreparingPlatform(platform: platform.label)}');
        return _setupPlatform(a, platform);
      },
      iosUnsupported: () => stderr.writeln(text.setupIosUnsupported),
      failed: (platform, error) => stderr.writeln(
          text.setupPlatformFailed(platform: platform.label, error: error)));
  stdout.writeln('\n${m.result}');
  for (final result in results.entries) {
    stdout.writeln(result.value == 0
        ? text.setupPlatformReady(platform: result.key.label)
        : text.setupPlatformIncomplete(platform: result.key.label));
  }
  return setupExitCode(results);
}

Future<int> _setupPlatform(ArgResults a, SetupPlatform platform) async {
  final ios = platform == SetupPlatform.ios;
  final m = Msg(terminalLang, ios: ios);
  final t = Toolchain(SystemHost());
  final setup = Setup(t);
  var checks = await checkSetupPlatform(t, platform);
  final plan = setup.buildPlan(checks);

  for (final c in plan.present) {
    stdout.writeln('  ✅ ${m.title(c.id)}: ${m.alreadyThere}');
  }
  for (final c in plan.manual) {
    stdout.writeln('  ❌ ${m.title(c.id)}: ${m.installYourself(c)}');
  }
  for (final e in plan.blocked.entries) {
    stdout.writeln('  ⏸️  ${m.title(e.key)}: ${m.waitingFor(e.value)}');
  }
  for (final c in plan.optional) {
    stdout.writeln('  ℹ️  ${m.title(c.id)}: ${m.issue(c)}');
  }

  if (plan.nothingToDo) {
    if (!ios) setup.writeToolsJson(checks);
    stdout.writeln('');
    stdout.writeln(plan.coversEverything ? m.allPresent : m.someManual);
    return plan.coversEverything ? 0 : 1;
  }

  stdout.writeln('\n${m.willInstall}');
  for (final s in plan.steps) {
    stdout.writeln('  ⬇️  ${m.title(s.id)}');
  }
  if (setup.sdkmanagerPackages(plan).isNotEmpty) stdout.writeln(m.licensesNote);

  if (!(a['yes'] as bool)) {
    if (!stdin.hasTerminal) {
      stderr.writeln(m.noTerminal);
      return 2;
    }
    stdout.write('\n${m.confirm}');
    String? line;
    try {
      line =
          stdin.readLineSync(encoding: const Utf8Codec(allowMalformed: true));
    } catch (_) {}
    if (!yesAnswers.contains((line ?? '').trim().toLowerCase())) {
      stdout.writeln(m.cancelled);
      return 1;
    }
  }

  final imageCount = plan.steps
      .where((step) => step.id == 'system-image' || step.id == 'control-image')
      .length;
  if (imageCount > 0) {
    final root = (await t.findSdkRoot())?.path;
    final free = root == null ? null : await t.host.freeBytes(root);
    final estimatedGiB = imageCount * 4;
    if (free != null && free < estimatedGiB * (1 << 30)) {
      stdout.writeln(
          '⚠️  ${m.freeSpaceWarning('$estimatedGiB GB', '${(free / (1 << 30)).toStringAsFixed(1)} GB')}');
    }
  }

  final outcomes = await setup.execute(plan,
      onStep: (id) => stdout.writeln('\n▶ ${m.step(m.title(id))}'),
      log: (s) => stdout.writeln('    $s'));
  for (final o in outcomes) {
    if (o.skipped) {
      stdout.writeln(
          '  ⏸️  ${m.title(o.id)}: ${m.waitingFor(o.skippedFor ?? const [])}');
    } else if (o.ok) {
      stdout.writeln('  ✅ ${m.title(o.id)}');
    } else {
      stdout.writeln('  ❌ ${m.title(o.id)}: ${o.error}');
    }
  }

  checks = await checkSetupPlatform(t, platform);
  if (!ios) setup.writeToolsJson(checks);
  stdout.writeln('\n${m.result}');
  printToolChecks(checks, m, t);
  final ok =
      checks.where((c) => c.state != ToolState.optional).every((c) => c.ok);
  stdout.writeln('');
  stdout.writeln(
      ok ? (ios ? m.allPresent : m.savedTo(t.toolsJsonPath)) : m.stillMissing);
  return ok ? 0 : 1;
}
