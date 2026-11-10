import 'dart:convert';
import 'dart:io';

import 'package:aegis/aegis.dart';
import 'package:args/args.dart';
import 'package:path/path.dart' as p;

import '../../l10n/messages.g.dart';
import '../../probe/ios_target.dart';
import '../../probe/messages.dart';
import '../../probe/pins.dart' show avdName, controlAvdName;
import '../../rules/ipa_rules.dart';
import '../../rules/probe_rules.dart' show iosProbeRules;
import '../../services/android_probe.dart';
import '../arguments.dart';
import '../probe_options.dart';
import '../terminal.dart';

Future<void> auditCommand(ArgResults root, ArgParser parser) async {
  final run = root.command?.name == 'run';
  final args = run ? root.command! : root;

  if (args['help'] as bool) {
    stdout.writeln('aegis $aegisVersion - security audit for Flutter apps\n');
    if (run) {
      stdout.writeln(
          'Usage: aegis run [project-path] [--mode code|apk|aab|ipa] [options]\n');
      stdout.writeln(terminalText.runModeHelp);
      stdout.writeln(
          'Audits the project with the settings in aegis.yaml, prints the report and writes');
      stdout.writeln(
          'build/aegis-report.html and opens it (--no-open to skip).\n');
      stdout.writeln(
          '--mode apk|aab|ipa audits the file set in aegis.yaml (relative to the project):');
      stdout.writeln('  apk: build/app/outputs/flutter-apk/app-release.apk');
      stdout.writeln('  aab: build/app/outputs/bundle/release/app-release.aab');
      stdout.writeln('  ipa: build/ios/ipa/app.ipa');
      stdout.writeln(
          'Android probes use the Aegis emulators. IPA runtime tests ask for Simulator or device.');
      stdout.writeln(
          'Use --ios-target simulator|device in CI, or --no-probe for static-only IPA checks.\n');
      stdout.writeln(parser.commands['run']!.usage);
    } else {
      stdout.writeln('Usage:');
      stdout.writeln(
          '  aegis init                  Create aegis.yaml (app type and language) once per project.');
      stdout.writeln(
          '  aegis setup [--yes]         Install the resilience-probe tools once per machine');
      stdout.writeln(
          '                              (what you already have is skipped).');
      stdout.writeln(
          '  aegis doctor                Check those tools without changing anything.');
      stdout.writeln(
          '  aegis run [--mode MODE]     Choose an audit mode: code, apk, aab or ipa.');
      stdout.writeln(
          '  aegis probe                 Only the resilience probe on the configured APK, AAB or IPA.');
      stdout.writeln(
          '  aegis [project-path] [options]   Full control, for CI.\n');
      stdout.writeln(parser.usage);
    }
    return;
  }
  if (args['version'] as bool) {
    stdout.writeln('aegis $aegisVersion');
    return;
  }
  if (args['list-rules'] as bool) {
    _listRules();
    return;
  }

  final path = args.rest.isEmpty ? '.' : args.rest.first;

  AegisConfig config;
  try {
    config = AegisConfig.load(p.absolute(path));
  } on FormatException catch (e) {
    stderr.writeln(e.message);
    exit(2);
  }

  final profileArg = args['profile'] as String?;
  if (profileArg != null) {
    final profile = ProfileSet.tryParse(profileArg);
    if (profile == null) {
      stderr.writeln(
          'Unknown profile "$profileArg". Use l1, l2, l1+r, l2+r or a preset like banking.');
      exit(2);
    }
    config = config.copyWith(profile: profile);
  }
  if (args['lang'] != null) {
    config = config.copyWith(lang: args['lang'] as String);
  } else if (run && !config.langSet) {
    config = config.copyWith(lang: systemLang());
  }
  final failOn = Severity.tryParse(args['fail-on'] as String?);
  if (failOn != null) config = config.copyWith(failOn: failOn);
  final minScoreArg = args['min-score'] as String?;
  if (minScoreArg != null) {
    final v = int.tryParse(minScoreArg);
    if (v == null) {
      stderr.writeln('--min-score must be a number.');
      exit(2);
    }
    config = config.copyWith(minScore: v);
  }

  var mode = args['mode'] as String?;
  if (run && mode == null) {
    final text = terminalText;
    if (!stdin.hasTerminal) {
      stderr.writeln(text.runModeRequired);
      exit(2);
    }
    stdout.writeln(text.runChooseMode);
    for (var i = 0; i < auditModes.length; i++) {
      stdout.writeln('  ${i + 1}) ${auditModes[i]}');
    }
    while (mode == null) {
      stdout.write(text.runModePrompt);
      String? answer;
      try {
        answer =
            stdin.readLineSync(encoding: const Utf8Codec(allowMalformed: true));
      } catch (_) {}
      if (answer == null ||
          ['q', 'quit', 'cancel'].contains(answer.trim().toLowerCase())) {
        stdout.writeln(Msg(terminalLang).cancelled);
        exit(1);
      }
      final choice = parseMenuChoice(answer, auditModes.length);
      final name = answer.trim().toLowerCase();
      mode = choice != null
          ? auditModes[choice - 1]
          : auditModes.contains(name)
              ? name
              : null;
      if (mode == null) stdout.writeln(text.runInvalidMode);
    }
  }

  var apkPath = args['apk'] as String?;
  var ipaPath = args['ipa'] as String?;
  if (apkPath != null && ipaPath != null) {
    stderr.writeln('Use one of --apk or --ipa.');
    exit(2);
  }
  if (run &&
      (mode == 'code' && (apkPath != null || ipaPath != null) ||
          mode == 'ipa' && apkPath != null ||
          mode != 'ipa' && ipaPath != null)) {
    stderr.writeln(terminalText.runModeConflict(mode: mode));
    exit(2);
  }
  if (run && apkPath == null && ipaPath == null) {
    // The file comes from aegis.yaml only: build names and folders change
    // between projects and flavors, so aegis never guesses one from build/.
    final key = switch (mode) {
      'apk' => 'apk',
      'aab' => 'aab',
      'ipa' => 'ipa',
      _ => null,
    };
    final value = switch (key) {
      'apk' => config.apk,
      'aab' => config.aab,
      'ipa' => config.ipa,
      _ => null,
    };
    if (value != null) {
      final resolved = AegisConfig.resolve(p.absolute(path), value)!;
      if (!File(resolved).existsSync()) {
        final build =
            'flutter build ${key == 'aab' ? 'appbundle' : key} --release';
        stderr.writeln('File not found: $resolved');
        stderr.writeln(
            '(from "$key: $value" in aegis.yaml). Build it ($build) or fix the path.');
        exit(2);
      }
      if (key == 'ipa') {
        ipaPath = resolved;
      } else {
        apkPath = resolved;
      }
      stdout.writeln(
          'aegis: auditing the code and ${p.relative(resolved, from: path)}');
    } else if (mode == 'apk' || mode == 'aab' || mode == 'ipa') {
      final example = switch (mode) {
        'apk' => '$flutterApkDir/app-release.apk',
        'aab' => '$flutterBundleDir/release/app-release.aab',
        _ => 'build/ios/ipa/app.ipa',
      };
      stderr.writeln(
          '--mode $mode needs the file\'s path in aegis.yaml, relative to the project, e.g.:');
      stderr.writeln('  $mode: $example');
      exit(2);
    }
    if (config.file == null) {
      stdout.writeln(
          'aegis: no aegis.yaml, using profile ${config.profile}. Run "aegis init" to set your app type.');
    }
  }
  final artifact = ipaPath ?? apkPath;
  if (artifact != null && !File(artifact).existsSync()) {
    stderr.writeln('File not found: $artifact');
    exit(2);
  }

  var iosTarget = parseIosTarget(args['ios-target'] as String?);
  if (run && iosTarget != null && mode != 'ipa') {
    stderr.writeln(terminalText.iosTargetIpaOnly);
    exit(2);
  }
  if (run && ipaPath != null && args['probe'] as bool) {
    final text = terminalText;
    if (iosTarget == null) {
      if (!stdin.hasTerminal) {
        stderr.writeln(text.iosTargetRequired);
        exit(2);
      }
      stdout.writeln(text.iosChooseTarget);
      stdout.writeln('  1) iOS Simulator');
      stdout.writeln('  2) ${text.iosDeviceLabel}');
      while (iosTarget == null) {
        stdout.write(text.iosTargetPrompt);
        String? answer;
        try {
          answer = stdin.readLineSync(
              encoding: const Utf8Codec(allowMalformed: true));
        } catch (_) {}
        if (answer == null ||
            ['q', 'quit', 'cancel'].contains(answer.trim().toLowerCase())) {
          stdout.writeln(Msg(terminalLang).cancelled);
          exit(1);
        }
        iosTarget = parseIosTarget(answer);
        if (iosTarget == null) stdout.writeln(text.iosInvalidTarget);
      }
    }
    try {
      iosSelection(args, config, p.absolute(path), target: iosTarget);
    } on FormatException {
      stderr.writeln(text.iosTargetConflict);
      exit(2);
    }
    stdout.writeln(text.iosTargetSelected(
        target: iosTarget == IosTarget.simulator
            ? 'iOS Simulator'
            : text.iosDeviceLabel));
  }

  final baselineArg = args['baseline'] as String?;
  final baselineFile =
      baselineArg ?? p.join(path, config.baseline ?? defaultBaselineFile);
  final updateBaseline = args['update-baseline'] as bool;
  Baseline? baseline;
  if (!updateBaseline && !(args['ignore-baseline'] as bool)) {
    if (File(baselineFile).existsSync()) {
      try {
        baseline = Baseline.load(baselineFile);
      } on FormatException catch (e) {
        stderr.writeln(e.message);
        exit(2);
      }
    } else if (baselineArg != null) {
      stderr.writeln(
          'Baseline not found: $baselineArg (create it with --update-baseline)');
      exit(2);
    }
  }

  // `aegis run` with an app runs the resilience probe first; its results are
  // rules AEG-R01..R04 in the same report. Plain `aegis` (CI) never does.
  ProbeOutcome? probe;
  if (run && artifact != null) {
    final outcome = (args['probe'] as bool)
        ? ipaPath != null
            ? await runConfiguredIosProbe(
                ipaPath, args, config, p.absolute(path), target: iosTarget)
            : await runAndroidProbe(apkPath!,
                log: logProbe,
                onRunning: announceAndroidProbe,
                config: config,
                projectRoot: p.absolute(path),
                signedApk: args['probe-apk'] as String?,
                expectedSigner: args['probe-cert-sha256'] as String?,
                rootAvd: (args['root-avd'] as String?) ?? avdName,
                controlAvd: (args['control-avd'] as String?) ?? controlAvdName)
        : ProbeOutcome.skipped(En.aegisTurnedOffWithNoProbe,
            skippedAr: Ar.aegisTurnedOffWithNoProbe, requested: false);
    probe = outcome;
    if (outcome.skipped != null) {
      stdout.writeln(terminalText.aegisAegisResilienceProbeSkippedStaticChecks(
          value1: outcome.skippedOf(terminalLang)));
    }
  }

  final AuditReport report;
  try {
    report = await runAudit(path,
        config: config,
        offline: args['offline'] as bool,
        apkPath: apkPath,
        ipaPath: ipaPath,
        baseline: baseline,
        probe: probe);
  } on FileSystemException catch (e) {
    stderr.writeln('${e.message}: ${e.path}');
    if (artifact == null) {
      stderr.writeln(
          'Tip: use --apk <file> or --ipa <file> to audit a binary without source.');
    }
    exit(2);
  } on FormatException catch (e) {
    stderr.writeln('Could not read ${artifact ?? 'the file'}: ${e.message}');
    exit(2);
  }

  final strictFailure = (args['strict'] as bool) && !report.complete;
  if (updateBaseline && !report.complete) {
    stderr.writeln('aegis: audit incomplete; baseline was not updated.');
    exit(2);
  }
  if (updateBaseline) {
    final b = Baseline.fromResults(report.results);
    final file = File(baselineFile);
    file.parent.createSync(recursive: true);
    file.writeAsStringSync(b.toJsonString());
    stdout.writeln(
        'Baseline: ${b.total} findings (${b.entries.length} entries) written to ${file.path}');
    stdout.writeln(
        'Commit this file. From now on, only new findings trigger --fail-on.');
    exit(0);
  }

  final failing = strictFailure ||
      (config.failOn != null && report.countAtLeast(config.failOn!) > 0) ||
      (config.minScore != null && report.score.value < config.minScore!);

  final formats = (args['format'] as List<String>).toSet();
  // `aegis run` writes into the audited project's build/ folder.
  final output = run && !args.wasParsed('output')
      ? p.join(path, 'build', 'aegis-report')
      : args['output'] as String;
  final lang = config.lang;
  final written = <String>[];

  void write(String ext, String content) {
    final file = File('$output.$ext');
    file.parent.createSync(recursive: true);
    file.writeAsStringSync(content);
    written.add(file.path);
  }

  if (formats.contains('json')) write('json', renderJson(report));
  if (formats.contains('sarif')) write('sarif', renderSarif(report));
  if (formats.contains('md')) write('md', renderMarkdown(report, lang: lang));
  if (formats.contains('html')) write('html', renderHtml(report, lang: lang));
  if (formats.contains('console')) {
    final color = (args['color'] as bool) &&
        stdout.hasTerminal &&
        stdout.supportsAnsiEscapes;
    stdout.write(ConsoleReporter(
            lang: terminalLang, color: color, verbose: args['verbose'] as bool)
        .render(report));
  }
  if (formats.contains('azure')) {
    stdout.write(renderAzure(report, failOn: config.failOn, failing: failing));
  }
  for (final w in written) {
    stdout.writeln('Report: $w');
  }
  if (run &&
      (args['open'] as bool) &&
      formats.contains('html') &&
      stdout.hasTerminal) {
    await _openInBrowser('$output.html');
  }

  var code = 0;
  if (config.failOn != null && report.countAtLeast(config.failOn!) > 0) {
    stderr.writeln(report.usesBaseline
        ? 'aegis: new findings (not in the baseline) at or above "${config.failOn!.name}" found.'
        : 'aegis: findings at or above "${config.failOn!.name}" found.');
    code = 1;
  }
  if (config.minScore != null && report.score.value < config.minScore!) {
    stderr.writeln(
        'aegis: score ${report.score.value} is below the minimum ${config.minScore}.');
    code = 1;
  }

  if (report.incomplete.isNotEmpty) {
    stderr.writeln(
        'aegis: incomplete checks: ${report.incomplete.map((r) => r.meta.id).join(', ')}.');
  }
  if (report.incomplete.isEmpty && report.probe?.incomplete == true) {
    stderr.writeln('aegis: resilience probe incomplete.');
  }
  if (!report.results.any((rule) => rule.counts)) {
    stderr.writeln('aegis: no checks completed.');
  }
  if (strictFailure) {
    stderr.writeln('aegis: audit incomplete (--strict).');
    exit(2);
  }
  exit(code);
}

void _listRules() {
  for (final r in [...allRules, ...apkRules, ...ipaRules, ...iosProbeRules]) {
    final m = r.meta;
    final profiles = m.profiles.map((x) => x.name.toUpperCase()).join('/');
    stdout.writeln(
        '${m.id.padRight(8)} ${m.severity.name.padRight(8)} ${profiles.padRight(9)} '
        '${m.title.of(terminalLang)}  [${m.masvs.join(', ')}]');
  }
}

Future<void> _openInBrowser(String file) async {
  final path = p.absolute(file);
  try {
    if (Platform.isMacOS) {
      await Process.run('open', [path]);
    } else if (Platform.isWindows) {
      await Process.run('cmd', ['/c', 'start', '', path]);
    } else {
      await Process.run('xdg-open', [path]);
    }
  } catch (_) {
    stdout.writeln('Open $path in a browser.');
  }
}
