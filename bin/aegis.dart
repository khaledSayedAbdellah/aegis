import 'dart:convert';
import 'dart:io';

import 'package:aegis/aegis.dart';
import 'package:aegis/src/probe/device.dart';
import 'package:aegis/src/probe/apk_identity.dart';
import 'package:aegis/src/probe/apk_set.dart';
import 'package:aegis/src/probe/pins.dart' show avdName, controlAvdName;
import 'package:aegis/src/project.dart' show androidAttr;
import 'package:aegis/src/probe/host.dart';
import 'package:aegis/src/probe/messages.dart';
import 'package:aegis/src/probe/probe_report.dart';
import 'package:aegis/src/probe/probe_runner.dart';
import 'package:aegis/src/probe/setup.dart';
import 'package:aegis/src/probe/toolchain.dart';
import 'package:args/args.dart';
import 'package:path/path.dart' as p;

const _formats = ['console', 'json', 'md', 'html', 'sarif', 'azure'];

const _modes = ['all', 'code', 'apk', 'aab'];

/// Options shared by plain `aegis` and `aegis run`. `run` has friendlier
/// defaults: an HTML report next to the console output, the APK/AAB comes
/// from apk:/aab: in aegis.yaml, and the resilience probe runs on it.
ArgParser _parser({bool run = false}) => ArgParser()
  ..addOption('profile',
      abbr: 'p',
      help: 'MAS profile: l1, l2, l1+r, l2+r, or a preset '
          '(standard, sensitive, game, banking, fintech, payments, government).')
  ..addOption('apk',
      help: 'Also audit a release APK or app bundle (.aab), e.g. build/app/outputs/flutter-apk/app-release.apk '
          'or build/app/outputs/bundle/release/app-release.aab. '
          'Without a pubspec.yaml in the project path, only the APK is audited.')
  ..addOption('lang', abbr: 'l', allowed: ['en', 'ar'], help: 'Report language.')
  ..addMultiOption('format',
      abbr: 'f',
      allowed: _formats,
      defaultsTo: run ? ['console', 'html'] : ['console'],
      help: 'Output formats (comma separated). "azure" prints Azure Pipelines annotations for new findings.')
  ..addOption('output',
      abbr: 'o',
      defaultsTo: run ? 'build/aegis-report' : 'aegis-report',
      help: 'Report path without extension for file formats.')
  ..addOption('fail-on',
      allowed: ['critical', 'high', 'medium', 'low'],
      help: 'Exit with code 1 when a finding at or above this severity exists.')
  ..addOption('min-score', help: 'Exit with code 1 when the score is below this value.')
  ..addOption('baseline',
      help: 'Baseline file of accepted findings (default: aegis-baseline.json in the project, '
          'or "baseline:" in aegis.yaml). Known findings are reported separately and do not trigger --fail-on.')
  ..addFlag('update-baseline',
      negatable: false, help: 'Accept all current findings: write them to the baseline file and exit.')
  ..addFlag('ignore-baseline', negatable: false, help: 'Report every finding as new, ignoring the baseline.')
  ..addFlag('strict', negatable: false, help: 'Fail if an applicable check could not complete.')
  ..addFlag('offline', negatable: false, help: 'Skip the OSV vulnerability lookup (no network).')
  ..addFlag('verbose', abbr: 'v', negatable: false, help: 'Show every finding and not-applicable rules.')
  ..addFlag('color', defaultsTo: true, help: 'Colored console output.')
  ..addFlag('list-rules', negatable: false, help: 'List all rules and exit.')
  ..addFlag('version', negatable: false, help: 'Print the version and exit.')
  ..addFlag('help', abbr: 'h', negatable: false, help: 'Show this help.')
  ..addOption('mode',
      abbr: 'm',
      allowed: _modes,
      defaultsTo: 'all',
      hide: !run,
      allowedHelp: {
        'all': 'Code + the APK/AAB set in aegis.yaml (apk:, else aab:) with the resilience probe; '
            'code only when neither is set.',
        'code': 'Dart code, packages and Android/iOS configuration only.',
        'apk': 'Code + the APK at apk: in aegis.yaml + the resilience probe on the two emulators.',
        'aab': 'Code + the AAB at aab: in aegis.yaml + the resilience probe on the two emulators.',
      },
      help: 'What to audit.')
  ..addOption('probe-cert-sha256', hide: !run,
      help: 'Expected app signing certificate SHA-256 for --probe-apk (hex).')
  ..addOption('probe-apk', hide: !run,
      help: 'For an AAB, the corresponding signed APK, .apks archive or device-specific APK directory.')
  ..addOption('control-avd', hide: !run, help: 'Dedicated Aegis AVD for the control launch.')
  ..addOption('root-avd', hide: !run,
      help: 'Dedicated rooted Aegis AVD for the root comparison.')
  ..addFlag('probe',
      defaultsTo: true,
      hide: !run,
      help: 'Run the resilience probe on the two emulators when an APK/AAB is audited. '
          '--no-probe runs the static checks only.')
  ..addFlag('open',
      defaultsTo: run,
      hide: !run,
      help: 'Open the HTML report in the browser (only in a terminal, never in CI).');

ArgParser _initParser() => ArgParser()
  ..addOption('profile',
      abbr: 'p', help: 'l1, l2, l1+r, l2+r or a preset. Asked interactively when omitted.')
  ..addOption('lang', abbr: 'l', allowed: ['en', 'ar'], help: 'Report language (default: system language).')
  ..addFlag('force', negatable: false, help: 'Overwrite an existing aegis.yaml.')
  ..addFlag('help', abbr: 'h', negatable: false, help: 'Show this help.');

ArgParser _toolsParser({bool setup = false}) {
  final a = ArgParser()
    ..addOption('lang', abbr: 'l', allowed: ['en', 'ar'], help: 'Output language (default: system).')
    ..addFlag('help', abbr: 'h', negatable: false, help: 'Show this help.');
  if (setup) {
    a
      ..addFlag('yes', abbr: 'y', negatable: false, help: 'Install without asking first.')
      ..addFlag('aab', negatable: false, help: 'Also install bundletool (for auditing .aab).')
      ..addFlag('remove', negatable: false, help: "Delete what aegis installed under ~/.aegis and exit.");
  }
  return a;
}

ArgParser _rootParser() => _parser()
  ..addCommand('run', _parser(run: true))
  ..addCommand('init', _initParser())
  ..addCommand('doctor', _toolsParser())
  ..addCommand('setup', _toolsParser(setup: true))
  ..addCommand('probe', _probeParser());

ArgParser _probeParser() => ArgParser()
  ..addOption('lang', abbr: 'l', allowed: ['en', 'ar'], help: 'Output language (default: system).')
  ..addOption('project',
      help: "The app's Flutter project, for its aegis.yaml (default: found from the APK's location).")
  ..addOption('profile', help: "MAS profile (default: the project's aegis.yaml, else L1).")
  ..addOption('probe-cert-sha256',
      help: 'Expected app signing certificate SHA-256 for --probe-apk (hex).')
  ..addOption('probe-apk', help: 'For an AAB, the corresponding signed APK, .apks archive or device-specific APK directory.')
  ..addOption('control-avd', help: 'Dedicated Aegis AVD for the control launch.')
  ..addOption('root-avd', help: 'Dedicated rooted Aegis AVD for the root comparison.')
  ..addMultiOption('only',
      allowed: ['root', 'debugger', 'hooking', 'repackage'],
      help: 'Run only these checks.')
  ..addFlag('help', abbr: 'h', negatable: false, help: 'Show this help.');

/// `ar` when the system language is Arabic, else `en`.
String _systemLang() {
  try {
    return Platform.localeName.toLowerCase().startsWith('ar') ? 'ar' : 'en';
  } catch (_) {
    return 'en';
  }
}



Future<void> main(List<String> arguments) async {
  final parser = _rootParser();
  final ArgResults root;
  try {
    root = parser.parse(arguments);
  } on FormatException catch (e) {
    stderr.writeln(e.message);
    stderr.writeln('Run "aegis --help" for usage.');
    exit(2);
  }

  if (root.command?.name == 'init') {
    await _init(root.command!);
    return;
  }
  if (root.command?.name == 'doctor') {
    exit(await _doctor(root.command!));
  }
  if (root.command?.name == 'setup') {
    exit(await _setup(root.command!));
  }
  if (root.command?.name == 'probe') {
    exit(await _probe(root.command!));
  }
  final run = root.command?.name == 'run';
  final args = run ? root.command! : root;

  if (args['help'] as bool) {
    stdout.writeln('aegis $aegisVersion - security audit for Flutter apps\n');
    if (run) {
      stdout.writeln('Usage: aegis run [project-path] [--mode all|code|apk|aab] [options]\n');
      stdout.writeln('Audits the project with the settings in aegis.yaml, prints the report and writes');
      stdout.writeln('build/aegis-report.html and opens it (--no-open to skip).\n');
      stdout.writeln('--mode apk|aab|all audits the file set in aegis.yaml (relative to the project):');
      stdout.writeln('  apk: build/app/outputs/flutter-apk/app-release.apk');
      stdout.writeln('  aab: build/app/outputs/bundle/release/app-release.aab');
      stdout.writeln('and first runs the resilience probe on the two Aegis emulators (see');
      stdout.writeln('"aegis setup"). Its results are rules AEG-R01..R04 in the same report.\n');
      stdout.writeln(parser.commands['run']!.usage);
    } else {
      stdout.writeln('Usage:');
      stdout.writeln('  aegis init                  Create aegis.yaml (app type and language) once per project.');
      stdout.writeln('  aegis setup [--yes]         Install the resilience-probe tools once per machine');
      stdout.writeln('                              (what you already have is skipped).');
      stdout.writeln('  aegis doctor                Check those tools without changing anything.');
      stdout.writeln('  aegis run [--mode MODE]     Audit with friendly defaults: all, code, apk or aab.');
      stdout.writeln('  aegis probe                 Only the resilience probe on the apk:/aab: in aegis.yaml.');
      stdout.writeln('  aegis [project-path] [options]   Full control, for CI.\n');
      stdout.writeln(parser.usage);
    }
    return;
  }
  if (args['version'] as bool) {
    stdout.writeln('aegis $aegisVersion');
    return;
  }
  if (args['list-rules'] as bool) {
    _listRules((args['lang'] as String?) ?? 'en');
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
      stderr.writeln('Unknown profile "$profileArg". Use l1, l2, l1+r, l2+r or a preset like banking.');
      exit(2);
    }
    config = config.copyWith(profile: profile);
  }
  if (args['lang'] != null) {
    config = config.copyWith(lang: args['lang'] as String);
  } else if (run && !config.langSet) {
    config = config.copyWith(lang: _systemLang());
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

  var apkPath = args['apk'] as String?;
  if (run && apkPath == null) {
    // The file comes from aegis.yaml only: build names and folders change
    // between projects and flavors, so aegis never guesses one from build/.
    final mode = args['mode'] as String;
    final key = switch (mode) {
      'apk' => 'apk',
      'aab' => 'aab',
      'all' => config.apk != null ? 'apk' : (config.aab != null ? 'aab' : null),
      _ => null,
    };
    final value = key == 'apk' ? config.apk : (key == 'aab' ? config.aab : null);
    if (value != null) {
      final resolved = AegisConfig.resolve(p.absolute(path), value)!;
      if (!File(resolved).existsSync()) {
        final build = key == 'apk' ? 'flutter build apk --release' : 'flutter build appbundle --release';
        stderr.writeln('File not found: $resolved');
        stderr.writeln('(from "$key: $value" in aegis.yaml). Build it ($build) or fix the path.');
        exit(2);
      }
      apkPath = resolved;
      stdout.writeln('aegis: auditing the code and ${p.relative(resolved, from: path)}');
    } else if (mode == 'apk' || mode == 'aab') {
      final example = mode == 'apk'
          ? '$flutterApkDir/app-release.apk'
          : '$flutterBundleDir/release/app-release.aab';
      stderr.writeln('--mode $mode needs the file\'s path in aegis.yaml, relative to the project, e.g.:');
      stderr.writeln('  $mode: $example');
      exit(2);
    } else if (mode == 'all') {
      stdout.writeln('aegis: no apk:/aab: in aegis.yaml, auditing the code only');
    }
    if (config.file == null) {
      stdout.writeln('aegis: no aegis.yaml, using profile ${config.profile}. Run "aegis init" to set your app type.');
    }
  }
  if (apkPath != null && !File(apkPath).existsSync()) {
    stderr.writeln('File not found: $apkPath');
    exit(2);
  }

  final baselineArg = args['baseline'] as String?;
  final baselineFile = baselineArg ??
      p.join(path, config.baseline ?? defaultBaselineFile);
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
      stderr.writeln('Baseline not found: $baselineArg (create it with --update-baseline)');
      exit(2);
    }
  }

  // `aegis run` with an app runs the resilience probe first; its results are
  // rules AEG-R01..R04 in the same report. Plain `aegis` (CI) never does.
  ProbeOutcome? probe;
  if (run && apkPath != null && File(apkPath).existsSync()) {
    final ar = config.lang == 'ar';
    final outcome = (args['probe'] as bool)
        ? await _runProbe(apkPath, lang: config.lang, config: config, projectRoot: p.absolute(path),
            signedApk: args['probe-apk'] as String?,
            expectedSigner: args['probe-cert-sha256'] as String?,
            rootAvd: (args['root-avd'] as String?) ?? avdName,
            controlAvd: (args['control-avd'] as String?) ?? controlAvdName)
        : ProbeOutcome.skipped(ar ? 'اتقفل بـ --no-probe' : 'turned off with --no-probe', requested: false);
    probe = outcome;
    if (outcome.skipped != null) {
      stdout.writeln(ar
          ? 'aegis: اختبار الحماية اتخطّى (${outcome.skipped})، الفحص الثابت بس'
          : 'aegis: resilience probe skipped (${outcome.skipped}), static checks only');
    }
  }

  final AuditReport report;
  try {
    report = await runAudit(path,
        config: config,
        offline: args['offline'] as bool,
        apkPath: apkPath,
        baseline: baseline,
        probe: probe);
  } on FileSystemException catch (e) {
    stderr.writeln('${e.message}: ${e.path}');
    if (apkPath == null) stderr.writeln('Tip: use --apk <file> to audit a compiled APK without the source.');
    exit(2);
  } on FormatException catch (e) {
    stderr.writeln('Could not read ${apkPath ?? 'the file'}: ${e.message}');
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
    stdout.writeln('Baseline: ${b.total} findings (${b.entries.length} entries) written to ${file.path}');
    stdout.writeln('Commit this file. From now on, only new findings trigger --fail-on.');
    exit(0);
  }

  final failing = strictFailure || (config.failOn != null && report.countAtLeast(config.failOn!) > 0) ||
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
    final color = (args['color'] as bool) && stdout.hasTerminal && stdout.supportsAnsiEscapes;
    stdout.write(ConsoleReporter(lang: lang, color: color, verbose: args['verbose'] as bool)
        .render(report));
  }
  if (formats.contains('azure')) {
    stdout.write(renderAzure(report, failOn: config.failOn, failing: failing));
  }
  for (final w in written) {
    stdout.writeln('Report: $w');
  }
  if (run && (args['open'] as bool) && formats.contains('html') && stdout.hasTerminal) {
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
    stderr.writeln('aegis: score ${report.score.value} is below the minimum ${config.minScore}.');
    code = 1;
  }

  if (report.incomplete.isNotEmpty) {
    stderr.writeln('aegis: incomplete checks: ${report.incomplete.map((r) => r.meta.id).join(', ')}.');
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

void _listRules(String lang) {
  for (final r in [...allRules, ...apkRules]) {
    final m = r.meta;
    final profiles = m.profiles.map((x) => x.name.toUpperCase()).join('/');
    stdout.writeln('${m.id.padRight(8)} ${m.severity.name.padRight(8)} ${profiles.padRight(9)} '
        '${m.title.of(lang)}  [${m.masvs.join(', ')}]');
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

const _appTypes = [
  ('l1', 'Normal app, no sensitive data', 'تطبيق عادي، مفيهوش بيانات حساسة'),
  ('l2', 'Personal or business data (accounts, HR, health)', 'بيانات شخصية أو بيانات شغل (حسابات، HR، صحة)'),
  ('l2+r', 'Banking, payments or government', 'بنوك أو مدفوعات أو جهات حكومية'),
  ('l1+r', 'Game or app that must resist tampering', 'لعبة أو تطبيق لازم يقاوم التعديل والغش'),
];

Future<void> _init(ArgResults args) async {
  if (args['help'] as bool) {
    stdout.writeln('Usage: aegis init [project-path] [--profile P] [--lang en|ar] [--force]\n');
    stdout.writeln('Writes aegis.yaml so that "aegis run" needs no options.\n');
    stdout.writeln(_initParser().usage);
    return;
  }
  final root = args.rest.isEmpty ? '.' : args.rest.first;
  final file = File(p.join(root, AegisConfig.fileName));
  if (file.existsSync() && !(args['force'] as bool)) {
    stderr.writeln('${file.path} already exists. Edit it, or use --force to overwrite it.');
    exit(2);
  }
  final lang = (args['lang'] as String?) ?? _systemLang();
  final ar = lang == 'ar';

  var profile = args['profile'] as String?;
  if (profile != null && ProfileSet.tryParse(profile) == null) {
    stderr.writeln('Unknown profile "$profile". Use l1, l2, l1+r, l2+r or a preset like banking.');
    exit(2);
  }
  if (profile == null) {
    if (!stdin.hasTerminal) {
      profile = 'l1';
    } else {
      stdout.writeln(ar ? 'نوع التطبيق إيه؟' : 'What kind of app is it?');
      for (var i = 0; i < _appTypes.length; i++) {
        final (id, en, arText) = _appTypes[i];
        stdout.writeln('  ${i + 1}) ${ar ? arText : en}  ($id)');
      }
      while (profile == null) {
        stdout.write(ar ? 'اختار رقم [1-${_appTypes.length}]: ' : 'Choose [1-${_appTypes.length}]: ');
        // Arabic keyboards send ٣ instead of 3, and some terminals send bytes
        // that are not valid UTF-8; neither should crash the prompt.
        String? line;
        try {
          line = stdin.readLineSync(encoding: const Utf8Codec(allowMalformed: true));
        } catch (_) {
          line = null;
        }
        if (line == null) {
          stderr.writeln('No answer: use aegis init --profile l1|l2|l2+r|l1+r');
          exit(2);
        }
        final n = parseMenuChoice(line, _appTypes.length);
        if (n != null) profile = _appTypes[n - 1].$1;
      }
    }
  }

  file.writeAsStringSync('''
# aegis settings: https://github.com/khaledSayedAbdellah/aegis
# l1: any app · l2: sensitive data · +r: resist tampering and reverse engineering
profile: $profile
lang: $lang
# The run fails (exit code 1) on a new finding at or above this severity.
fail_on: high
# The release build to audit with `aegis run --mode apk|aab|all` (static checks
# plus the resilience probe on the emulator). Relative to this folder; update it
# when the path changes (flavor, version in the file name).
# apk: build/app/outputs/flutter-apk/app-release.apk
# aab: build/app/outputs/bundle/release/app-release.aab
# For the AAB probe, supply the APK for the same build and its expected
# app-signing certificate fingerprint. CLI flags override these settings.
# probe_apk: build/app/outputs/flutter-apk/app-release.apk  # Or a signed .apks archive / device-specific APK directory
# probe_cert_sha256: "your-app-signing-certificate-sha256-in-hex"
''');
  stdout.writeln(ar
      ? '''اتعمل ${file.path}.

الخطوات الجاية:
  1. aegis setup   مرة واحدة على الجهاز: بيسطّب الإيموليتر والأدوات اللي اختبار الحماية
                   (probe) محتاجها، وبيتخطّى أي حاجة موجودة. من غيره aegis run بيعمل
                   الفحص الثابت بس للـ APK/AAB.
  2. حط مسار نسخة الـ release في aegis.yaml:  apk: build/app/outputs/flutter-apk/app-release.apk
  3. aegis run'''
      : '''Wrote ${file.path}.

Next:
  1. aegis setup   Once per machine: installs both emulators and the tools the resilience
                   probe needs, skipping what you already have. Without it, aegis run
                   does only the static checks of the APK/AAB.
  2. Set your release build's path in aegis.yaml:  apk: build/app/outputs/flutter-apk/app-release.apk
  3. aegis run''');
}

// --- doctor -----------------------------------------------------------------

String _toolsLang(ArgResults a) => (a['lang'] as String?) ?? _systemLang();

/// The icon for a tool's state. [blocked] is an installable tool whose
/// dependencies are not present yet.
String _mark(ToolCheck c, {bool blocked = false}) => switch (c.state) {
      ToolState.present => '✅',
      ToolState.installable => blocked ? '⏸️ ' : '⬇️ ',
      ToolState.manual => '❌',
      ToolState.optional => 'ℹ️ ',
    };

/// Renders the detail column for one tool. [blocked] are the dependencies
/// that keep it from being installed this run (from the setup plan).
String _detail(ToolCheck c, Msg m, Toolchain t, List<String>? blocked) {
  if (c.ok) {
    return [
      if (c.version != null) c.version!,
      if (c.path != null) t.tilde(c.path!),
      if (c.source != null) '(${c.source})',
    ].join('  ');
  }
  if (blocked != null) return m.waitingFor(blocked);
  if (c.installable) return m.installHintFor(c.id);
  return m.issue(c);
}

/// The table of tools. An installable tool is ⏸️ only when something it
/// needs can't be installed in the same run (the person installs it first).
void _printChecks(List<ToolCheck> checks, Msg m, Toolchain t) {
  final blocked = Setup(t).buildPlan(checks).blocked;
  final w = checks.map((c) => m.title(c.id).length).fold(0, (a, b) => a > b ? a : b);
  for (final c in checks) {
    final b = blocked[c.id];
    stdout.writeln('  ${_mark(c, blocked: b != null)} ${m.title(c.id).padRight(w)}  ${_detail(c, m, t, b)}');
  }
}

Future<int> _doctor(ArgResults a) async {
  final m = Msg(_toolsLang(a));
  if (a['help'] as bool) {
    stdout.writeln('Usage: aegis doctor [--lang en|ar]\n');
    stdout.writeln('Checks the tools the resilience probe needs. Changes nothing.');
    stdout.writeln('Exit code 0 when everything required is present.\n');
    stdout.writeln(_toolsParser().usage);
    return 0;
  }
  final t = Toolchain(SystemHost());
  final checks = await t.checkAll();
  stdout.writeln(m.header);
  _printChecks(checks, m, t);
  stdout.writeln('');

  final required = checks.where((c) => c.state != ToolState.optional);
  final missing = required.where((c) => !c.ok).toList();
  if (missing.isEmpty) {
    stdout.writeln(m.allPresent);
    return 0;
  }
  final installable = Setup(t).buildPlan(checks).steps.length;
  if (installable > 0) stdout.writeln('⬇️  ${m.toInstall(installable)}');
  if (missing.any((c) => c.state == ToolState.manual)) stdout.writeln('❌ ${m.someManual}');
  return 1;
}

// --- setup ------------------------------------------------------------------

Future<int> _setup(ArgResults a) async {
  final m = Msg(_toolsLang(a));
  if (a['help'] as bool) {
    stdout.writeln('Usage: aegis setup [--yes] [--aab] [--remove] [--lang en|ar]\n');
    stdout.writeln('Installs what "aegis doctor" reports as missing. Tools already present are');
    stdout.writeln('skipped. Asks once before installing; --yes skips the question.');
    stdout.writeln('--remove deletes what aegis installed (never your Java or Android SDK).\n');
    stdout.writeln(_toolsParser(setup: true).usage);
    return 0;
  }
  final aab = a['aab'] as bool;
  final t = Toolchain(SystemHost());
  final setup = Setup(t);

  if (a['remove'] as bool) {
    final removed = await setup.remove();
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
  var checks = await t.checkAll(aab: aab);
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
  if (!aab) {
    for (final c in plan.optional) {
      stdout.writeln('  ℹ️  ${m.title(c.id)}: ${m.issue(c)}');
    }
  }

  if (plan.nothingToDo) {
    setup.writeToolsJson(checks);
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
      line = stdin.readLineSync(encoding: const Utf8Codec(allowMalformed: true));
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
      stdout.writeln('⚠️  ${m.freeSpaceWarning('$estimatedGiB GB', '${(free / (1 << 30)).toStringAsFixed(1)} GB')}');
    }
  }

  final outcomes = await setup.execute(plan,
      onStep: (id) => stdout.writeln('\n▶ ${m.step(m.title(id))}'),
      log: (s) => stdout.writeln('    $s'));
  for (final o in outcomes) {
    if (o.skipped) {
      stdout.writeln('  ⏸️  ${m.title(o.id)}: ${m.waitingFor(o.skippedFor ?? const [])}');
    } else if (o.ok) {
      stdout.writeln('  ✅ ${m.title(o.id)}');
    } else {
      stdout.writeln('  ❌ ${m.title(o.id)}: ${o.error}');
    }
  }

  checks = await t.checkAll(aab: aab);
  setup.writeToolsJson(checks);
  stdout.writeln('\n${m.result}');
  _printChecks(checks, m, t);
  final ok = checks.where((c) => c.state != ToolState.optional).every((c) => c.ok);
  stdout.writeln('');
  stdout.writeln(ok ? m.savedTo(t.toolsJsonPath) : m.stillMissing);
  return ok ? 0 : 1;
}

// --- probe ------------------------------------------------------------------

Future<int> _probe(ArgResults a) async {
  final lang = (a['lang'] as String?) ?? _systemLang();
  final ar = lang == 'ar';
  if (a['help'] as bool) {
    stdout.writeln('Usage: aegis probe [app.apk|app.aab] [--project DIR] [--profile P] [--only root,hooking] [--lang en|ar]\n');
    stdout.writeln('Runs only the resilience probe: the app on the aegis-probe emulator, checking');
    stdout.writeln('whether its own anti-tampering reacts to the standard MASTG conditions.');
    stdout.writeln('The app is apk: (else aab:) in the project\'s aegis.yaml, unless a path is given.');
    stdout.writeln('"aegis run --mode apk" runs the same probe and puts it in the full report.');
    stdout.writeln('Run "aegis setup" first to install the emulator and tools.\n');
    stdout.writeln(_probeParser().usage);
    return 0;
  }

  // The app: a positional path, else apk:/aab: in the project's aegis.yaml.
  // The project is --project, else the one the given file sits in, else the
  // current folder; its aegis.yaml also gives the profile.
  final projectArg = a['project'] as String?;
  var appPath = a.rest.isNotEmpty ? a.rest.first : null;
  final projectDir = projectArg ?? (appPath == null ? null : projectOf(appPath)) ?? '.';
  AegisConfig config;
  try {
    config = AegisConfig.load(p.absolute(projectDir));
  } on FormatException catch (e) {
    stderr.writeln(e.message);
    return 2;
  }
  if (appPath == null) {
    final value = config.apk ?? config.aab;
    if (value == null) {
      stderr.writeln(ar
          ? 'حدّد مسار التطبيق في aegis.yaml (نسبةً للمشروع)، مثلًا:\n  apk: $flutterApkDir/app-release.apk\nأو مرّره: aegis probe path/to/app.apk'
          : 'Set the app\'s path in aegis.yaml (relative to the project), e.g.:\n  apk: $flutterApkDir/app-release.apk\nor pass it: aegis probe path/to/app.apk');
      return 2;
    }
    appPath = AegisConfig.resolve(p.absolute(projectDir), value)!;
  }
  if (!File(appPath).existsSync()) {
    stderr.writeln('File not found: $appPath');
    return 2;
  }

  final profileArg = a['profile'] as String?;
  if (profileArg != null) {
    final profile = ProfileSet.tryParse(profileArg);
    if (profile == null) {
      stderr.writeln('Unknown profile "$profileArg". Use l1, l2, l1+r, l2+r or a preset.');
      return 2;
    }
    config = config.copyWith(profile: profile);
  }
  final profileFrom = profileArg != null
      ? '--profile'
      : (config.file != null ? p.relative(config.file!) : (ar ? 'الافتراضي' : 'default'));
  stdout.writeln(ar
      ? 'الـ profile: ${config.profile} (من $profileFrom)'
      : 'Profile: ${config.profile} (from $profileFrom)');

  bool? obfuscated;
  try {
    obfuscated = _looksObfuscated(ApkContext.load(appPath));
  } on FormatException catch (e) {
    stderr.writeln(e.message);
    return 2;
  }

  final only = (a['only'] as List<String>).toSet();
  final outcome = await _runProbe(appPath, lang: lang, config: config, projectRoot: p.absolute(projectDir),
      only: only.isEmpty ? null : only,
      signedApk: a['probe-apk'] as String?, expectedSigner: a['probe-cert-sha256'] as String?, rootAvd: a['root-avd'] as String?, controlAvd: a['control-avd'] as String?);
  final report = outcome.report;
  if (report == null) {
    stderr.writeln(outcome.skipped);
    return 2;
  }
  stdout.writeln('');
  stdout.write(renderProbe(report, lang: lang, resilienceProfile: config.profile.resilience));
  if (obfuscated != null) {
    final mode = appPath.toLowerCase().endsWith('.aab') ? 'aab' : 'apk';
    stdout.writeln('');
    stdout.writeln(obfuscated
        ? (ar
            ? 'ثابت (هندسة عكسية): النسخة دي معمولّها obfuscation ✅'
            : 'Static (reverse engineering): this build is obfuscated ✅')
        : (ar
            ? 'ثابت (هندسة عكسية): النسخة دي مش معمولّها obfuscation ❌ — كود Dart مقروء. شغّل "aegis run --mode $mode" للتقرير الكامل (AEG-B07).'
            : 'Static (reverse engineering): this build is NOT obfuscated ❌ — the Dart code is readable. Run "aegis run --mode $mode" for the full report (AEG-B07).'));
  }
  return probeExitCode(report, resilienceProfile: config.profile.resilience);
}

/// Runs the probe on an installable APK with its original signing identity.
Future<ProbeOutcome> _runProbe(String appPath, {
  required String lang,
  required AegisConfig config,
  required String projectRoot,
  Set<String>? only,
  String? signedApk,
  String? expectedSigner,
  String? rootAvd,
  String? controlAvd,
}) async {
  final ar = lang == 'ar';
  String? expectedDigest;
  late final ApkContext input;
  ApkContext? companion;
  var useApkArchive = false;
  var useApkDirectory = false;
  try {
    input = ApkContext.load(appPath);
    if (input.isBundle) {
      signedApk ??= AegisConfig.resolve(projectRoot, config.probeApk);
      expectedSigner ??= config.probeCertSha256;
      if (expectedSigner != null) {
        expectedDigest = normalizeCertificateSha256(expectedSigner);
        if (expectedDigest == null) {
          return const ProbeOutcome.skipped(
              '--probe-cert-sha256 or probe_cert_sha256 must be a SHA-256 certificate fingerprint in hex.');
        }
      }
      if (signedApk == null) {
        return const ProbeOutcome.skipped(
            'For an AAB, supply the corresponding signed APK or APK set with --probe-apk or probe_apk in aegis.yaml.');
      }
      useApkDirectory = Directory(signedApk).existsSync();
      useApkArchive = !useApkDirectory && signedApk.toLowerCase().endsWith('.apks');
      if (!useApkArchive && !useApkDirectory) {
        final apk = ApkContext.load(signedApk);
        if (apk.isBundle || apk.packageName != input.packageName ||
            apk.versionCode == null || apk.versionCode != input.versionCode ||
            apk.manifest!.rootElement.getAttribute('split')?.isNotEmpty == true) {
          return const ProbeOutcome.skipped(
              '--probe-apk must have the same package name and version code as the AAB. Supply all splits as a .apks archive or a device-specific APK directory.');
        }
        companion = apk;
      }
    } else {
      if (signedApk != null || expectedSigner != null) {
        return const ProbeOutcome.skipped('--probe-apk and --probe-cert-sha256 are only used when auditing an AAB.');
      }
    }
  } on FileSystemException catch (e) {
    return ProbeOutcome.skipped('${e.message}: ${e.path}');
  } on FormatException catch (e) {
    return ProbeOutcome.skipped(e.message);
  }
  final dedicatedName = RegExp(r'^aegis-probe(?:-[\w-]+)?$');
  if ([rootAvd, controlAvd].whereType<String>().any((name) => !dedicatedName.hasMatch(name)) ||
      rootAvd == (controlAvd ?? avdName)) {
    return const ProbeOutcome.skipped('Use distinct, dedicated aegis-probe emulator names.');
  }

  final host = SystemHost();
  final toolchain = Toolchain(host);
  final tools = await ProbeTools.resolve(host, toolchain);
  final missing = tools.missing(only: only);
  if (signedApk != null && tools.apksigner == null && !missing.contains('apksigner')) {
    missing.add('apksigner');
  }
  if (useApkArchive && !host.fileExists(toolchain.bundletoolPath)) missing.add('bundletool');
  if (useApkArchive && tools.javaHome == null) missing.add('Java');
  if (missing.isNotEmpty) {
    return ProbeOutcome.skipped(ar
        ? 'ناقص ${missing.join('، ')}؛ شغّل "aegis setup${useApkArchive ? ' --aab' : ''}"'
        : 'missing ${missing.join(', ')}; run "aegis setup${useApkArchive ? ' --aab' : ''}"');
  }

  final work = Directory.systemTemp.createTempSync('aegis-probe-');
  final lock = File(p.join(toolchain.aegisDir, 'probe.lock'));
  RandomAccessFile? guard;
  try {
    lock.parent.createSync(recursive: true);
    guard = lock.openSync(mode: FileMode.append);
    guard.lockSync(FileLock.exclusive);
  } on FileSystemException {
    guard?.closeSync();
    work.deleteSync(recursive: true);
    return const ProbeOutcome.skipped('Could not lock the probe emulators; another probe may be running.');
  }
  try {
    final device = Device(host, tools, avdName: controlAvd);
    final rootDevice = rootAvd == null ? null : Device(host, tools, avdName: rootAvd);
    void log(String message) => stdout.writeln('  · $message');
    ProbeApkIdentity? apkIdentity;
    var installed = companion ?? input;
    var runtimePath = installed.path;
    var splits = const <String>[];
    List<String>? rootedApks;
    if (signedApk != null) {
      try {
        if (useApkArchive || useApkDirectory) {
          final bundletool = useApkArchive ? toolchain.bundletoolPath : null;
          final staged = useApkArchive
              ? File(signedApk).copySync(p.join(work.path, 'verified.apks')).path
              : stageSelectedApks(signedApk, p.join(work.path, 'verified-apks'));
          final control = await prepareProbeApkSet(device, staged,
              p.join(work.path, 'control-apks'), bundle: input,
              bundletool: bundletool, expectedSigner: expectedDigest, log: log);
          installed = control.base;
          runtimePath = installed.path;
          splits = control.splits;
          if (rootDevice != null &&
              (only == null || only.contains('root') || only.contains('hooking'))) {
            final rooted = await prepareProbeApkSet(rootDevice, staged,
                p.join(work.path, 'rooted-apks'), bundle: input,
                bundletool: bundletool, expectedSigner: expectedDigest, log: log);
            if (!sameApkSigners(control.identity, rooted.identity)) {
              return const ProbeOutcome.skipped('The emulator APK sets have different signing certificates.');
            }
            rootedApks = [rooted.base.path, ...rooted.splits];
          }
          apkIdentity = ProbeApkIdentity(
            signerSha256: control.identity.signerSha256,
            expectedSignerSha256: expectedDigest,
            controlApks: [p.basename(runtimePath), ...splits.map(p.basename)],
            rootedApks: rootedApks?.map(p.basename).toList() ?? const [],
          );
        } else {
          // Verify and install the same bytes even if a build replaces the input.
          runtimePath = p.join(work.path, 'verified.apk');
          File(runtimePath).writeAsBytesSync(installed.archive.bytes);
          apkIdentity = await verifyProbeApk(host, tools.apksigner!, runtimePath,
              expectedCertificateSha256: expectedDigest, javaHome: tools.javaHome);
        }
      } on FormatException catch (e) {
        return ProbeOutcome.skipped(e.message);
      } on FileSystemException catch (e) {
        return ProbeOutcome.skipped('Could not stage the probe APK files: ${e.message}');
      } on StateError catch (e) {
        return ProbeOutcome.skipped(e.message);
      }
    }
    final package = installed.packageName!;
    final controlName = controlAvd ?? tools.avdName;
    stdout.writeln(ar
        ? 'بيشغّل $package على إيموليتر $controlName… (ممكن ياخد دقيقة)'
        : 'Running $package on the $controlName emulator… (this can take a minute)');
    final app = installed.application;
    final report = await ProbeRunner(device, rootDevice: rootDevice).run(
        appPath: runtimePath,
        appLabel: useApkDirectory ? p.normalize(p.absolute(signedApk!)) : signedApk ?? installed.path,
        apkIdentity: apkIdentity,
        splits: splits, rootedApks: rootedApks,
        package: package, workDir: work.path,
        only: only,
        debuggable: app != null && androidAttr(app, 'debuggable') == 'true',
        log: log);
    return ProbeOutcome.ran(report);
  } finally {
    guard.closeSync();
    try {
      work.deleteSync(recursive: true);
    } catch (_) {}
  }
}

/// A quick obfuscation signal for the probe's static line: a non-obfuscated
/// Flutter build keeps its source paths (package:.../*.dart) in libapp.so,
/// which --obfuscate strips. Null when there is no libapp.so to judge.
/// The full check is AEG-B07 in the APK audit.
bool? _looksObfuscated(ApkContext apk) {
  if (apk.libappEntry == null) return null;
  final sourcePaths = apk.libappStrings
      .where((s) => s.startsWith('package:') && s.endsWith('.dart'))
      .length;
  return sourcePaths < 20;
}

