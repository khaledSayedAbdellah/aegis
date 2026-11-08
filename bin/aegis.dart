import 'dart:convert';
import 'dart:io';

import 'package:aegis/aegis.dart';
import 'package:aegis/src/probe/device.dart';
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
/// defaults: an HTML report next to the console output, and the APK/AAB is
/// found in build/ instead of being passed with --apk.
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
        'all': 'Code + the newest release APK/AAB in build/ (code only when none is built).',
        'code': 'Dart code, packages and Android/iOS configuration only.',
        'apk': 'Code + the newest release APK in build/app/outputs/flutter-apk/.',
        'aab': 'Code + the newest release AAB in build/app/outputs/bundle/.',
      },
      help: 'What to audit.')
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
      ..addFlag('aab', negatable: false, help: 'Also install bundletool (for auditing .aab).');
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
  ..addOption('profile', help: 'MAS profile (default: aegis.yaml, else L1).')
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
      stdout.writeln('build/aegis-report.html and opens it (--no-open to skip). The APK/AAB is taken');
      stdout.writeln('from build/, no path needed.\n');
      stdout.writeln(parser.commands['run']!.usage);
    } else {
      stdout.writeln('Usage:');
      stdout.writeln('  aegis init                  Create aegis.yaml (app type and language) once.');
      stdout.writeln('  aegis run [--mode MODE]     Audit with friendly defaults: all, code, apk or aab.');
      stdout.writeln('  aegis doctor                Check the tools the resilience probe needs.');
      stdout.writeln('  aegis setup [--yes]         Install the missing ones (present ones are skipped).');
      stdout.writeln('  aegis probe [app.apk]       Check on an emulator whether the app resists tampering.');
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
    final mode = args['mode'] as String;
    final File? found = switch (mode) {
      'apk' => findBuiltBinary(path, 'apk'),
      'aab' => findBuiltBinary(path, 'aab'),
      'all' => findNewestBinary(path),
      _ => null,
    };
    if (found != null) {
      apkPath = found.path;
      stdout.writeln('aegis: auditing the code and ${p.relative(found.path, from: path)}');
    } else if (mode == 'apk' || mode == 'aab') {
      final build = mode == 'apk' ? 'flutter build apk --release' : 'flutter build appbundle --release';
      final dir = mode == 'apk' ? flutterApkDir : flutterBundleDir;
      stderr.writeln('No release ${mode.toUpperCase()} in $dir. Build one first: $build');
      exit(2);
    } else if (mode == 'all') {
      stdout.writeln('aegis: no release APK/AAB in build/, auditing the code only');
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

  final AuditReport report;
  try {
    report = await runAudit(path,
        config: config,
        offline: args['offline'] as bool,
        apkPath: apkPath,
        baseline: baseline);
  } on FileSystemException catch (e) {
    stderr.writeln('${e.message}: ${e.path}');
    if (apkPath == null) stderr.writeln('Tip: use --apk <file> to audit a compiled APK without the source.');
    exit(2);
  } on FormatException catch (e) {
    stderr.writeln('Could not read ${apkPath ?? 'the file'}: ${e.message}');
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

  final failing = (config.failOn != null && report.countAtLeast(config.failOn!) > 0) ||
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
''');
  stdout.writeln(ar
      ? 'اتعمل ${file.path}. شغّل: aegis run'
      : 'Wrote ${file.path}. Now run: aegis run');
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
    stdout.writeln(m.allPresent(m.ar));
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
    stdout.writeln('Usage: aegis setup [--yes] [--aab] [--lang en|ar]\n');
    stdout.writeln('Installs what "aegis doctor" reports as missing. Tools already present are');
    stdout.writeln('skipped. Asks once before installing; --yes skips the question.\n');
    stdout.writeln(_toolsParser(setup: true).usage);
    return 0;
  }
  final aab = a['aab'] as bool;
  final t = Toolchain(SystemHost());
  final setup = Setup(t);
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
    stdout.writeln(plan.coversEverything ? m.allPresent(m.ar) : m.someManual);
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

  // Warn (don't block) when the system image won't fit.
  if (plan.steps.any((s) => s.id == 'system-image')) {
    final root = (await t.findSdkRoot())?.path;
    final free = root == null ? null : await SystemHost().freeBytes(root);
    if (free != null && free < 4 * 1024 * 1024 * 1024) {
      stdout.writeln('⚠️  ${m.freeSpaceWarning('4 GB', '${(free / (1 << 30)).toStringAsFixed(1)} GB')}');
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
    stdout.writeln('Usage: aegis probe [app.apk] [--profile P] [--only root,hooking] [--lang en|ar]\n');
    stdout.writeln('Runs the app on the aegis-probe emulator and checks whether its own');
    stdout.writeln('anti-tampering reacts to the standard MASTG resilience conditions.');
    stdout.writeln('Run "aegis setup" first to install the emulator and tools.\n');
    stdout.writeln(_probeParser().usage);
    return 0;
  }

  const projectDir = '.';
  AegisConfig config;
  try {
    config = AegisConfig.load(p.absolute(projectDir));
  } on FormatException catch (e) {
    stderr.writeln(e.message);
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

  // Resolve the app: a positional path, else the newest release build.
  final rest = a.rest;
  var appPath = rest.isNotEmpty ? rest.first : findNewestBinary(projectDir)?.path;
  if (appPath == null) {
    stderr.writeln(ar
        ? 'مفيش APK/AAB. ابنيه الأول أو مرّر مساره: aegis probe path/to/app.apk'
        : 'No APK/AAB found. Build one or pass its path: aegis probe path/to/app.apk');
    return 2;
  }
  if (!File(appPath).existsSync()) {
    stderr.writeln('File not found: $appPath');
    return 2;
  }
  if (appPath.toLowerCase().endsWith('.aab')) {
    stderr.writeln(ar
        ? 'الـ probe بياخد APK دلوقتي. ابني APK (flutter build apk --release) ومرّره.'
        : 'probe takes an APK for now. Build one (flutter build apk --release) and pass it.');
    return 2;
  }

  // The package name comes from the app's own manifest.
  String? package;
  try {
    package = ApkContext.load(appPath).packageName;
  } on FormatException catch (e) {
    stderr.writeln(e.message);
    return 2;
  }
  if (package == null) {
    stderr.writeln(ar ? 'مش قادر أقرا اسم الحزمة من التطبيق.' : "Couldn't read the package name from the app.");
    return 2;
  }

  final host = SystemHost();
  final tools = await ProbeTools.resolve(host, Toolchain(host));
  final missing = tools.missing();
  if (missing.isNotEmpty) {
    stderr.writeln(ar
        ? 'ناقص: ${missing.join('، ')}. شغّل "aegis setup" الأول.'
        : 'Missing: ${missing.join(', ')}. Run "aegis setup" first.');
    return 2;
  }

  final only = (a['only'] as List<String>).toSet();
  final work = Directory.systemTemp.createTempSync('aegis-probe-');
  try {
    stdout.writeln(ar
        ? 'بيشغّل $package على إيموليتر aegis-probe… (ممكن ياخد دقيقة)'
        : 'Running $package on the aegis-probe emulator… (this can take a minute)');
    final runner = ProbeRunner(Device(host, tools));
    final report = await runner.run(
        appPath: appPath, package: package, workDir: work.path,
        only: only.isEmpty ? null : only);
    stdout.writeln('');
    stdout.write(renderProbe(report, lang: lang, resilienceProfile: config.profile.resilience));
    return probeExitCode(report, resilienceProfile: config.profile.resilience);
  } finally {
    try {
      work.deleteSync(recursive: true);
    } catch (_) {}
  }
}
