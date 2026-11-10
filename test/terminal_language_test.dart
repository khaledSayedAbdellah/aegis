import 'dart:io';

import 'package:aegis/src/l10n/messages.g.dart';
import 'package:path/path.dart' as p;
import 'package:test/test.dart';

import 'cli_test.dart' show aegisBin, project;

Future<ProcessResult> arabicHost(List<String> args) => Process.run(
      Platform.resolvedExecutable,
      [aegisBin, ...args],
      environment: {'LANG': 'ar_EG.UTF-8', 'LC_ALL': 'ar_EG.UTF-8'},
    );

void expectEnglishTerminal(ProcessResult result) {
  expect('${result.stdout}${result.stderr}',
      isNot(matches(RegExp(r'[\u0600-\u06ff]'))));
}

void main() {
  for (final cliOverride in [false, true]) {
    test(
        'Arabic report files keep English console (CLI override: $cliOverride)',
        () async {
      final dir = project();
      File(p.join(dir.path, 'aegis.yaml'))
          .writeAsStringSync('lang: ${cliOverride ? 'en' : 'ar'}\n');
      final result = await arabicHost([
        'run',
        dir.path,
        '--mode',
        'code',
        '--offline',
        '--no-open',
        '--no-color',
        '-f',
        'console,html,md',
        if (cliOverride) ...['--lang', 'ar'],
      ]);
      expect(result.exitCode, 0, reason: '${result.stdout}${result.stderr}');
      expectEnglishTerminal(result);
      expect(result.stdout, contains(En.i18nAegisSecurityAudit));
      final html =
          File(p.join(dir.path, 'build/aegis-report.html')).readAsStringSync();
      final md =
          File(p.join(dir.path, 'build/aegis-report.md')).readAsStringSync();
      expect(html, contains('lang="ar" dir="rtl"'));
      expect(html, contains(Ar.i18nAegisSecurityAudit));
      expect(md, contains(Ar.i18nAegisSecurityAudit));
    });
  }

  test('Arabic host and language flag do not translate command messages',
      () async {
    final dir = project();
    final commands = <(List<String>, int, String)>[
      (['init', dir.path, '--profile', 'l1', '--lang', 'ar'], 0, 'Wrote'),
      (['run', dir.path, '--lang', 'ar'], 2, En.runModeRequired),
      (['setup', '--lang', 'ar'], 2, En.setupPlatformRequired),
      (['setup', '--help', '--lang', 'ar'], 0, En.setupHelpScope),
      (['doctor', '--help', '--lang', 'ar'], 0, 'Checks the tools'),
      (['--list-rules', '--lang', 'ar'], 0, 'AEG-'),
      (['probe', '--project', dir.path, '--lang', 'ar'], 2, 'Set'),
    ];
    for (final (args, code, message) in commands) {
      final result = await arabicHost(args);
      expect(result.exitCode, code, reason: args.join(' '));
      expectEnglishTerminal(result);
      expect('${result.stdout}${result.stderr}', contains(message));
    }
    expect(File(p.join(dir.path, 'aegis.yaml')).readAsStringSync(),
        contains('lang: ar'));
  });

  test('skipped Android probe prints English but keeps Arabic in report',
      () async {
    final dir = project();
    File('test/fixtures/aab/secure.aab').copySync(p.join(dir.path, 'app.aab'));
    File(p.join(dir.path, 'aegis.yaml'))
        .writeAsStringSync('lang: ar\naab: app.aab\n');
    final result = await arabicHost([
      'run',
      dir.path,
      '--mode',
      'aab',
      '--offline',
      '--no-open',
      '--no-color',
      '-f',
      'console,html',
    ]);
    expectEnglishTerminal(result);
    expect(result.stdout, contains(En.aabCompanionRequired));
    expect(File(p.join(dir.path, 'build/aegis-report.html')).readAsStringSync(),
        contains(Ar.aabCompanionRequired));
  });
}
