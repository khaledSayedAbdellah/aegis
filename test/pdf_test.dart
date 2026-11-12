import 'dart:io';

import 'package:aegis/aegis.dart';
import 'package:aegis/src/reporters/i18n.dart';
import 'package:aegis/src/reporters/pdf.dart';
import 'package:path/path.dart' as p;
import 'package:test/test.dart';

final aegisBin = p.absolute('bin/aegis.dart');

Directory project() {
  final dir = Directory.systemTemp.createTempSync('aegis_pdf_');
  addTearDown(() => dir.deleteSync(recursive: true));
  File(p.join(dir.path, 'pubspec.yaml')).writeAsStringSync(
      'name: app\ndependencies:\n  flutter:\n    sdk: flutter\n');
  File(p.join(dir.path, 'lib', 'main.dart'))
    ..parent.createSync(recursive: true)
    ..writeAsStringSync('void main() {}\n');
  File(p.join(dir.path, 'aegis.yaml')).writeAsStringSync('profile: l2+r\n');
  return dir;
}

Future<ProcessResult> run(Directory dir, List<String> extra,
        {Map<String, String> env = const {}}) =>
    Process.run(Platform.resolvedExecutable, [
      aegisBin,
      'run',
      dir.path,
      '--mode',
      'code',
      '--offline',
      '--no-open',
      ...extra
    ], environment: {
      'LANG': 'en_US.UTF-8',
      'LC_ALL': 'en_US.UTF-8',
      ...env
    });

String today() {
  final now = DateTime.now();
  String two(int v) => v.toString().padLeft(2, '0');
  return '${now.year}-${two(now.month)}-${two(now.day)}';
}

void main() {
  test('the file name is mode, MAS profile and audit date', () {
    final date = DateTime(2026, 3, 7, 23, 59);
    expect(pdfReportName('apk', ProfileSet.tryParse('l2+r')!, date),
        'apk-L2+R-2026-03-07.pdf');
    expect(pdfReportName('code', ProfileSet.tryParse('l1')!, date),
        'code-L1-2026-03-07.pdf');
    expect(pdfReportName('ipa', ProfileSet.tryParse('game')!, date),
        'ipa-L1+R-2026-03-07.pdf');
  });

  test('every collapsed section is expanded for printing', () {
    const html = '<details class="card known"><summary>a</summary></details>'
        '<details class="card" open><summary>b</summary></details>'
        '<details><summary>c</summary></details><p>details</p>';
    final printed = printableHtml(html);
    expect(printed, contains('<details open class="card known">'));
    expect(printed, contains('<details class="card" open>'));
    expect(printed, contains('<details open>'));
    expect(RegExp(r'<details\b').allMatches(printed), hasLength(3));
    expect(RegExp(r'\bopen\b').allMatches(printed), hasLength(3));
  });

  test(
      'the PDF version keeps only the score, category scores and open findings',
      () async {
    final dir = project();
    File(p.join(dir.path, 'lib', 'main.dart')).writeAsStringSync(
        // AWS's documented example key: a finding for aegis, but not a
        // real secret for GitHub push protection.
        'final awsKey = "AKIAIOSFODNN7EXAMPLE";\n'
        'void main() {}\n');
    final report = await runAudit(dir.path, offline: true);
    final t = Strings('en');
    final full = renderHtml(report);
    final compact = renderHtml(report, compact: true);
    expect(report.failed, isNotEmpty);
    for (final kept in [
      t.score,
      '<b>${report.score.value}</b>',
      t.failed,
      'AEG-D01',
      t.why,
      t.fix,
      'class="cat"',
    ]) {
      expect(compact, contains(kept));
    }
    for (final dropped in [
      t.coverage,
      '${t.passed} (',
      t.manual,
      t.disclaimer,
    ]) {
      expect(full, contains(dropped));
      expect(compact, isNot(contains(dropped)));
    }
  });

  group('browser lookup', () {
    test('AEGIS_BROWSER wins and is used as given', () {
      expect(
          findPdfBrowser(environment: {
            'AEGIS_BROWSER': '/missing/chrome',
            'CHROME_PATH': '/other'
          }, operatingSystem: 'linux', exists: (_) => true),
          '/missing/chrome');
      expect(
          findPdfBrowser(
              environment: {'CHROME_PATH': '/opt/chrome'},
              operatingSystem: 'linux',
              exists: (_) => false),
          '/opt/chrome');
    });

    test('finds installed browsers on each OS', () {
      expect(
          findPdfBrowser(
              environment: {'HOME': '/Users/dev'},
              operatingSystem: 'macos',
              exists: (f) =>
                  f ==
                  '/Users/dev/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge'),
          '/Users/dev/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge');
      expect(
          findPdfBrowser(
              environment: {'PATH': '/usr/local/bin:/usr/bin'},
              operatingSystem: 'linux',
              exists: (f) => f == '/usr/bin/chromium'),
          '/usr/bin/chromium');
      expect(
          findPdfBrowser(
              environment: {'ProgramFiles(x86)': r'C:\Program Files (x86)'},
              operatingSystem: 'windows',
              exists: (f) => f.endsWith('msedge.exe')),
          r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe');
      expect(
          findPdfBrowser(
              environment: {'PATH': '/usr/bin'},
              operatingSystem: 'linux',
              exists: (_) => false),
          isNull);
    });
  });

  test('a browser that cannot start is reported, not thrown', () async {
    final dir = Directory.systemTemp.createTempSync('aegis_pdf_');
    addTearDown(() => dir.deleteSync(recursive: true));
    final problem = await writePdfReport('<p>x</p>',
        p.join(dir.path, 'out.pdf'), p.join(dir.path, 'no-such-browser'));
    expect(problem, contains('could not start'));
    expect(File(p.join(dir.path, 'out.pdf')).existsSync(), isFalse);
  });

  test('run keeps going when the PDF cannot be written', () async {
    final dir = project();
    final r = await run(dir, [],
        env: {'AEGIS_BROWSER': p.join(dir.path, 'no-such-browser')});
    expect(
        r.stderr, contains('aegis: PDF report not written: could not start'));
    expect(File(p.join(dir.path, 'build', 'aegis-report.html')).existsSync(),
        isTrue);
    expect(
        Directory(p.join(dir.path, 'build'))
            .listSync()
            .where((f) => f.path.endsWith('.pdf')),
        isEmpty);
  });

  final browser = findPdfBrowser();
  test('run writes <mode>-<profile>-<date>.pdf next to the HTML report',
      () async {
    final dir = project();
    final r = await run(dir, ['-f', 'pdf', '-l', 'ar']);
    final pdf = File(p.join(dir.path, 'build', 'code-L2+R-${today()}.pdf'));
    expect(r.stderr, isNot(contains('PDF report not written')));
    expect(r.stdout, contains('Report: ${pdf.path}'));
    expect(pdf.readAsBytesSync().take(5), '%PDF-'.codeUnits);
    // Only pdf was asked for: the HTML used to print it is not left behind.
    expect(File(p.join(dir.path, 'build', 'aegis-report.html')).existsSync(),
        isFalse);
  },
      skip: browser == null ? 'no Chrome, Edge or Chromium installed' : false,
      timeout: const Timeout(Duration(minutes: 3)));
}
