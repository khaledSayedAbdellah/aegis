import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:path/path.dart' as p;

import '../model.dart';

/// The PDF report's file name: the audit mode, the MAS profile and the audit
/// date, for example `apk-L2+R-2026-11-12.pdf`.
String pdfReportName(String mode, ProfileSet profile, DateTime date) {
  String two(int v) => v.toString().padLeft(2, '0');
  final day = '${date.year}-${two(date.month)}-${two(date.day)}';
  return '$mode-$profile-$day.pdf';
}

/// The HTML report with every collapsible section expanded, because a
/// printed page cannot be clicked open.
String printableHtml(String html) =>
    html.replaceAllMapped(RegExp(r'<details\b([^>]*)>'), (m) {
      final attributes = m[1]!;
      return RegExp(r'\sopen\b').hasMatch(attributes)
          ? m[0]!
          : '<details open$attributes>';
    });

/// Environment variables that point at a Chromium-based browser to print
/// the PDF with. `AEGIS_BROWSER` wins over the common `CHROME_PATH`.
const pdfBrowserVariables = ['AEGIS_BROWSER', 'CHROME_PATH'];

/// Finds Chrome, Edge, Chromium or Brave. A browser set in
/// [pdfBrowserVariables] is used as given, even when it does not exist, so
/// a wrong path is reported instead of silently replaced.
String? findPdfBrowser({
  Map<String, String>? environment,
  String? operatingSystem,
  bool Function(String path)? exists,
}) {
  final env = environment ?? Platform.environment;
  final os = operatingSystem ?? Platform.operatingSystem;
  final isFile = exists ?? (String path) => File(path).existsSync();
  for (final name in pdfBrowserVariables) {
    final value = env[name]?.trim();
    if (value != null && value.isNotEmpty) return value;
  }
  for (final candidate in _browserCandidates(env, os)) {
    if (isFile(candidate)) return candidate;
  }
  return null;
}

List<String> _browserCandidates(Map<String, String> env, String os) {
  switch (os) {
    case 'macos':
      const apps = [
        'Google Chrome.app/Contents/MacOS/Google Chrome',
        'Microsoft Edge.app/Contents/MacOS/Microsoft Edge',
        'Chromium.app/Contents/MacOS/Chromium',
        'Brave Browser.app/Contents/MacOS/Brave Browser',
      ];
      final home = env['HOME'];
      return [
        for (final app in apps) '/Applications/$app',
        if (home != null)
          for (final app in apps) '$home/Applications/$app',
      ];
    case 'windows':
      const exes = [
        r'Google\Chrome\Application\chrome.exe',
        r'Microsoft\Edge\Application\msedge.exe',
        r'Chromium\Application\chrome.exe',
        r'BraveSoftware\Brave-Browser\Application\brave.exe',
      ];
      final roots = [
        env['ProgramFiles'],
        env['ProgramFiles(x86)'],
        env['LOCALAPPDATA'],
      ].whereType<String>();
      return [
        for (final exe in exes)
          for (final root in roots) '$root\\$exe',
      ];
    default:
      const names = [
        'google-chrome',
        'google-chrome-stable',
        'chromium',
        'chromium-browser',
        'microsoft-edge',
        'microsoft-edge-stable',
        'brave-browser',
      ];
      final dirs = (env['PATH'] ?? '').split(':').where((d) => d.isNotEmpty);
      return [
        for (final name in names)
          for (final dir in dirs) '$dir/$name',
      ];
  }
}

/// The command line that prints [htmlFile] to [pdfFile] with [browser].
List<String> pdfBrowserArguments(
        String htmlFile, String pdfFile, String profileDir) =>
    [
      '--headless',
      '--disable-gpu',
      '--no-first-run',
      '--no-default-browser-check',
      '--disable-extensions',
      '--user-data-dir=$profileDir',
      '--no-pdf-header-footer',
      '--print-to-pdf-no-header',
      '--print-to-pdf=$pdfFile',
      Uri.file(htmlFile).toString(),
    ];

/// Prints [html] to [pdfFile] with the headless [browser]. Returns null on
/// success, otherwise why the PDF could not be written.
Future<String?> writePdfReport(String html, String pdfFile, String browser,
    {Duration timeout = const Duration(seconds: 90)}) async {
  final work = Directory.systemTemp.createTempSync('aegis-pdf-');
  try {
    final htmlFile = p.join(work.path, 'report.html');
    File(htmlFile).writeAsStringSync(printableHtml(html));
    final target = File(p.absolute(pdfFile));
    target.parent.createSync(recursive: true);
    if (target.existsSync()) target.deleteSync();
    final Process process;
    try {
      process = await Process.start(
          browser,
          pdfBrowserArguments(
              htmlFile, target.path, p.join(work.path, 'profile')));
    } on ProcessException catch (e) {
      return 'could not start $browser: ${e.message}';
    }
    final errors = StringBuffer();
    final out = process.stdout.drain<void>();
    final err = process.stderr
        .transform(const Utf8Decoder(allowMalformed: true))
        .forEach(errors.write);
    final int code;
    try {
      code = await process.exitCode.timeout(timeout);
    } on TimeoutException {
      process.kill(ProcessSignal.sigkill);
      return '$browser did not finish within ${timeout.inSeconds} seconds';
    }
    await Future.wait([out, err]);
    if (target.existsSync() && target.lengthSync() > 0) return null;
    final detail = errors
        .toString()
        .split('\n')
        .map((l) => l.trim())
        .where((l) => l.isNotEmpty)
        .lastOrNull;
    return '$browser exited with code $code without writing the PDF'
        '${detail == null ? '' : ': $detail'}';
  } finally {
    try {
      work.deleteSync(recursive: true);
    } catch (_) {}
  }
}
