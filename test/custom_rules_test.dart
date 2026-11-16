import 'dart:io';

import 'package:aegis/aegis.dart';
import 'package:path/path.dart' as p;
import 'package:test/test.dart';

const _yaml = r'''
custom_rules:
  - id: x-http-url
    title: Plain HTTP URL
    title_ar: لينك HTTP
    severity: medium
    pattern: "http://(?!localhost)[\\w./-]+"
    files: ["lib/**", "android/**/*.kt"]
    message: "Plain HTTP URL: {match}"
    message_ar: "لينك HTTP: {match}"
    fix: Use https.
    masvs: MASVS-NETWORK-1
  - id: X-LAUNCH-EXTERNAL
    title: Links opened in another app
    severity: low
    call: launchUrl
    args:
      - index: 0
        not_matches: "^kHelp"
      - name: mode
        matches: externalApplication
    message: "{call}() opens the link in another app."
    fix: Open links in the in-app browser.
''';

Future<String> _project(Map<String, String> files) async {
  final dir = Directory.systemTemp.createTempSync('aegis_custom_');
  addTearDown(() => dir.deleteSync(recursive: true));
  ({
    'pubspec.yaml': 'name: app\n',
    'aegis.yaml': _yaml,
    ...files,
  }).forEach((path, content) {
    final f = File(p.join(dir.path, path));
    f.parent.createSync(recursive: true);
    f.writeAsStringSync(content);
  });
  return dir.path;
}

const _code = '''
void open(Uri uri) {
  launchUrl(uri, mode: LaunchMode.externalApplication);
  launchUrl(kHelp, mode: LaunchMode.externalApplication);
  launchUrl(uri);
  // aegis:ignore X-LAUNCH-EXTERNAL
  launchUrl(uri, mode: LaunchMode.externalApplication);
}
const api = 'http://api.example.com/v1';
const local = 'http://localhost:8080';
''';

void main() {
  test('pattern and call rules report with their own text', () async {
    final root = await _project({
      'lib/main.dart': _code,
      'android/app/src/main/kotlin/Main.kt':
          'val u = "http://cdn.example.com"\n',
      'build/out.txt': 'http://ignored.example.com',
      'test/a_test.dart': "const u = 'http://test.example.com';",
    });
    final r = await runAudit(root, offline: true);
    final http = r.results.firstWhere((x) => x.meta.id == 'X-HTTP-URL');
    expect(http.severity, Severity.medium);
    expect(http.meta.masvs, ['MASVS-NETWORK-1']);
    expect(http.findings.map((f) => '${f.file}:${f.line} ${f.message}'), [
      'android/app/src/main/kotlin/Main.kt:1 Plain HTTP URL: http://cdn.example.com',
      'lib/main.dart:8 Plain HTTP URL: http://api.example.com/v1',
    ]);
    expect(
        http.findings.last.messageAr, 'لينك HTTP: http://api.example.com/v1');
    final launch =
        r.results.firstWhere((x) => x.meta.id == 'X-LAUNCH-EXTERNAL');
    expect(launch.findings.map((f) => '${f.line} ${f.message}'),
        ['2 launchUrl() opens the link in another app.']);
    expect(launch.suppressed, 1);
  });

  test('custom findings can be accepted in the baseline', () async {
    final root = await _project({'lib/main.dart': _code});
    final first = await runAudit(root, offline: true);
    final file = p.join(root, 'aegis-baseline.json');
    File(file)
        .writeAsStringSync(Baseline.fromResults(first.results).toJsonString());
    final again =
        await runAudit(root, offline: true, baseline: Baseline.load(file));
    final http = again.results.firstWhere((x) => x.meta.id == 'X-HTTP-URL');
    expect(http.findings, isNotEmpty);
    expect(http.findings.every((f) => f.baselined), isTrue);
  });

  test('bad entries are explained', () {
    String error(String yaml) {
      try {
        AegisConfig.parse(yaml);
        return 'no error';
      } on FormatException catch (e) {
        return e.message;
      }
    }

    expect(error('custom_rules:\n  - id: AEG-Z01\n'),
        contains('must start with X-'));
    expect(
        error('custom_rules:\n  - {id: X-A, title: t, severity: high, '
            'message: m, fix: f}\n'),
        contains('give either pattern or call'));
    expect(
        error('custom_rules:\n  - {id: X-A, title: t, severity: high, '
            'message: m, fix: f, pattern: "("}\n'),
        contains('not a valid regex'));
    expect(
        error('custom_rules:\n  - {id: X-A, title: t, severity: urgent, '
            'message: m, fix: f, call: x}\n'),
        contains('severity must be'));
    expect(
        error('custom_rules:\n  - {id: X-A, title: t, severity: low, '
            'message: m, fix: f, call: x}\n'
            '  - {id: x-a, title: t, severity: low, message: m, fix: f, call: x}\n'),
        contains('defined twice'));
  });
}
