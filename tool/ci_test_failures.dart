/// Turns `dart test --file-reporter json:<file>` output into GitHub
/// annotations and a job summary, so failing tests can be read from the
/// run page without opening its log.
///
///     dart run tool/ci_test_failures.dart test-results.json
library;

import 'dart:convert';
import 'dart:io';

void main(List<String> args) {
  final file = File(args.isEmpty ? 'test-results.json' : args.first);
  if (!file.existsSync()) {
    stdout.writeln('No test results at ${file.path}.');
    return;
  }
  final names = <int, String>{};
  final paths = <int, String>{};
  final errors = <int, StringBuffer>{};
  final failed = <int>[];
  final suites = <int, String>{};
  for (final line in file.readAsLinesSync()) {
    if (line.trim().isEmpty) continue;
    final Map<String, Object?> e;
    try {
      e = jsonDecode(line) as Map<String, Object?>;
    } on FormatException {
      continue;
    }
    switch (e['type']) {
      case 'suite':
        final s = e['suite'] as Map;
        suites[s['id'] as int] = (s['path'] ?? '') as String;
      case 'testStart':
        final t = e['test'] as Map;
        names[t['id'] as int] = t['name'] as String;
        paths[t['id'] as int] = suites[t['suiteID']] ?? '';
      case 'error':
        (errors[e['testID'] as int] ??= StringBuffer())
          ..writeln(e['error'])
          ..writeln(e['stackTrace']);
      case 'testDone':
        if (e['result'] != 'success' && e['hidden'] != true) {
          failed.add(e['testID'] as int);
        }
    }
  }
  String clip(String s, int max) =>
      s.length > max ? '${s.substring(0, max)}…' : s;
  final summary = StringBuffer('## Failing tests (${failed.length})\n\n');
  for (final id in failed) {
    final name = names[id] ?? 'test $id';
    final path = paths[id] ?? '';
    final error = clip((errors[id] ?? StringBuffer()).toString().trim(), 1500);
    final oneLine = error
        .replaceAll('%', '%25')
        .replaceAll('\r', '')
        .replaceAll('\n', '%0A');
    stdout.writeln(
        '::error file=$path,title=${clip(name, 200).replaceAll(',', ' ')}::$oneLine');
    summary
      ..writeln('### `$path`: $name')
      ..writeln()
      ..writeln('```')
      ..writeln(error)
      ..writeln('```')
      ..writeln();
  }
  final target = Platform.environment['GITHUB_STEP_SUMMARY'];
  if (target != null) {
    File(target).writeAsStringSync(summary.toString(), mode: FileMode.append);
  } else {
    stdout.write(summary);
  }
}
