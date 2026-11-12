// Audits a project from Dart code instead of the `aegis` command.
//
//   dart run example/example.dart example/vulnerable_app
//
// The bundled `vulnerable_app` is intentionally insecure, so it reports
// findings and a low score.
import 'dart:io';

import 'package:aegis/aegis.dart';

Future<void> main(List<String> args) async {
  final path = args.isEmpty ? 'example/vulnerable_app' : args.first;

  // `offline` skips the dependency advisory lookup, the only network call.
  final report = await runAudit(path, offline: true);

  stdout.writeln(
      ConsoleReporter(color: stdout.supportsAnsiEscapes).render(report));

  // The same report in machine-readable form.
  File('aegis-report.json').writeAsStringSync(renderJson(report));

  for (final rule in report.failed) {
    stdout.writeln('${rule.meta.id} ${rule.severity.name}: '
        '${rule.findings.length} finding(s)');
  }
  stdout.writeln('Score: ${report.score.value}/100, '
      'complete: ${report.complete}');

  // Mirror the CLI: a non-zero exit code when something needs fixing.
  exitCode = report.failed.isEmpty ? 0 : 1;
}
