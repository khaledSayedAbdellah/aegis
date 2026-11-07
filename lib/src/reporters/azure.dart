/// Azure Pipelines logging commands: one annotation per new finding, shown on
/// the build summary and in the step log.
library;

import '../engine.dart';
import '../model.dart';

/// How many findings are annotated before the rest are summarized in one line.
const azureAnnotationLimit = 50;

String _escapeData(String s) => s
    .replaceAll('%', '%AZP25')
    .replaceAll('\r', '%0D')
    .replaceAll('\n', '%0A');

String _escapeProperty(String s) =>
    _escapeData(s).replaceAll(']', '%5D').replaceAll(';', '%3B');

/// Repository-relative files can be linked; `package:...` and `x.apk!/...`
/// locations cannot.
bool _linkable(String? file) =>
    file != null && !file.startsWith('package:') && !file.contains('!/');

/// Renders `##vso[task.logissue]` lines for findings that are not in the
/// baseline. Findings at or above [failOn] (or high when it is null) are
/// errors, the rest warnings.
///
/// When there are new findings but the run will not fail ([failing] is
/// false), the step is marked "succeeded with issues" so it stands out
/// without breaking the build.
String renderAzure(AuditReport r, {Severity? failOn, bool failing = false}) {
  final b = StringBuffer();
  final threshold = failOn ?? Severity.high;
  var count = 0;
  var skipped = 0;
  for (final res in r.newFailed) {
    final type = res.severity >= threshold ? 'error' : 'warning';
    for (final f in res.newFindings) {
      if (count >= azureAnnotationLimit) {
        skipped++;
        continue;
      }
      count++;
      final props = <String>['type=$type', 'code=${res.meta.id}'];
      if (_linkable(f.file)) {
        props.add('sourcepath=${_escapeProperty(f.file!)}');
        if (f.line != null) props.add('linenumber=${f.line}');
      }
      final where = f.location.isEmpty || _linkable(f.file) ? '' : ' (${f.location})';
      final text = 'aegis ${res.meta.id} [${res.severity.name}] ${res.meta.title.en}: ${f.message}$where';
      b.writeln('##vso[task.logissue ${props.join(';')};]${_escapeData(text)}');
    }
  }
  if (skipped > 0) {
    b.writeln('##vso[task.logissue type=warning;]${_escapeData('aegis: $skipped more findings, see the report artifact.')}');
  }
  if (r.newFindingCount > 0 && !failing) {
    b.writeln('##vso[task.complete result=SucceededWithIssues;]aegis found new issues below the failure threshold');
  }
  return b.toString();
}
