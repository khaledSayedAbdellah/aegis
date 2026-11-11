import 'dart:convert';

import 'package:aegis/aegis.dart';
import 'package:aegis/src/l10n/messages.g.dart';
import 'package:aegis/src/scoring.dart' show computeScore, computeCoverage;
import 'package:test/test.dart';

final _meta = allRules.firstWhere((r) => r.meta.id == 'AEG-D01').meta;

RuleResult _result(RuleStatus status, {bool incomplete = false}) => RuleResult(
      meta: _meta,
      status: status,
      severity: Severity.high,
      incomplete: incomplete,
      findings: status == RuleStatus.failed
          ? [Finding(ruleId: _meta.id, message: 'Verified failure')]
          : [],
    );

AuditReport _report(List<RuleResult> results, {ProbeOutcome? probe}) {
  final profile = ProfileSet.tryParse('l1+r')!;
  return AuditReport(
      projectName: 'test',
      root: '.',
      profile: profile,
      results: results,
      score: computeScore(results),
      coverage: computeCoverage(results, profile),
      manual: [],
      generatedAt: DateTime.utc(2026),
      probe: probe);
}

void _expectProvisional(AuditReport report, bool expected) {
  for (final lang in ['en', 'ar']) {
    final t = L10n(lang);
    for (final output in [
      renderHtml(report, lang: lang),
      renderMarkdown(report, lang: lang),
      ConsoleReporter(lang: lang, color: false).render(report)
    ]) {
      expect(output.contains(t.scoreProvisional), expected);
      expect(output.contains(t.scoreProvisionalDetail), expected);
    }
  }
  expect((reportToJson(report)['score'] as Map)['provisional'], expected);
  final sarif = jsonDecode(renderSarif(report)) as Map;
  expect(sarif['runs'][0]['properties']['scoreProvisional'], expected);
}

void main() {
  test('100 with unresolved checks is visibly provisional without rescoring',
      () {
    final r = _report([
      _result(RuleStatus.passed),
      _result(RuleStatus.incomplete),
    ]);
    expect(r.score.value, 100);
    expect(r.complete, isFalse);
    _expectProvisional(r, true);
    final html = renderHtml(r);
    expect(html.indexOf('class="score-warning"'),
        lessThan(html.indexOf('</section>')));
    expect(html, contains('conic-gradient(var(--warn)'));
    expect(ConsoleReporter().render(r), contains('\x1B[1;33m100/100 (A)'));
    expect(r.score.value, 100);
  });

  test('a verified partial failure retains its penalty and red score', () {
    final r = _report([_result(RuleStatus.failed, incomplete: true)]);
    final full = _report([_result(RuleStatus.failed)]);
    expect(r.score.value, full.score.value);
    expect(r.score.value, lessThan(70));
    expect(r.failed, hasLength(1));
    _expectProvisional(r, true);
    _expectProvisional(full, false);
    expect(renderHtml(r), contains('conic-gradient(var(--bad)'));
  });

  test('a skipped requested probe warns even without incomplete rule rows', () {
    final r = _report([_result(RuleStatus.passed)],
        probe: const ProbeOutcome.skipped('Tools unavailable'));
    expect(r.incomplete, isEmpty);
    _expectProvisional(r, true);
  });

  test('completed selected scope and explicit opt-outs do not warn', () {
    final r = _report([
      _result(RuleStatus.passed),
      _result(RuleStatus.disabled),
      _result(RuleStatus.notApplicable),
      _result(RuleStatus.outOfProfile),
    ], probe: const ProbeOutcome.skipped('Disabled', requested: false));
    expect(r.complete, isTrue);
    _expectProvisional(r, false);
    expect(renderHtml(r), contains('conic-gradient(var(--ok)'));
  });

  test('zero completed rules never displays a final score', () {
    final r = _report([]);
    expect(r.score.value, 0);
    _expectProvisional(r, true);
  });
}
