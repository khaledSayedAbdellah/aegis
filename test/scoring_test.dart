import 'dart:convert';
import 'dart:io';

import 'package:aegis/aegis.dart';
import 'package:aegis/src/scoring.dart' show computeScore;
import 'package:path/path.dart' as p;
import 'package:test/test.dart';

RuleMeta meta(String id) => [...allRules, ...apkRules].firstWhere((r) => r.meta.id == id).meta;

RuleResult failed(String id, Severity s) => RuleResult(
    meta: meta(id),
    status: RuleStatus.failed,
    severity: s,
    findings: [Finding(ruleId: id, message: 'x')]);

RuleResult passed(String id) =>
    RuleResult(meta: meta(id), status: RuleStatus.passed, severity: meta(id).severity);

void main() {
  // One rule per category, so each category score is easy to follow.
  const ids = ['AEG-D01', 'AEG-D02', 'AEG-D05', 'AEG-C02', 'AEG-A06'];

  test('no critical or high: the score is the average of the categories', () {
    final s = computeScore([
      failed('AEG-D02', Severity.medium), // NETWORK 92
      for (final id in ids.where((x) => x != 'AEG-D02')) passed(id),
    ]);
    expect(s.capReason, isNull);
    expect(s.value, s.uncapped);
    expect(s.value, ((92 + 100 * 4) / 5).round());
  });

  test('a high finding scales the score below 74 instead of cutting it there', () {
    final onlyHigh = computeScore([
      failed('AEG-D01', Severity.high), // STORAGE 80
      for (final id in ids.where((x) => x != 'AEG-D01')) passed(id),
    ]);
    final highAndMore = computeScore([
      failed('AEG-D01', Severity.high),
      failed('AEG-D02', Severity.medium),
      failed('AEG-D05', Severity.medium),
      failed('AEG-C02', Severity.low),
      passed('AEG-A06'),
    ]);

    expect(onlyHigh.uncapped, ((80 + 400) / 5).round()); // 96
    expect(onlyHigh.value, (96 * 74 / 100).round()); // 71
    expect(onlyHigh.capReason, 'high');
    expect(onlyHigh.capRules, ['AEG-D01']);
    expect(onlyHigh.ceiling, 74);

    expect(highAndMore.value, lessThan(onlyHigh.value),
        reason: 'more problems must lower the score even while a high one is open');
    expect(highAndMore.value, lessThanOrEqualTo(74));
  });

  test('a critical finding keeps the score at or below 49', () {
    final s = computeScore([
      failed('AEG-D01', Severity.critical),
      for (final id in ids.where((x) => x != 'AEG-D01')) passed(id),
    ]);
    expect(s.value, lessThanOrEqualTo(49));
    expect(s.capReason, 'critical');
    expect(s.ceiling, 49);
  });

  test('categories know their worst open problem', () {
    final s = computeScore([
      failed('AEG-D01', Severity.high),
      failed('AEG-C02', Severity.low),
      passed('AEG-D02'),
    ]);
    expect(s.categories['STORAGE']!.worst, Severity.high);
    expect(s.categories['STORAGE']!.failedRuleIds, ['AEG-D01']);
    expect(s.categories['CODE']!.worst, Severity.low);
    expect(s.categories['NETWORK']!.worst, isNull);
  });

  test('reports explain the limit and colour categories by severity', () async {
    final dir = Directory.systemTemp.createTempSync('aegis_score_');
    addTearDown(() => dir.deleteSync(recursive: true));
    File(p.join(dir.path, 'pubspec.yaml'))
        .writeAsStringSync('name: app\ndependencies:\n  flutter:\n    sdk: flutter\n');
    File(p.join(dir.path, 'lib', 'a.dart'))
      ..parent.createSync()
      ..writeAsStringSync("const awsKey = 'AKIAZ7QW3RT5YU8IO2PL';\n");
    final r = await runAudit(dir.path, config: AegisConfig(), offline: true);

    expect(r.score.capRules, contains('AEG-D01'));
    final console = ConsoleReporter(color: false).render(r);
    expect(console, contains('at most 74 while a HIGH finding is open'));
    expect(console, contains('without it'));
    expect(ConsoleReporter(color: false, lang: 'ar').render(r), contains('مش هيعدي 74'));

    final md = renderMarkdown(r);
    expect(md, contains('🔴'), reason: 'STORAGE has a high finding');
    final html = renderHtml(r);
    expect(html, contains('<small class="muted">AEG-D01'));

    final json = jsonDecode(renderJson(r)) as Map<String, dynamic>;
    expect(json['score']['uncapped'], greaterThan(json['score']['value'] as int));
    expect(json['score']['categories']['STORAGE']['worstSeverity'], 'high');
  });
}
