import 'dart:convert';
import 'dart:io';

import 'package:aegis/aegis.dart';
import 'package:aegis/src/scoring.dart' show computeScore, findingFactor;
import 'package:path/path.dart' as p;
import 'package:test/test.dart';

RuleMeta meta(String id) =>
    [...allRules, ...apkRules].firstWhere((r) => r.meta.id == id).meta;

RuleResult failed(String id, Severity s, {int findings = 1}) => RuleResult(
        meta: meta(id),
        status: RuleStatus.failed,
        severity: s,
        findings: [
          for (var i = 0; i < findings; i++)
            Finding(ruleId: id, message: 'x $i')
        ]);

RuleResult passed(String id) => RuleResult(
    meta: meta(id), status: RuleStatus.passed, severity: meta(id).severity);

/// The open problems of the Aldrees workspace, source only, profile L2+R
/// (release-20261107.1).
List<RuleResult> aldreesL2r() => [
      failed('AEG-D01', Severity.high, findings: 3),
      failed('AEG-P01', Severity.high),
      failed('AEG-P05', Severity.medium),
      failed('AEG-P07', Severity.medium),
      failed('AEG-P08', Severity.medium, findings: 2),
      failed('AEG-C02', Severity.low, findings: 9),
      failed('AEG-P09', Severity.low),
      passed('AEG-D05'),
    ];

/// The same app under L1: only the hardcoded passwords and the unpinned
/// packages are in scope.
List<RuleResult> aldreesL1() => [
      failed('AEG-D01', Severity.high, findings: 3),
      failed('AEG-C02', Severity.low, findings: 9),
      passed('AEG-D05'),
    ];

void main() {
  group('Bands: the worst open problem decides the range', () {
    test('nothing open is 100', () {
      expect(computeScore([passed('AEG-D01'), passed('AEG-D02')]).value, 100);
    });

    test('one problem of each severity', () {
      int one(Severity s) => computeScore([failed('AEG-D02', s)]).value;
      expect(one(Severity.low), inInclusiveRange(90, 99));
      expect(one(Severity.medium), inInclusiveRange(70, 89));
      expect(one(Severity.high), inInclusiveRange(40, 69));
      expect(one(Severity.critical), inInclusiveRange(0, 39));
      expect(Score.gradeOf(one(Severity.low)), 'A');
      expect(Score.gradeOf(one(Severity.high)), 'D');
      expect(Score.gradeOf(one(Severity.critical)), 'F');
    });

    test('any number of lower problems never reaches the next band', () {
      final manyLows = computeScore(
          [for (var i = 0; i < 40; i++) failed('AEG-C02', Severity.low)]);
      expect(manyLows.value, greaterThanOrEqualTo(90));
      final manyMediums = computeScore([
        failed('AEG-D01', Severity.high),
        for (var i = 0; i < 40; i++) failed('AEG-D02', Severity.medium),
      ]);
      expect(manyMediums.value, greaterThanOrEqualTo(40));
    });
  });

  group('Inside a band every problem counts', () {
    test('the same worst problem, more other problems: lower score', () {
      final l1 = computeScore(aldreesL1());
      final l2r = computeScore(aldreesL2r());
      expect(l1.worst, Severity.high);
      expect(l2r.worst, Severity.high);
      expect(l1.value, 58);
      expect(l2r.value, 47);
      expect(l1.grade, 'D');
    });

    test('fixing anything never lowers the score', () {
      final all = aldreesL2r();
      final before = computeScore(all).value;
      for (final f in all.where((r) => r.status == RuleStatus.failed)) {
        final after =
            computeScore(all.where((r) => !identical(r, f)).toList()).value;
        expect(after, greaterThanOrEqualTo(before),
            reason: 'fixing ${f.meta.id}');
      }
    });

    test('more findings of one rule cost more, up to twice', () {
      expect(findingFactor(1), 1);
      expect(findingFactor(3), closeTo(1.4, 0.01));
      expect(findingFactor(1000), 2);
      final one = computeScore([failed('AEG-D01', Severity.high)]).value;
      final three =
          computeScore([failed('AEG-D01', Severity.high, findings: 3)]).value;
      expect(three, lessThan(one));
    });
  });

  group('What to fix next', () {
    test('blocking rules and the score once they are fixed', () {
      final s = computeScore(aldreesL2r());
      expect(s.blockingRules, ['AEG-D01', 'AEG-P01']);
      expect(s.afterBlockingFixed, 80);
      expect(s.band, (40, 70));
      expect(s.gains.keys.first, 'AEG-D01',
          reason: 'three findings weigh more than one');
      expect(s.gains.values.every((g) => g >= 0), isTrue);
    });

    test('fixing the only high problem in L1 gives an A', () {
      final s = computeScore(aldreesL1());
      expect(s.afterBlockingFixed, 99);
      expect(s.gains['AEG-D01'], 99 - 58);
    });
  });

  test('categories use the same formula, so number and colour agree', () {
    final s = computeScore(aldreesL2r());
    final storage = s.categories['STORAGE']!;
    expect(storage.worst, Severity.high);
    expect(storage.score, inInclusiveRange(40, 69));
    expect(storage.failedRuleIds, ['AEG-D01']);
    expect(s.categories['CRYPTO']!.score, 100);
    expect(s.categories['CRYPTO']!.worst, isNull);
  });

  test('reports explain the band and the best fixes', () async {
    final dir = Directory.systemTemp.createTempSync('aegis_score_');
    addTearDown(() => dir.deleteSync(recursive: true));
    File(p.join(dir.path, 'pubspec.yaml')).writeAsStringSync(
        'name: app\ndependencies:\n  flutter:\n    sdk: flutter\n');
    File(p.join(dir.path, 'lib', 'a.dart'))
      ..parent.createSync()
      ..writeAsStringSync("const awsKey = 'AKIAZ7QW3RT5YU8IO2PL';\n");
    final r = await runAudit(dir.path, config: AegisConfig(), offline: true);

    expect(r.score.blockingRules, contains('AEG-D01'));
    final console = ConsoleReporter(color: false).render(r);
    expect(console, contains('40-69 while a HIGH problem is open'));
    expect(console, contains('Biggest single gains: AEG-D01'));
    expect(ConsoleReporter(color: false, lang: 'ar').render(r),
        contains('بين 40-69'));

    expect(renderMarkdown(r), contains('🔴'));
    expect(renderHtml(r), contains('<small class="muted">AEG-D01'));

    final json = jsonDecode(renderJson(r)) as Map<String, dynamic>;
    expect(json['score']['worstSeverity'], 'high');
    expect(json['score']['band'], [40, 69]);
    expect(json['score']['blockingRules'], contains('AEG-D01'));
    expect(json['score']['categories']['STORAGE']['worstSeverity'], 'high');
  });
}
