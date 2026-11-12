/// Turns rule results into a score, a grade and MASVS coverage.
library;

import 'dart:math' as math;

import 'masvs.dart';
import 'model.dart';

// How the score works (docs: README "Score").
//
// 1. **The worst open problem picks the band**, like SonarQube's security
//    rating: nothing open = 100, worst low = 90..99 (A), worst medium =
//    70..89 (B/C), worst high = 40..69 (D), worst critical = 0..39 (F).
//    A single high finding can never hide behind many healthy checks, and
//    fixing it always moves the score up a band.
// 2. **Every open problem moves the score down inside the band**: each
//    failing rule adds its [severityWeight] to a penalty P, more findings of
//    the same rule add a little more (see [findingFactor]), and the score
//    is `low + (high - low) * e^(-P / [penaltyScale])`. Two apps with the
//    same worst problem but a different number of other problems get
//    different scores, and fixing anything never lowers the score.
// 3. The same formula gives each MASVS category its score, so a category's
//    number and colour always agree.
//
// Known (baseline) findings count like any other: the score is the state
// of the app, the baseline only decides what fails the build.

/// Penalty per failing rule, by severity.
const Map<Severity, double> severityWeight = {
  Severity.critical: 10,
  Severity.high: 6,
  Severity.medium: 3,
  Severity.low: 1,
  Severity.info: 0,
};

/// Score range for each worst open severity: [from, to).
const Map<Severity, (int, int)> severityBand = {
  Severity.critical: (0, 40),
  Severity.high: (40, 70),
  Severity.medium: (70, 90),
  Severity.low: (90, 100),
  Severity.info: (90, 100),
};

/// Larger values make each problem cost less inside its band.
const double penaltyScale = 20;

/// The same mistake in several places is worse than in one, but it is still
/// one fix: 1 finding = 1x, 3 = 1.4x, 9 = 1.8x, 16 or more = 2x.
double findingFactor(int findings) =>
    findings <= 1 ? 1 : math.min(2, 1 + 0.25 * math.log(findings) / math.ln2);

class CategoryScore {
  CategoryScore(this.category, this.score, this.checked, this.failed,
      {this.worst, this.failedRuleIds = const []});
  final String category;
  final int score;
  final int checked;
  final int failed;

  /// Most severe failing rule in this category, null when all passed.
  final Severity? worst;
  final List<String> failedRuleIds;
}

class Score {
  Score(this.value, this.categories,
      {this.worst,
      this.blockingRules = const [],
      this.penalty = 0,
      this.gains = const {},
      this.afterBlockingFixed});

  final int value;
  final Map<String, CategoryScore> categories;

  /// The most severe open problem: it decides the band and the grade.
  final Severity? worst;

  /// The rules at [worst] severity: fixing all of them moves the score up a band.
  final List<String> blockingRules;

  /// Sum of the weights of all failing rules.
  final double penalty;

  /// Points gained by fixing each failing rule alone, best first.
  final Map<String, int> gains;

  /// The score once every [blockingRules] rule is fixed.
  final int? afterBlockingFixed;

  /// `critical` or `high` when such a problem limits the score.
  String? get capReason =>
      worst == Severity.critical || worst == Severity.high ? worst!.name : null;

  /// The score range of the current band, e.g. (40, 70) while a high is open.
  (int, int)? get band => worst == null ? null : severityBand[worst];

  String get grade => gradeOf(value);

  static String gradeOf(int v) {
    if (v >= 90) return 'A';
    if (v >= 80) return 'B';
    if (v >= 70) return 'C';
    if (v >= 40) return 'D';
    return 'F';
  }
}

/// Score of a set of results (all rules, or one category).
(int, Severity?, double) _scoreOf(Iterable<RuleResult> results) {
  Severity? worst;
  var penalty = 0.0;
  for (final r in results) {
    if (r.status != RuleStatus.failed) continue;
    penalty += severityWeight[r.severity]! * findingFactor(r.findings.length);
    if (worst == null || r.severity > worst) worst = r.severity;
  }
  if (worst == null) return (100, null, 0);
  final (from, to) = severityBand[worst]!;
  final value =
      (from + (to - from) * math.exp(-penalty / penaltyScale)).floor();
  return (value.clamp(from, to - 1).toInt(), worst, penalty);
}

Score computeScore(List<RuleResult> results) {
  final counted = results.where((r) => r.counts).toList();
  final byCat = <String, List<RuleResult>>{};
  for (final r in counted) {
    byCat.putIfAbsent(r.meta.category, () => []).add(r);
  }
  final cats = <String, CategoryScore>{};
  for (final e in byCat.entries) {
    final (value, worst, _) = _scoreOf(e.value);
    final failedIds = [
      for (final r in e.value)
        if (r.status == RuleStatus.failed) r.meta.id
    ];
    cats[e.key] = CategoryScore(e.key, value, e.value.length, failedIds.length,
        worst: worst, failedRuleIds: failedIds);
  }

  final (value, worst, penalty) = _scoreOf(counted);
  if (worst == null) return Score(counted.isEmpty ? 0 : value, cats);

  final failed = counted.where((r) => r.status == RuleStatus.failed).toList();
  final gains = <String, int>{};
  for (final f in failed) {
    final (without, _, _) = _scoreOf(failed.where((r) => !identical(r, f)));
    gains[f.meta.id] = without - value;
  }
  final sortedGains = Map.fromEntries(
      gains.entries.toList()..sort((a, b) => b.value.compareTo(a.value)));
  final blocking = [
    for (final r in failed)
      if (r.severity == worst) r.meta.id
  ];
  final (afterBlocking, _, _) =
      _scoreOf(failed.where((r) => r.severity != worst));

  return Score(value, cats,
      worst: worst,
      blockingRules: blocking,
      penalty: penalty,
      gains: sortedGains,
      afterBlockingFixed: afterBlocking);
}

enum ControlStatus { checked, manualOnly, notCovered }

class ControlCoverage {
  ControlCoverage(this.control, this.status, this.ruleIds,
      [this.failedRuleIds = const []]);
  final MasvsControl control;

  /// Whether the control is checked automatically. Not whether it passed:
  /// see [failedRuleIds].
  final ControlStatus status;
  final List<String> ruleIds;

  /// Rules of this control that failed (known findings included).
  final List<String> failedRuleIds;

  bool get passed => status == ControlStatus.checked && failedRuleIds.isEmpty;
}

class Coverage {
  Coverage(this.controls);
  final List<ControlCoverage> controls;

  int get inScope => controls.length;
  int get checked =>
      controls.where((c) => c.status == ControlStatus.checked).length;
  int get percent => inScope == 0 ? 0 : (checked * 100 / inScope).round();
}

Coverage computeCoverage(List<RuleResult> results, ProfileSet profile) {
  final out = <ControlCoverage>[];
  for (final c in masvsControls) {
    if (c.resilienceOnly && !profile.resilience) continue;
    final ids = results
        .where((r) => r.counts && !r.incomplete && r.meta.masvs.contains(c.id))
        .map((r) => r.meta.id)
        .toList();
    final ControlStatus status;
    if (ids.isNotEmpty) {
      status = ControlStatus.checked;
    } else if (manualChecks
        .any((m) => m.masvs == c.id && profile.includesAny(m.profiles))) {
      status = ControlStatus.manualOnly;
    } else {
      status = ControlStatus.notCovered;
    }
    final failed = results
        .where(
            (r) => r.status == RuleStatus.failed && r.meta.masvs.contains(c.id))
        .map((r) => r.meta.id)
        .toList();
    out.add(ControlCoverage(c, status, ids, failed));
  }
  return Coverage(out);
}
