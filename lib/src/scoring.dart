/// Turns rule results into a score, a grade and MASVS coverage.
library;

import 'masvs.dart';
import 'model.dart';

/// Points lost per failing rule, by severity.
const Map<Severity, int> severityWeight = {
  Severity.critical: 40,
  Severity.high: 20,
  Severity.medium: 8,
  Severity.low: 3,
  Severity.info: 0,
};

/// While any critical finding is open the score cannot exceed this.
const criticalCap = 49;

/// While any high finding is open the score cannot exceed this.
const highCap = 74;

class CategoryScore {
  CategoryScore(this.category, this.score, this.checked, this.failed,
      {this.worst, this.failedRuleIds = const []});
  final String category;

  /// 100 minus the points of the failing rules in this category.
  final int score;
  final int checked;
  final int failed;

  /// Most severe failing rule in this category, null when all passed. A
  /// category with a high finding is not healthy even when its score is 80.
  final Severity? worst;
  final List<String> failedRuleIds;
}

class Score {
  Score(this.value, this.categories, {this.capReason, int? uncapped, this.capRules = const []})
      : uncapped = uncapped ?? value;

  final int value;
  final Map<String, CategoryScore> categories;

  /// `critical` or `high` when an open finding of that severity limits the
  /// score.
  final String? capReason;

  /// Average of the categories, before the critical/high limit.
  final int uncapped;

  /// The rules that limit the score.
  final List<String> capRules;

  /// The highest score possible while the [capReason] finding is open.
  int? get ceiling => capReason == 'critical'
      ? criticalCap
      : capReason == 'high'
          ? highCap
          : null;

  String get grade => gradeOf(value);

  static String gradeOf(int v) {
    if (v >= 90) return 'A';
    if (v >= 80) return 'B';
    if (v >= 70) return 'C';
    if (v >= 60) return 'D';
    return 'F';
  }
}

/// Each category starts at 100 and loses [severityWeight] points per
/// failing rule; the score is their average.
///
/// While a critical (high) finding is open the score is scaled into
/// 0..[criticalCap] (0..[highCap]) instead of being cut at that value, so it
/// stays below the limit but still drops with every other problem: two apps
/// with the same high finding and different numbers of other problems get
/// different scores.
Score computeScore(List<RuleResult> results) {
  final byCat = <String, List<RuleResult>>{};
  for (final r in results.where((r) => r.counts)) {
    byCat.putIfAbsent(r.meta.category, () => []).add(r);
  }
  final cats = <String, CategoryScore>{};
  for (final e in byCat.entries) {
    var s = 100;
    Severity? worst;
    final failedIds = <String>[];
    for (final r in e.value) {
      if (r.status != RuleStatus.failed) continue;
      failedIds.add(r.meta.id);
      s -= severityWeight[r.severity]!;
      if (worst == null || r.severity > worst) worst = r.severity;
    }
    cats[e.key] = CategoryScore(e.key, s.clamp(0, 100).toInt(), e.value.length, failedIds.length,
        worst: worst, failedRuleIds: failedIds);
  }
  if (cats.isEmpty) return Score(100, cats);
  final average =
      (cats.values.map((c) => c.score).reduce((a, b) => a + b) / cats.length)
          .round();
  final failed = results.where((r) => r.status == RuleStatus.failed).toList();
  final critical = [for (final r in failed) if (r.severity == Severity.critical) r.meta.id];
  final high = [for (final r in failed) if (r.severity == Severity.high) r.meta.id];
  if (critical.isNotEmpty) {
    return Score((average * criticalCap / 100).round(), cats,
        capReason: 'critical', uncapped: average, capRules: critical);
  }
  if (high.isNotEmpty) {
    return Score((average * highCap / 100).round(), cats,
        capReason: 'high', uncapped: average, capRules: high);
  }
  return Score(average, cats);
}

enum ControlStatus { checked, manualOnly, notCovered }

class ControlCoverage {
  ControlCoverage(this.control, this.status, this.ruleIds, [this.failedRuleIds = const []]);
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
        .where((r) => r.counts && r.meta.masvs.contains(c.id))
        .map((r) => r.meta.id)
        .toList();
    final ControlStatus status;
    if (ids.isNotEmpty) {
      status = ControlStatus.checked;
    } else if (manualChecks.any(
        (m) => m.masvs == c.id && profile.includesAny(m.profiles))) {
      status = ControlStatus.manualOnly;
    } else {
      status = ControlStatus.notCovered;
    }
    final failed = results
        .where((r) => r.status == RuleStatus.failed && r.meta.masvs.contains(c.id))
        .map((r) => r.meta.id)
        .toList();
    out.add(ControlCoverage(c, status, ids, failed));
  }
  return Coverage(out);
}
