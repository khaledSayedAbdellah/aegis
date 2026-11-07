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
  CategoryScore(this.category, this.score, this.checked, this.failed);
  final String category;
  final int score;
  final int checked;
  final int failed;
}

class Score {
  Score(this.value, this.categories, {this.capReason});

  final int value;
  final Map<String, CategoryScore> categories;

  /// Set when the score was capped by a critical/high finding.
  final String? capReason;

  String get grade => gradeOf(value);

  static String gradeOf(int v) {
    if (v >= 90) return 'A';
    if (v >= 80) return 'B';
    if (v >= 70) return 'C';
    if (v >= 60) return 'D';
    return 'F';
  }
}

Score computeScore(List<RuleResult> results) {
  final byCat = <String, List<RuleResult>>{};
  for (final r in results.where((r) => r.counts)) {
    byCat.putIfAbsent(r.meta.category, () => []).add(r);
  }
  final cats = <String, CategoryScore>{};
  for (final e in byCat.entries) {
    var s = 100;
    var failed = 0;
    for (final r in e.value) {
      if (r.status != RuleStatus.failed) continue;
      failed++;
      s -= severityWeight[r.severity]!;
    }
    cats[e.key] =
        CategoryScore(e.key, s.clamp(0, 100).toInt(), e.value.length, failed);
  }
  if (cats.isEmpty) return Score(100, cats);
  var overall =
      (cats.values.map((c) => c.score).reduce((a, b) => a + b) / cats.length)
          .round();
  String? cap;
  final failed = results.where((r) => r.status == RuleStatus.failed);
  if (failed.any((r) => r.severity == Severity.critical) && overall > criticalCap) {
    overall = criticalCap;
    cap = 'critical';
  } else if (failed.any((r) => r.severity == Severity.high) && overall > highCap) {
    overall = highCap;
    cap = 'high';
  }
  return Score(overall, cats, capReason: cap);
}

enum ControlStatus { checked, manualOnly, notCovered }

class ControlCoverage {
  ControlCoverage(this.control, this.status, this.ruleIds);
  final MasvsControl control;
  final ControlStatus status;
  final List<String> ruleIds;
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
    out.add(ControlCoverage(c, status, ids));
  }
  return Coverage(out);
}
