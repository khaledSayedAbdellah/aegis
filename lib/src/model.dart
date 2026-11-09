/// Core data types shared by rules, the engine and the reporters.
library;

import 'pass_titles.dart';

/// How bad a finding is. Ordered from least to most severe.
enum Severity {
  info,
  low,
  medium,
  high,
  critical;

  /// Parses `low`, `medium`, `high`, `critical` or `info` (case-insensitive).
  static Severity? tryParse(String? value) {
    if (value == null) return null;
    final v = value.trim().toLowerCase();
    for (final s in Severity.values) {
      if (s.name == v) return s;
    }
    return null;
  }

  bool operator >=(Severity other) => index >= other.index;
  bool operator >(Severity other) => index > other.index;
}

/// OWASP MAS testing profiles.
///
/// * [l1] – baseline security for every app.
/// * [l2] – defense-in-depth for apps handling high-risk sensitive data.
/// * [r] – resilience against reverse engineering and tampering
///   (always combined with L1 or L2, never alone).
enum MasProfile { l1, l2, r }

/// A selection of MAS profiles, e.g. `L2+R`.
class ProfileSet {
  const ProfileSet(this.base, {this.resilience = false});

  /// Either [MasProfile.l1] or [MasProfile.l2].
  final MasProfile base;

  /// Whether MAS-R is added on top of [base].
  final bool resilience;

  static const ProfileSet standard = ProfileSet(MasProfile.l1);

  /// Named presets so people don't need to know the OWASP vocabulary.
  static const Map<String, String> presets = {
    'standard': 'l1',
    'basic': 'l1',
    'sensitive': 'l2',
    'health': 'l2',
    'game': 'l1+r',
    'media': 'l1+r',
    'banking': 'l2+r',
    'fintech': 'l2+r',
    'payments': 'l2+r',
    'government': 'l2+r',
  };

  /// Parses `l1`, `l2`, `l1+r`, `l2+r` or a preset name such as `banking`.
  static ProfileSet? tryParse(String? input) {
    if (input == null) return null;
    var v = input.trim().toLowerCase().replaceAll(' ', '');
    v = presets[v] ?? v;
    final parts = v.split('+').where((p) => p.isNotEmpty).toSet();
    if (parts.isEmpty) return null;
    MasProfile? base;
    var r = false;
    for (final p in parts) {
      switch (p) {
        case 'l1':
          base = base == MasProfile.l2 ? MasProfile.l2 : MasProfile.l1;
        case 'l2':
          base = MasProfile.l2;
        case 'r':
          r = true;
        default:
          return null;
      }
    }
    return ProfileSet(base ?? MasProfile.l1, resilience: r);
  }

  /// True when a rule tagged with [profiles] is in scope for this selection.
  /// L2 includes everything from L1.
  bool includesAny(Set<MasProfile> profiles) {
    if (profiles.contains(MasProfile.l1)) return true;
    if (profiles.contains(MasProfile.l2) && base == MasProfile.l2) return true;
    if (profiles.contains(MasProfile.r) && resilience) return true;
    return false;
  }

  bool get isL2 => base == MasProfile.l2;

  @override
  String toString() =>
      '${base == MasProfile.l2 ? 'L2' : 'L1'}${resilience ? '+R' : ''}';
}

/// Text in both supported languages.
class Bilingual {
  const Bilingual(this.en, this.ar);
  final String en;
  final String ar;

  String of(String lang) => lang == 'ar' ? ar : en;
}

/// Static description of a rule.
class RuleMeta {
  const RuleMeta({
    required this.id,
    required this.title,
    required this.description,
    required this.fix,
    required this.severity,
    required this.masvs,
    required this.profiles,
    this.maswe = const [],
    this.cwe,
    this.l2Severity,
    this.passTitleText,
  });

  /// Stable id such as `AEG-A01`.
  final String id;

  /// Describes the problem, e.g. "Android app is debuggable".
  final Bilingual title;

  /// Describes the healthy state, shown when the rule passes.
  Bilingual get passTitle => passTitleText ?? passTitles[id] ?? title;

  /// Overrides the shared pass title (see [mapText]).
  final Bilingual? passTitleText;

  /// A copy with every text (both languages) passed through [f], e.g. to
  /// say "AAB" instead of "APK".
  RuleMeta mapText(String Function(String) f) {
    Bilingual m(Bilingual b) => Bilingual(f(b.en), f(b.ar));
    return RuleMeta(
      id: id,
      title: m(title),
      description: m(description),
      fix: m(fix),
      severity: severity,
      masvs: masvs,
      profiles: profiles,
      maswe: maswe,
      cwe: cwe,
      l2Severity: l2Severity,
      passTitleText: m(passTitle),
    );
  }

  /// Why this matters.
  final Bilingual description;

  /// What to do about it.
  final Bilingual fix;

  /// Default severity.
  final Severity severity;

  /// Severity to use when the L2 profile is selected (stricter apps).
  final Severity? l2Severity;

  /// MASVS v2 control ids, e.g. `MASVS-NETWORK-1`.
  final List<String> masvs;

  /// MASWE weakness ids, e.g. `MASWE-0026`.
  final List<String> maswe;

  /// CWE id, e.g. `CWE-319`.
  final String? cwe;

  /// Profiles in which this rule is active.
  final Set<MasProfile> profiles;

  /// The MASVS category of the first control, e.g. `NETWORK`.
  String get category {
    if (masvs.isEmpty) return 'CODE';
    final parts = masvs.first.split('-');
    return parts.length >= 2 ? parts[1] : 'CODE';
  }

  Severity severityFor(ProfileSet profile) =>
      profile.isL2 ? (l2Severity ?? severity) : severity;
}

/// A single problem found in the project.
class Finding {
  Finding({
    required this.ruleId,
    required this.message,
    this.file,
    this.line,
    this.snippet,
    this.messageAr,
  });

  final String ruleId;

  /// English detail specific to this occurrence.
  final String message;

  /// Optional Arabic detail; falls back to [message].
  final String? messageAr;

  /// Path relative to the project root, using `/`.
  final String? file;
  final int? line;

  /// Short, already-redacted excerpt.
  final String? snippet;

  /// True when this finding is listed in the baseline (a known issue).
  bool baselined = false;

  String messageOf(String lang) =>
      lang == 'ar' ? (messageAr ?? message) : message;

  String get location {
    if (file == null) return '';
    return line == null ? file! : '$file:$line';
  }

  Map<String, Object?> toJson() => {
        'ruleId': ruleId,
        'message': message,
        if (messageAr != null) 'messageAr': messageAr,
        if (file != null) 'file': file,
        if (line != null) 'line': line,
        if (snippet != null) 'snippet': snippet,
        if (baselined) 'baselined': true,
      };
}

/// The outcome of running one rule.
enum RuleStatus {
  /// The rule ran and found nothing.
  passed,

  /// The rule ran and produced findings.
  failed,

  /// The rule does not apply (e.g. no `ios/` folder).
  notApplicable,

  /// The rule could not complete or reach a verdict.
  incomplete,

  /// The rule is disabled in `aegis.yaml`.
  disabled,

  /// The rule is outside the selected MAS profile.
  outOfProfile,
}

class RuleResult {
  RuleResult({
    required this.meta,
    required this.status,
    required this.severity,
    this.findings = const [],
    this.suppressed = 0,
    this.incomplete = false,
    this.note,
  });

  final RuleMeta meta;
  final RuleStatus status;
  final bool incomplete;

  /// Effective severity for the selected profile.
  final Severity severity;
  final List<Finding> findings;

  /// Findings hidden by inline `aegis:ignore` comments.
  final int suppressed;

  /// Why the rule was not applicable, if relevant.
  final String? note;

  bool get counts =>
      status == RuleStatus.passed || status == RuleStatus.failed;

  /// Findings that are not in the baseline.
  List<Finding> get newFindings =>
      findings.where((f) => !f.baselined).toList();

  /// Findings accepted by the baseline.
  List<Finding> get knownFindings =>
      findings.where((f) => f.baselined).toList();

  /// Failed with at least one finding that is not in the baseline.
  bool get hasNew =>
      status == RuleStatus.failed && findings.any((f) => !f.baselined);
}
