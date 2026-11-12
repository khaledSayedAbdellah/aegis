/// UI strings for reports.
library;

import '../l10n/messages.g.dart';

import '../model.dart';
import '../scoring.dart';

class Strings {
  const Strings(this.lang);
  final String lang;

  bool get ar => lang == 'ar';

  String get title => L10n(lang).i18nAegisSecurityAudit;
  String get project => L10n(lang).i18nProject;
  String get profile => L10n(lang).i18nMasProfile;
  String get score => L10n(lang).i18nSecurityScore;
  String get coverage => L10n(lang).i18nMasvsCoverage;
  String get control => L10n(lang).i18nControl;
  String get result => L10n(lang).i18nResult;
  String get rules => L10n(lang).i18nRules;
  String get probeCheck => L10n(lang).i18nCheck;
  String get probeObserved => L10n(lang).i18nObserved;
  String get coverageLegend => L10n(lang).i18nCheckedAndPassedCheckedHas;
  String coverageLine(int checked, int total, int pct) =>
      L10n(lang).i18nOfControlsCheckedAutomatically(
          checked: checked, total: total, pct: pct);
  String get failed => L10n(lang).i18nNeedsFixing;
  String get passed => L10n(lang).i18nPassed;
  String get notApplicable => L10n(lang).i18nNotApplicable;
  String get evidenceOnly => L10n(lang).i18nEvidenceOnly;
  String get manual => L10n(lang).i18nCheckManuallyNoToolCanVerifyThese;
  String get fix => L10n(lang).i18nFix;
  String get why => L10n(lang).i18nWhy;
  String get categories => L10n(lang).i18nByCategory;
  String get suppressed => L10n(lang).i18nSuppressedByAegisIgnore;

  /// Why the score is in its band and what lifts it out, e.g. "40-69 while
  /// a HIGH problem is open (AEG-D01, AEG-P01); fixing them gives 80".
  /// Null when nothing above low is open.
  String? band(Score s) {
    final w = s.worst;
    final b = s.band;
    if (w == null || b == null || !(w >= Severity.medium)) return null;
    final sev = severity(w);
    final rules = s.blockingRules.join(', ');
    final range = '${b.$1}-${b.$2 - 1}';
    final after = s.afterBlockingFixed;
    return L10n(lang)
        .scoreBand(range: range, severity: sev, rules: rules, after: after);
  }

  /// The single fixes worth most points, e.g. "AEG-D01 +4 · AEG-P05 +2".
  String? bestFixes(Score s) {
    final top = s.gains.entries.where((e) => e.value > 0).take(3).toList();
    if (top.isEmpty) return null;
    final list = top.map((e) => '${e.key} +${e.value}').join(' · ');
    return L10n(lang).i18nBiggestSingleGains(list: list);
  }

  String get rulesCol => L10n(lang).i18nRulesPassed;
  String get problemsCol => L10n(lang).i18nOpenProblems;
  String get packages => L10n(lang).i18nPackagesScanned;
  String get binary => L10n(lang).i18nApk;
  String binaryKind(String kind) => switch (kind) {
        'AAB' => L10n(lang).i18nAppBundleAab,
        'IPA' => L10n(lang).i18nIosApplicationIpa,
        _ => binary,
      };
  String get uploadKey => L10n(lang).i18nUploadKeyGooglePlayReSignsTheAppWith;
  String get signer => L10n(lang).i18nSignedBy;
  String certHash(String kind) => kind == 'IPA'
      ? L10n(lang).i18nSigningCertificateSha256Base64
      : L10n(lang).i18nCertificateSha256Base64ForFreeraspSigningcerthashes;
  String get baseline => L10n(lang).i18nBaseline;
  String baselineLine(int known, int fresh, int fixed) => L10n(lang)
      .i18nKnownNewFixedSinceThe(known: known, fresh: fresh, fixed: fixed);
  String get newIssues => L10n(lang).i18nNewIssuesNotInTheBaseline;
  String get noNewIssues => L10n(lang).i18nNoNewIssuesSinceTheBaseline;
  String get known => L10n(lang).i18nKnownIssuesAcceptedInTheBaseline;
  String knownCount(int n) => L10n(lang).i18nKnown(n: n);
  String get knownHint => L10n(lang).i18nKnownIssuesStillCountInTheScoreThey;
  String get resolved => L10n(lang).i18nFixedSinceTheBaseline;
  String get updateHint =>
      L10n(lang).i18nRunAegisUpdateBaselineToRemoveFixedIssuesFrom;
  String get noIssues => L10n(lang).i18nNoIssuesFound;
  String get isKnown => L10n(lang).i18nKnown2;
  String get disclaimer =>
      L10n(lang).i18nThisScoreMeasuresHowWellKnownProtectionsAre;
  String severity(Severity s) {
    switch (s) {
      case Severity.critical:
        return L10n(lang).i18nCritical;
      case Severity.high:
        return L10n(lang).i18nHigh;
      case Severity.medium:
        return L10n(lang).i18nMedium;
      case Severity.low:
        return L10n(lang).i18nLow;
      case Severity.info:
        return L10n(lang).i18nInfo;
    }
  }
}
