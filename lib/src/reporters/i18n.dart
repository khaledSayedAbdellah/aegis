/// UI strings for reports.
library;

import '../model.dart';
import '../scoring.dart';

class Strings {
  const Strings(this.lang);
  final String lang;

  bool get ar => lang == 'ar';
  String _t(String en, String ar) => this.ar ? ar : en;

  String get title => _t('Aegis security audit', 'تقرير aegis الأمني');
  String get project => _t('Project', 'المشروع');
  String get profile => _t('MAS profile', 'مستوى الحماية (MAS)');
  String get score => _t('Security score', 'السكور الأمني');
  String get coverage => _t('MASVS coverage', 'تغطية MASVS');
  String get control => _t('Control', 'البند');
  String get result => _t('Result', 'النتيجة');
  String get rules => _t('Rules', 'القواعد');
  String get coverageLegend => _t(
      '✅ checked and passed · ❌ checked, has problems (in bold) · ❔ check it yourself · — not covered by aegis',
      '✅ اتفحص وسليم · ❌ اتفحص وفيه مشاكل (القواعد اللي بالـ bold) · ❔ لازم تتأكد منه بنفسك · — aegis مش بيغطيه');
  String coverageLine(int checked, int total, int pct) => _t(
      '$checked of $total controls checked automatically ($pct%)',
      'اتفحص $checked من $total بند أوتوماتيك ($pct%)');
  String get failed => _t('Needs fixing', 'محتاج يتصلح');
  String get passed => _t('Passed', 'سليم');
  String get notApplicable => _t('Not applicable', 'مش منطبق');
  String get manual => _t('Check manually (no tool can verify these)', 'لازم تتأكد منها بنفسك (مفيش أداة تقدر تفحصها)');
  String get fix => _t('Fix', 'الحل');
  String get why => _t('Why', 'ليه مهم');
  String get categories => _t('By category', 'حسب القسم');
  String get suppressed => _t('suppressed by aegis:ignore', 'متخفي بـ aegis:ignore');
  /// Why the score is limited, e.g. "at most 74 while a HIGH finding is
  /// open (AEG-D01); 96 without it".
  String capped(Score s) {
    final sev = severity(s.capReason == 'critical' ? Severity.critical : Severity.high);
    final rules = s.capRules.join(', ');
    return _t(
        'at most ${s.ceiling} while a $sev finding is open ($rules); ${s.uncapped} without it',
        'مش هيعدي ${s.ceiling} طول ما فيه مشكلة $sev مفتوحة ($rules) · من غيرها كان ${s.uncapped}');
  }

  String get rulesCol => _t('Rules passed', 'القواعد السليمة');
  String get problemsCol => _t('Open problems', 'المشاكل المفتوحة');
  String get packages => _t('Packages scanned', 'المكتبات اللي اتفحصت');
  String get binary => _t('APK', 'الـ APK');
  String binaryKind(String kind) =>
      kind == 'AAB' ? _t('App bundle (AAB)', 'الـ App Bundle (AAB)') : binary;
  String get uploadKey => _t('upload key: Google Play re-signs the app with the app signing key',
      'upload key: Google Play بيعيد توقيع التطبيق بالـ app signing key');
  String get signer => _t('Signed by', 'متوقع بواسطة');
  String get certHash => _t('Certificate SHA-256 (Base64, for freeRASP signingCertHashes)',
      'الـ SHA-256 بتاع الشهادة (Base64، لـ signingCertHashes في freeRASP)');
  String get baseline => _t('Baseline', 'الـ Baseline');
  String baselineLine(int known, int fresh, int fixed) => _t(
      '$known known · $fresh new · $fixed fixed since the baseline',
      '$known معروفة · $fresh جديدة · $fixed اتصلحت من وقت الـ baseline');
  String get newIssues => _t('New issues (not in the baseline)', 'مشاكل جديدة (مش في الـ baseline)');
  String get noNewIssues => _t('No new issues since the baseline.', 'مفيش مشاكل جديدة من وقت الـ baseline.');
  String get known => _t('Known issues (accepted in the baseline)', 'مشاكل معروفة (متسجلة في الـ baseline)');
  String knownCount(int n) => _t('$n known', '$n معروفة');
  String get knownHint => _t(
      'Known issues still count in the score. They do not fail the build (--fail-on) until they change.',
      'المشاكل المعروفة لسه بتأثر على السكور، بس مش بتوقّع الـ build (‎--fail-on) إلا لو اتغيرت.');
  String get resolved => _t('Fixed since the baseline', 'اتصلحت من وقت الـ baseline');
  String get updateHint => _t(
      'Run aegis --update-baseline to remove fixed issues from the baseline.',
      'شغّل aegis --update-baseline علشان تشيل اللي اتصلح من الـ baseline.');
  String get noIssues => _t('No issues found.', 'مفيش مشاكل.');
  String get isKnown => _t('known', 'معروفة');
  String get disclaimer => _t(
      'This score measures how well known protections are implemented in the code and config. It does not prove the app cannot be attacked: backend security and runtime behavior must be tested separately.',
      'السكور ده بيقيس قد إيه الحمايات المعروفة متطبقة في الكود والإعدادات. هو مش إثبات إن التطبيق مستحيل يتخترق: أمان الـ backend وسلوك التطبيق وقت التشغيل لازم يتفحصوا لوحدهم.');
  String severity(Severity s) {
    switch (s) {
      case Severity.critical:
        return _t('CRITICAL', 'خطير جداً');
      case Severity.high:
        return _t('HIGH', 'عالي');
      case Severity.medium:
        return _t('MEDIUM', 'متوسط');
      case Severity.low:
        return _t('LOW', 'منخفض');
      case Severity.info:
        return _t('INFO', 'معلومة');
    }
  }
}
