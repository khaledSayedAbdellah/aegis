/// UI strings for reports.
library;

import '../model.dart';

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
  String capped(String reason) => _t(
      'capped because a $reason finding is open',
      'السكور له سقف لأن فيه مشكلة $reason مفتوحة');
  String get packages => _t('Packages scanned', 'المكتبات اللي اتفحصت');
  String get binary => _t('APK', 'الـ APK');
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
