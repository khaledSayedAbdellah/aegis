/// Titles shown when a rule passes.
///
/// Rule titles describe the problem ("Android app is debuggable"), which reads
/// wrong next to a check mark. These describe the healthy state instead.
library;

import 'model.dart';

const Map<String, Bilingual> passTitles = {
  // Protection correctness
  'AEG-P01': Bilingual('Runtime protection (RASP) is present', 'حماية وقت التشغيل (RASP) موجودة'),
  'AEG-P02': Bilingual('freeRASP is started and listening', 'freeRASP شغال ومتربط بـ callback'),
  'AEG-P03': Bilingual('freeRASP configuration matches the app', 'إعدادات freeRASP مطابقة للتطبيق'),
  'AEG-P04': Bilingual('Detected threats trigger a real reaction', 'التهديدات اللي بتتكشف ليها رد فعل حقيقي'),
  'AEG-P05': Bilingual('Firebase is protected by App Check', 'Firebase محمي بـ App Check'),
  'AEG-P06': Bilingual('App Check debug provider is limited to debug builds', 'الـ debug provider بتاع App Check محصور في الـ debug'),
  'AEG-P07': Bilingual('Certificate pinning is in place', 'الـ certificate pinning موجود'),
  'AEG-P08': Bilingual('Biometrics are bound to a key', 'البصمة مربوطة بمفتاح تشفير'),
  'AEG-P09': Bilingual('Screens are protected from capture', 'الشاشات محمية من التصوير والتسجيل'),
  'AEG-P10': Bilingual('Release builds use --obfuscate', 'بيلد الـ release بيستخدم --obfuscate'),
  // Android
  'AEG-A01': Bilingual('Android app is not debuggable', 'التطبيق مش قابل للـ debugging على Android'),
  'AEG-A02': Bilingual('App data backup is restricted', 'الـ backup لبيانات التطبيق مقفول أو محدود'),
  'AEG-A03': Bilingual('Manifest does not allow cleartext traffic', 'الـ manifest مش بيسمح بـ HTTP غير مشفر'),
  'AEG-A04': Bilingual('Network security config is strict', 'إعدادات network security config صارمة'),
  'AEG-A05': Bilingual('Certificate pins are not expired', 'الـ certificate pins لسه صالحة'),
  'AEG-A06': Bilingual('Exported components are protected', 'المكونات الـ exported محمية'),
  'AEG-A07': Bilingual('R8 shrinking/obfuscation is enabled', 'الـ R8 (shrinking/obfuscation) شغال'),
  'AEG-A08': Bilingual('Release build is not signed with the debug key', 'الـ release مش متوقع بمفتاح الـ debug'),
  'AEG-A09': Bilingual('Signing secrets are not exposed', 'أسرار التوقيع مش مكشوفة'),
  'AEG-A10': Bilingual('minSdk is 24 or higher', 'الـ minSdk 24 أو أكتر'),
  // iOS
  'AEG-I01': Bilingual('App Transport Security is enabled', 'الـ App Transport Security شغال'),
  'AEG-I02': Bilingual('ATS exceptions are safe', 'استثناءات الـ ATS آمنة'),
  'AEG-I03': Bilingual('No debugging entitlement in release', 'مفيش صلاحية debugging في الـ release'),
  'AEG-I04': Bilingual('Documents folder is not exposed', 'فولدر Documents مش مكشوف'),
  // Dart code
  'AEG-D01': Bilingual('No hardcoded secrets in Dart code', 'مفيش أسرار مكتوبة في كود Dart'),
  'AEG-D02': Bilingual('No cleartext http:// URLs in code', 'مفيش لينكات http:// في الكود'),
  'AEG-D03': Bilingual('TLS certificates are validated', 'شهادات TLS بيتم التحقق منها'),
  'AEG-D04': Bilingual('Sensitive data is not kept in plain storage', 'البيانات الحساسة مش متخزنة من غير تشفير'),
  'AEG-D05': Bilingual('No weak cryptography', 'مفيش تشفير ضعيف'),
  'AEG-D06': Bilingual('No hardcoded encryption keys or IVs', 'مفيش مفاتيح تشفير أو IV ثابتة في الكود'),
  'AEG-D07': Bilingual('Security values use a secure random generator', 'القيم الأمنية بتستخدم Random آمن'),
  'AEG-D08': Bilingual('No sensitive data in logs', 'مفيش بيانات حساسة في الـ logs'),
  'AEG-D09': Bilingual('No secret files bundled as assets', 'مفيش ملفات أسرار متضافة كـ assets'),
  'AEG-D10': Bilingual('WebViews are locked down', 'الـ WebView مقفول كويس'),
  // Dependencies
  'AEG-C01': Bilingual('No dependencies with known vulnerabilities', 'مفيش مكتبات عليها ثغرات معروفة'),
  'AEG-C02': Bilingual('Dependencies are pinned', 'المكتبات متثبتة على نسخ محددة'),
  // APK
  'AEG-B01': Bilingual('The APK is a release (AOT) build', 'الـ APK نسخة release (AOT)'),
  'AEG-B02': Bilingual('The APK is not debuggable', 'الـ APK مش قابل للـ debugging'),
  'AEG-B03': Bilingual('Final manifest keeps backup and network settings safe', 'الـ manifest النهائي محافظ على إعدادات الـ backup والشبكة'),
  'AEG-B04': Bilingual('Libraries add no unprotected exported components', 'المكتبات مش بتضيف مكونات exported من غير حماية'),
  'AEG-B05': Bilingual('No sensitive permissions added by libraries', 'مفيش صلاحيات حساسة ضافتها مكتبات'),
  'AEG-B06': Bilingual('No secrets found inside the APK', 'مفيش أسرار جوه الـ APK'),
  'AEG-B07': Bilingual('The shipped Dart code is obfuscated', 'كود Dart اللي اتشحن متعمله obfuscation'),
  'AEG-B08': Bilingual('No secret files inside the APK', 'مفيش ملفات أسرار جوه الـ APK'),
  'AEG-B09': Bilingual('The APK is signed with a release certificate', 'الـ APK متوقع بشهادة release'),
  'AEG-B10': Bilingual('freeRASP knows this APK\'s certificate', 'freeRASP عارف شهادة الـ APK ده'),
  'AEG-B11': Bilingual('APK SDK levels are current', 'إصدارات الـ SDK في الـ APK حديثة'),
};
