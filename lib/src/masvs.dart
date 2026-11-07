/// OWASP MASVS v2 controls, used for coverage reporting.
library;

import 'model.dart';

class MasvsControl {
  const MasvsControl(this.id, this.text, {this.resilienceOnly = false});

  final String id;
  final Bilingual text;

  /// Controls that only make sense when the MAS-R profile is selected.
  final bool resilienceOnly;

  String get category => id.split('-')[1];
}

const List<MasvsControl> masvsControls = [
  MasvsControl(
      'MASVS-STORAGE-1',
      Bilingual('The app securely stores sensitive data.',
          'التطبيق بيخزن البيانات الحساسة بشكل آمن.')),
  MasvsControl(
      'MASVS-STORAGE-2',
      Bilingual('The app prevents leakage of sensitive data.',
          'التطبيق بيمنع تسريب البيانات الحساسة.')),
  MasvsControl(
      'MASVS-CRYPTO-1',
      Bilingual('The app employs current strong cryptography.',
          'التطبيق بيستخدم تشفير قوي وحديث.')),
  MasvsControl(
      'MASVS-CRYPTO-2',
      Bilingual('The app performs key management according to best practices.',
          'التطبيق بيدير مفاتيح التشفير بالطريقة الصح.')),
  MasvsControl(
      'MASVS-AUTH-1',
      Bilingual('The app uses secure authentication and authorization protocols.',
          'التطبيق بيستخدم بروتوكولات مصادقة وصلاحيات آمنة.')),
  MasvsControl(
      'MASVS-AUTH-2',
      Bilingual('The app performs local authentication securely.',
          'المصادقة المحلية (زي البصمة) متطبقة بشكل آمن.')),
  MasvsControl(
      'MASVS-AUTH-3',
      Bilingual('The app secures sensitive operations with additional authentication.',
          'العمليات الحساسة محمية بمصادقة إضافية.')),
  MasvsControl(
      'MASVS-NETWORK-1',
      Bilingual('The app secures all network traffic.',
          'كل الاتصالات بالشبكة مؤمنة.')),
  MasvsControl(
      'MASVS-NETWORK-2',
      Bilingual('The app performs identity pinning for endpoints under the developer\'s control.',
          'التطبيق بيعمل certificate pinning للسيرفرات بتاعته.')),
  MasvsControl(
      'MASVS-PLATFORM-1',
      Bilingual('The app uses IPC mechanisms securely.',
          'التطبيق بيستخدم آليات التواصل بين التطبيقات (IPC) بأمان.')),
  MasvsControl(
      'MASVS-PLATFORM-2',
      Bilingual('The app uses WebViews securely.',
          'التطبيق بيستخدم الـ WebView بأمان.')),
  MasvsControl(
      'MASVS-PLATFORM-3',
      Bilingual('The app uses the user interface securely.',
          'الواجهة مش بتكشف بيانات حساسة.')),
  MasvsControl(
      'MASVS-CODE-1',
      Bilingual('The app requires an up-to-date platform version.',
          'التطبيق بيطلب إصدار نظام تشغيل حديث.')),
  MasvsControl(
      'MASVS-CODE-2',
      Bilingual('The app has a mechanism for enforcing app updates.',
          'فيه آلية لإجبار المستخدم على التحديث.')),
  MasvsControl(
      'MASVS-CODE-3',
      Bilingual('The app only uses software components without known vulnerabilities.',
          'المكتبات المستخدمة مفيهاش ثغرات معروفة.')),
  MasvsControl(
      'MASVS-CODE-4',
      Bilingual('The app validates and sanitizes all untrusted inputs.',
          'التطبيق بيتحقق من أي مدخلات غير موثوقة.')),
  MasvsControl(
      'MASVS-RESILIENCE-1',
      Bilingual('The app validates the integrity of the platform.',
          'التطبيق بيتأكد إن الجهاز سليم (مش rooted أو jailbroken).'),
      resilienceOnly: true),
  MasvsControl(
      'MASVS-RESILIENCE-2',
      Bilingual('The app implements anti-tampering mechanisms.',
          'التطبيق بيكشف لو حد عدّل عليه أو أعاد توقيعه.'),
      resilienceOnly: true),
  MasvsControl(
      'MASVS-RESILIENCE-3',
      Bilingual('The app implements anti-static analysis mechanisms.',
          'التطبيق صعب يتحلل ويتفك (obfuscation).'),
      resilienceOnly: true),
  MasvsControl(
      'MASVS-RESILIENCE-4',
      Bilingual('The app implements anti-dynamic analysis techniques.',
          'التطبيق بيكشف الـ debugging والـ hooking وقت التشغيل.'),
      resilienceOnly: true),
  MasvsControl(
      'MASVS-PRIVACY-1',
      Bilingual('The app minimizes access to sensitive data and resources.',
          'التطبيق بيطلب أقل صلاحيات وبيانات ممكنة.')),
  MasvsControl(
      'MASVS-PRIVACY-2',
      Bilingual('The app prevents identification of the user.',
          'التطبيق بيمنع التعرف على هوية المستخدم بدون داعي.')),
  MasvsControl(
      'MASVS-PRIVACY-3',
      Bilingual('The app is transparent about data collection and usage.',
          'التطبيق واضح في البيانات اللي بيجمعها.')),
  MasvsControl(
      'MASVS-PRIVACY-4',
      Bilingual('The app offers user control over their data.',
          'المستخدم يقدر يتحكم في بياناته.')),
];

/// Category display names.
const Map<String, Bilingual> masvsCategories = {
  'STORAGE': Bilingual('Storage', 'التخزين'),
  'CRYPTO': Bilingual('Cryptography', 'التشفير'),
  'AUTH': Bilingual('Authentication', 'المصادقة'),
  'NETWORK': Bilingual('Network', 'الشبكة'),
  'PLATFORM': Bilingual('Platform', 'المنصة'),
  'CODE': Bilingual('Code & dependencies', 'الكود والمكتبات'),
  'RESILIENCE': Bilingual('Resilience', 'مقاومة الاختراق'),
  'PRIVACY': Bilingual('Privacy', 'الخصوصية'),
};

/// Things no static tool can verify. Listed in every report so a clean score
/// is never mistaken for a clean app.
class ManualCheck {
  const ManualCheck(this.id, this.masvs, this.text,
      {this.profiles = const {MasProfile.l1}});
  final String id;
  final String masvs;
  final Bilingual text;
  final Set<MasProfile> profiles;
}

const List<ManualCheck> manualChecks = [
  ManualCheck(
      'AEG-M01',
      'MASVS-AUTH-1',
      Bilingual(
          'The backend enforces authorization on every endpoint (never trust the client).',
          'الـ backend بيتحقق من الصلاحيات في كل endpoint (متثقش في التطبيق أبداً).')),
  ManualCheck(
      'AEG-M02',
      'MASVS-AUTH-1',
      Bilingual('Sessions/tokens expire and are revoked on logout on the server.',
          'الـ tokens بتنتهي صلاحيتها وبتتلغي من السيرفر عند تسجيل الخروج.')),
  ManualCheck(
      'AEG-M03',
      'MASVS-RESILIENCE-2',
      Bilingual(
          'Attestation verdicts (Play Integrity / App Attest / App Check) are verified on the server, and App Check enforcement is ON in the Firebase console.',
          'نتيجة الـ attestation بيتم التحقق منها على السيرفر، والـ enforcement مفعّل في Firebase Console.'),
      profiles: {MasProfile.l2, MasProfile.r}),
  ManualCheck(
      'AEG-M04',
      'MASVS-RESILIENCE-2',
      Bilingual(
          'The Play App Signing certificate hash (from Play Console) is included in your RASP config, not only the upload key.',
          'الـ hash بتاع Play App Signing (من Play Console) موجود في إعدادات الـ RASP، مش upload key بس.'),
      profiles: {MasProfile.r}),
  ManualCheck(
      'AEG-M05',
      'MASVS-RESILIENCE-3',
      Bilingual(
          'The shipped binary is really obfuscated (verify the release APK/IPA, not just the build flag).',
          'الـ binary اللي اتشحن فعلاً عليه obfuscation (اتأكد من الـ APK/IPA نفسه، مش الـ flag بس).'),
      profiles: {MasProfile.r}),
  ManualCheck(
      'AEG-M06',
      'MASVS-PRIVACY-3',
      Bilingual(
          'Store privacy labels / Data safety form match the SDKs the app actually ships.',
          'بيانات الخصوصية في المتاجر (Data safety / Privacy labels) مطابقة للمكتبات اللي في التطبيق.')),
  ManualCheck(
      'AEG-M07',
      'MASVS-CODE-2',
      Bilingual('A forced-update mechanism exists for critical security fixes.',
          'فيه آلية تجبر المستخدم يحدّث لو فيه إصلاح أمني مهم.'),
      profiles: {MasProfile.l2}),
  ManualCheck(
      'AEG-M08',
      'MASVS-CODE-4',
      Bilingual('Deep links and push payloads are validated before use.',
          'الـ deep links والـ push notifications بيتم التحقق منها قبل الاستخدام.')),
];
