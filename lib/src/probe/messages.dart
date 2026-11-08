/// en/ar strings for `aegis doctor` and `aegis setup`.
library;

import 'pins.dart' as pins;
import 'toolchain.dart';

/// Human titles for each tool id, in both languages.
const _titles = <String, (String, String)>{
  'flutter': ('Flutter', 'Flutter'),
  'java': ('Java (JDK 17+)', 'Java (JDK 17+)'),
  'android-sdk': ('Android SDK', 'Android SDK'),
  'cmdline-tools': ('SDK command-line tools', 'أدوات سطر أوامر الـ SDK'),
  'platform-tools': ('platform-tools (adb)', 'platform-tools (adb)'),
  'build-tools': ('build-tools (apksigner)', 'build-tools (apksigner)'),
  'emulator': ('Emulator', 'المحاكي'),
  'system-image': ('Android 14 system image', 'صورة نظام Android 14'),
  'avd': ('AVD "${avd}"', 'جهاز وهمي "${avd}"'),
  'python': ('Python 3', 'Python 3'),
  'frida': ('Frida', 'Frida'),
  'frida-server': ('frida-server (Android)', 'frida-server (أندرويد)'),
  'bundletool': ('bundletool', 'bundletool'),
};

class Msg {
  const Msg(this.lang);
  final String lang;
  bool get ar => lang == 'ar';
  String _t(String en, String arTxt) => ar ? arTxt : en;

  String title(String id) {
    final t = _titles[id];
    if (t == null) return id;
    return (ar ? t.$2 : t.$1).replaceAll(r'${avd}', pins.avdName);
  }

  String get header => _t('Resilience probe tools', 'أدوات اختبار الحماية');

  /// The reason line shown after a tool that is not simply present.
  String issue(ToolCheck c) {
    final d = c.detail;
    return switch (c.issue) {
      Issue.flutterMissing => _t(
          'not found on PATH — install Flutter',
          'مش موجود في الـ PATH — سطّب Flutter'),
      Issue.javaMissing => _t(
          'no JDK found — install Android Studio, or set it with flutter config --jdk-dir',
          'مفيش JDK — سطّب Android Studio، أو حدّده بـ flutter config --jdk-dir'),
      Issue.javaOld => _t(
          'found Java ${d['found']}, but ${d['need']}+ is needed',
          'لقى Java ${d['found']}، بس محتاج ${d['need']}+'),
      Issue.sdkMissing => _t(
          'not found — install Android Studio (brings the SDK), or set ANDROID_HOME',
          'مش موجود — سطّب Android Studio (بيجيب الـ SDK)، أو حدّد ANDROID_HOME'),
      Issue.cmdlineMissing => _t(
          'missing — Android Studio: Settings → Languages & Frameworks → Android SDK → '
              'SDK Tools → "Android SDK Command-line Tools (latest)"',
          'ناقصة — في Android Studio: Settings → Languages & Frameworks → Android SDK → '
              'SDK Tools → "Android SDK Command-line Tools (latest)"'),
      Issue.buildToolsOld => _t(
          'too old — aegis installs ${pins.buildToolsVersion}',
          'قديمة — aegis هيسطّب ${pins.buildToolsVersion}'),
      Issue.pythonMissing => _t(
          'no Python 3.9+ found — install it, then rerun',
          'مفيش Python 3.9+ — سطّبه وبعدين شغّل تاني'),
      Issue.pythonOld => _t(
          'Python ${c.version} is too old (need ${pins.minPython.$1}.${pins.minPython.$2}+)',
          'Python ${c.version} قديم (محتاج ${pins.minPython.$1}.${pins.minPython.$2}+)'),
      Issue.pythonNoVenv => _t(
          'this Python has no venv module — install python3-venv',
          'الـ Python ده مفيهوش venv — سطّب python3-venv'),
      Issue.fridaOtherVersion => _t(
          'have ${d['have']}, need ${d['want']}',
          'عندك ${d['have']}، محتاج ${d['want']}'),
      Issue.optionalAab => _t(
          'optional, only for .aab — "aegis setup --aab"',
          'اختياري، للـ .aab بس — "aegis setup --aab"'),
      Issue.missing || null => _t('not installed', 'مش متسطّب'),
    };
  }

  /// The short note after an installable row in `doctor`.
  String get installHint =>
      _t('"aegis setup" installs it', '"aegis setup" هيسطّبه');

  String allPresent(bool ar) =>
      _t('Everything the probe needs is installed.', 'كل اللي الاختبار محتاجه متسطّب.');

  String get someManual => _t(
      'Some tools you install yourself (see above), then run "aegis setup".',
      'في أدوات بتسطّبها بنفسك (فوق)، وبعدين شغّل "aegis setup".');

  // setup
  String get willInstall => _t('Will install:', 'هيتسطّب:');
  String get alreadyThere => _t('present, skipped', 'موجود، هيتعدّى');
  String installYourself(ToolCheck c) =>
      _t('install it yourself: ', 'سطّبه بنفسك: ') + issue(c);
  String waitingFor(List<String> needs) => _t(
      'waiting for ${needs.join(', ')}', 'مستني ${needs.join('، ')}');
  String get licensesNote => _t(
      'The Android SDK tools will ask you to accept their licenses.',
      'أدوات الـ Android SDK هتطلب منك توافق على الرخص.');
  String get confirm => _t('Continue? [y/N]: ', 'أكمل؟ [y/N]: ');
  String get cancelled => _t('Cancelled.', 'اتلغى.');
  String get noTerminal =>
      _t('No terminal; use "aegis setup --yes".', 'مفيش terminal؛ استخدم "aegis setup --yes".');
  String get nothingToInstall =>
      _t('Nothing to install.', 'مفيش حاجة تتسطّب.');
  String get done => _t('Done.', 'خلص.');
  String get result => _t('Result:', 'النتيجة:');
  String savedTo(String path) =>
      _t('Paths saved to $path', 'المسارات اتحفظت في $path');
  String get stillMissing => _t(
      'Some tools are still missing; see above.',
      'لسه في أدوات ناقصة؛ شوف فوق.');
  String freeSpaceWarning(String need, String have) => _t(
      'The system image needs ~$need free, you have ~$have.',
      'صورة النظام محتاجة ~$need فاضية، عندك ~$have.');
  String step(String title) => _t('Installing $title…', 'بيسطّب $title…');
}

/// Yes answers accepted at the setup prompt.
const yesAnswers = ['y', 'yes', 'اه', 'أه', 'أيوه', 'ايوه', 'نعم', 'ن'];
