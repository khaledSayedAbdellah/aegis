/// Rules for Android configuration: manifest, Gradle and network config.
library;

import 'package:xml/xml.dart';

import '../model.dart';
import '../project.dart';
import '../util.dart';
import 'rule.dart';

const _all = {MasProfile.l1, MasProfile.l2, MasProfile.r};

/// Body of `buildTypes { release { ... } }` (Groovy or Kotlin DSL).
String? _releaseBlock(String gradle) {
  final text = stripCComments(gradle);
  final buildTypes = findBlock(text, 'buildTypes');
  if (buildTypes == null) return null;
  final bt = buildTypes.body;
  final direct = findBlock(bt, 'release');
  if (direct != null) return direct.body;
  final m = RegExp(r'''getByName\s*\(\s*["']release["']\s*\)\s*\{''')
      .firstMatch(bt);
  if (m == null) return null;
  final close = matchingBrace(bt, m.end - 1);
  return close == null ? null : bt.substring(m.end, close);
}

class DebuggableRule extends Rule {
  const DebuggableRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-A01',
        title: Bilingual('Android app is debuggable', 'التطبيق قابل للـ debugging على Android'),
        description: Bilingual(
            'A debuggable release lets anyone attach a debugger, read memory and bypass checks.',
            'لو نسخة الـ release قابلة للـ debugging، أي حد يقدر يوصل debugger ويقرا الذاكرة ويتخطى أي فحص.'),
        fix: Bilingual(
            'Remove android:debuggable from AndroidManifest.xml and never set debuggable/isDebuggable true for release.',
            'شيل android:debuggable من AndroidManifest.xml، ومتخليش debuggable أو isDebuggable بـ true في الـ release.'),
        severity: Severity.critical,
        masvs: ['MASVS-RESILIENCE-4'],
        maswe: ['MASWE-0063'],
        cwe: 'CWE-489',
        profiles: _all,
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final m = project.androidManifest;
    if (m == null || project.androidManifestXml == null) {
      return RuleCheck.notApplicable('No AndroidManifest.xml');
    }
    final out = <Finding>[];
    final app = firstElement(project.androidManifestXml!, 'application');
    if (app != null && androidAttr(app, 'debuggable') == 'true') {
      out.add(inFile(m.path, lineOfFirst(m.text, 'android:debuggable'),
          'android:debuggable="true" is set in the main manifest.',
          messageAr: 'android:debuggable="true" موجود في الـ manifest الأساسي.'));
    }
    final g = project.appGradle;
    if (g != null) {
      final release = _releaseBlock(g.text);
      if (release != null &&
          RegExp(r'(isDebuggable\s*=\s*true|debuggable\s*(=\s*)?true)')
              .hasMatch(release)) {
        out.add(inFile(g.path, lineOfFirst(g.text, RegExp(r'[dD]ebuggable\s*(=\s*)?true')),
            'The release build type is debuggable.',
            messageAr: 'الـ release build type قابل للـ debugging.'));
      }
    }
    return RuleCheck(out);
  }
}

class AllowBackupRule extends Rule {
  const AllowBackupRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-A02',
        title: Bilingual('App data can be backed up', 'بيانات التطبيق ممكن تتاخد backup'),
        description: Bilingual(
            'With backup allowed (the default) tokens and databases can be extracted through adb or cloud backups.',
            'لو الـ backup مسموح (وده الافتراضي)، الـ tokens وقواعد البيانات ممكن تتسحب عن طريق adb أو الـ cloud backup.'),
        fix: Bilingual(
            'Set android:allowBackup="false", or define android:dataExtractionRules / android:fullBackupContent that exclude sensitive files.',
            'حط android:allowBackup="false"، أو اعمل dataExtractionRules / fullBackupContent تستثني الملفات الحساسة.'),
        severity: Severity.medium,
        l2Severity: Severity.high,
        masvs: ['MASVS-STORAGE-2'],
        maswe: ['MASWE-0006'],
        cwe: 'CWE-530',
        profiles: _all,
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final m = project.androidManifest;
    final xml = project.androidManifestXml;
    if (m == null || xml == null) return RuleCheck.notApplicable();
    final app = firstElement(xml, 'application');
    if (app == null) return RuleCheck.notApplicable();
    final v = androidAttr(app, 'allowBackup');
    if (v == 'false') return RuleCheck([]);
    final hasRules = androidAttr(app, 'dataExtractionRules') != null ||
        androidAttr(app, 'fullBackupContent') != null;
    if (hasRules) return RuleCheck([]);
    if (v == 'true') {
      return RuleCheck([
        inFile(m.path, lineOfFirst(m.text, 'android:allowBackup'),
            'android:allowBackup="true" without backup rules.',
            messageAr: 'android:allowBackup="true" من غير قواعد backup.')
      ]);
    }
    return RuleCheck([
      inFile(m.path, lineOfFirst(m.text, '<application'),
          'android:allowBackup is not set, so backup is enabled by default.',
          messageAr: 'android:allowBackup مش متحدد، فالـ backup شغال افتراضياً.')
    ]);
  }
}

class CleartextManifestRule extends Rule {
  const CleartextManifestRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-A03',
        title: Bilingual('Cleartext HTTP traffic allowed (Android)', 'مسموح بـ HTTP غير مشفر (Android)'),
        description: Bilingual(
            'usesCleartextTraffic="true" lets the app send data over plain HTTP that anyone on the network can read or change.',
            'usesCleartextTraffic="true" بيخلي التطبيق يبعت بيانات على HTTP عادي، وأي حد على الشبكة يقدر يقراها أو يعدلها.'),
        fix: Bilingual(
            'Remove android:usesCleartextTraffic="true". If one dev host needs HTTP, allow only that domain in a network security config under debug-overrides.',
            'شيل android:usesCleartextTraffic="true". لو محتاج HTTP لسيرفر تطوير، اسمح بيه هو بس في network security config.'),
        severity: Severity.high,
        masvs: ['MASVS-NETWORK-1'],
        maswe: ['MASWE-0026'],
        cwe: 'CWE-319',
        profiles: _all,
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final m = project.androidManifest;
    final xml = project.androidManifestXml;
    if (m == null || xml == null) return RuleCheck.notApplicable();
    final app = firstElement(xml, 'application');
    if (app != null && androidAttr(app, 'usesCleartextTraffic') == 'true') {
      return RuleCheck([
        inFile(m.path, lineOfFirst(m.text, 'usesCleartextTraffic'),
            'android:usesCleartextTraffic="true" is set.',
            messageAr: 'android:usesCleartextTraffic="true" متحدد.')
      ]);
    }
    return RuleCheck([]);
  }
}

class NetworkSecurityConfigRule extends Rule {
  const NetworkSecurityConfigRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-A04',
        title: Bilingual('Weak network security config', 'إعدادات network security config ضعيفة'),
        description: Bilingual(
            'The network security config allows cleartext traffic or trusts user-installed CAs, which makes interception with a proxy trivial.',
            'الـ network security config بيسمح بـ HTTP أو بيثق في شهادات المستخدم، وده بيخلي اعتراض الترافيك بـ proxy سهل جداً.'),
        fix: Bilingual(
            'Set cleartextTrafficPermitted="false" and keep <certificates src="user"/> only inside <debug-overrides>.',
            'خلي cleartextTrafficPermitted="false"، وخلي <certificates src="user"/> جوه <debug-overrides> بس.'),
        severity: Severity.high,
        masvs: ['MASVS-NETWORK-1'],
        maswe: ['MASWE-0026', 'MASWE-0027'],
        cwe: 'CWE-295',
        profiles: _all,
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final f = project.networkSecurityConfig;
    final xml = project.networkSecurityConfigXml;
    if (f == null || xml == null) {
      return RuleCheck.notApplicable('No network security config');
    }
    final out = <Finding>[];
    for (final tag in const ['base-config', 'domain-config']) {
      for (final e in xml.findAllElements(tag)) {
        if (e.getAttribute('cleartextTrafficPermitted') == 'true') {
          out.add(inFile(f.path, lineOfFirst(f.text, 'cleartextTrafficPermitted="true"'),
              '<$tag cleartextTrafficPermitted="true"> allows HTTP.',
              messageAr: '<$tag cleartextTrafficPermitted="true"> بيسمح بـ HTTP.'));
        }
      }
    }
    for (final c in xml.findAllElements('certificates')) {
      if (c.getAttribute('src') != 'user') continue;
      final inDebug = c.ancestors
          .whereType<XmlElement>()
          .any((a) => a.name.local == 'debug-overrides');
      if (!inDebug) {
        out.add(inFile(f.path, lineOfFirst(f.text, RegExp(r'src\s*=\s*"user"')),
            'User-installed CA certificates are trusted in release builds.',
            messageAr: 'شهادات الـ CA اللي المستخدم بيثبتها موثوقة في الـ release.'));
      }
    }
    return RuleCheck(out);
  }
}

class PinExpirationRule extends Rule {
  const PinExpirationRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-A05',
        title: Bilingual('Certificate pins have expired', 'الـ certificate pins انتهت صلاحيتها'),
        description: Bilingual(
            'After the pin-set expiration date Android stops enforcing the pins, silently disabling pinning.',
            'بعد تاريخ الـ expiration، Android بيوقف تطبيق الـ pins، يعني الـ pinning بيتلغي من غير ما تحس.'),
        fix: Bilingual('Rotate the pins and move the expiration date forward.',
            'حدّث الـ pins وغيّر تاريخ الـ expiration.'),
        severity: Severity.medium,
        l2Severity: Severity.high,
        masvs: ['MASVS-NETWORK-2'],
        maswe: ['MASWE-0028'],
        cwe: 'CWE-295',
        profiles: _all,
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final f = project.networkSecurityConfig;
    final xml = project.networkSecurityConfigXml;
    if (f == null || xml == null) return RuleCheck.notApplicable();
    final sets = xml.findAllElements('pin-set').toList();
    if (sets.isEmpty) return RuleCheck.notApplicable('No pin-set');
    final now = DateTime.now();
    final out = <Finding>[];
    for (final s in sets) {
      final exp = s.getAttribute('expiration');
      if (exp == null) continue;
      final d = DateTime.tryParse(exp);
      if (d != null && d.isBefore(now)) {
        out.add(inFile(f.path, lineOfFirst(f.text, exp),
            'pin-set expired on $exp.', messageAr: 'الـ pin-set انتهى في $exp.'));
      }
    }
    return RuleCheck(out);
  }
}

class ExportedComponentRule extends Rule {
  const ExportedComponentRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-A06',
        title: Bilingual('Exported component without permission', 'مكوّن exported من غير permission'),
        description: Bilingual(
            'Any app on the device can start an exported activity, service, receiver or provider that has no permission.',
            'أي تطبيق على الجهاز يقدر يشغّل activity أو service أو receiver أو provider لو كان exported ومن غير permission.'),
        fix: Bilingual(
            'Set android:exported="false" unless the component must be public, and protect public ones with android:permission.',
            'خلي android:exported="false" إلا لو لازم يكون public، ولو public احميه بـ android:permission.'),
        severity: Severity.medium,
        masvs: ['MASVS-PLATFORM-1'],
        maswe: ['MASWE-0018'],
        cwe: 'CWE-926',
        profiles: _all,
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final m = project.androidManifest;
    final xml = project.androidManifestXml;
    if (m == null || xml == null) return RuleCheck.notApplicable();
    final out = <Finding>[];
    for (final tag in const ['activity', 'activity-alias', 'service', 'receiver', 'provider']) {
      for (final e in xml.findAllElements(tag)) {
        if (androidAttr(e, 'exported') != 'true') continue;
        if (androidAttr(e, 'permission') != null) continue;
        if (_isLauncher(e)) continue;
        final name = androidAttr(e, 'name') ?? tag;
        out.add(inFile(m.path, lineOfFirst(m.text, name),
            '<$tag $name> is exported without android:permission.',
            messageAr: '<$tag $name> متعمله export من غير android:permission.'));
      }
    }
    return RuleCheck(out);
  }

  bool _isLauncher(XmlElement e) {
    for (final f in e.findElements('intent-filter')) {
      final actions = f.findElements('action').map((a) => androidAttr(a, 'name'));
      final cats = f.findElements('category').map((a) => androidAttr(a, 'name'));
      if (actions.contains('android.intent.action.MAIN') &&
          cats.contains('android.intent.category.LAUNCHER')) {
        return true;
      }
      // App links / deep links are meant to be exported; validated elsewhere.
      if (actions.contains('android.intent.action.VIEW')) return true;
    }
    return false;
  }
}

class MinifyDisabledRule extends Rule {
  const MinifyDisabledRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-A07',
        title: Bilingual('R8 shrinking/obfuscation disabled', 'الـ R8 (shrinking/obfuscation) مقفول'),
        description: Bilingual(
            'Flutter enables R8 for release builds by default; turning it off leaves the Java/Kotlin code of every plugin readable.',
            'Flutter بيشغّل R8 في الـ release افتراضياً، ولو قفلته كود Java/Kotlin بتاع كل الـ plugins هيبقى مقروء.'),
        fix: Bilingual('Remove minifyEnabled false / isMinifyEnabled = false from the release build type.',
            'شيل minifyEnabled false أو isMinifyEnabled = false من الـ release.'),
        severity: Severity.low,
        l2Severity: Severity.medium,
        masvs: ['MASVS-RESILIENCE-3'],
        maswe: ['MASWE-0059'],
        cwe: 'CWE-656',
        profiles: _all,
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final g = project.appGradle;
    if (g == null) return RuleCheck.notApplicable('No app build.gradle');
    final release = _releaseBlock(g.text);
    if (release == null) return RuleCheck([]);
    final re = RegExp(r'(isMinifyEnabled\s*=\s*false|minifyEnabled\s*(=\s*)?false)');
    if (re.hasMatch(release)) {
      return RuleCheck([
        inFile(g.path, lineOfFirst(g.text, re),
            'The release build type disables R8 (minifyEnabled false).',
            messageAr: 'الـ release مقفول فيه R8 (minifyEnabled false).')
      ]);
    }
    return RuleCheck([]);
  }
}

class DebugSigningRule extends Rule {
  const DebugSigningRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-A08',
        title: Bilingual('Release build signed with the debug key', 'نسخة الـ release متوقعة بمفتاح الـ debug'),
        description: Bilingual(
            'The Flutter template signs release builds with the public debug key. Anyone can re-sign a modified copy, and signature checks become meaningless.',
            'قالب Flutter بيوقّع الـ release بمفتاح الـ debug المعروف. أي حد يقدر يعدّل التطبيق ويوقعه تاني، وفحص التوقيع ملوش لازمة.'),
        fix: Bilingual(
            'Create a release keystore, load it from key.properties (git-ignored) and set signingConfig = signingConfigs.getByName("release").',
            'اعمل release keystore، واقراه من key.properties (يكون في .gitignore)، وخلي signingConfig = signingConfigs.getByName("release").'),
        severity: Severity.high,
        masvs: ['MASVS-RESILIENCE-2'],
        cwe: 'CWE-321',
        profiles: _all,
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final g = project.appGradle;
    if (g == null) return RuleCheck.notApplicable('No app build.gradle');
    final release = _releaseBlock(g.text);
    if (release == null) return RuleCheck([]);
    final re = RegExp(
        r'''signingConfig\s*(=\s*)?signingConfigs\s*(\.\s*debug\b|\.\s*getByName\s*\(\s*["']debug["']\s*\))''');
    if (re.hasMatch(release)) {
      return RuleCheck([
        inFile(g.path, lineOfFirst(g.text, re),
            'release uses signingConfigs.debug.',
            messageAr: 'الـ release مستخدم signingConfigs.debug.')
      ]);
    }
    return RuleCheck([]);
  }
}

class SigningSecretsRule extends Rule {
  const SigningSecretsRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-A09',
        title: Bilingual('Signing secrets exposed', 'أسرار التوقيع مكشوفة'),
        description: Bilingual(
            'Keystore passwords in build.gradle, or keystores / key.properties that are not git-ignored, let anyone sign builds as you.',
            'باسوردات الـ keystore في build.gradle، أو ملفات keystore و key.properties مش متضافة لـ .gitignore، بتخلي أي حد يوقّع تطبيقات باسمك.'),
        fix: Bilingual(
            'Read passwords from key.properties or environment variables, and add key.properties, *.jks and *.keystore to .gitignore.',
            'اقرا الباسوردات من key.properties أو environment variables، وضيف key.properties و *.jks و *.keystore لـ .gitignore.'),
        severity: Severity.high,
        masvs: ['MASVS-STORAGE-1'],
        maswe: ['MASWE-0004'],
        cwe: 'CWE-798',
        profiles: _all,
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    if (!project.hasAndroid) return RuleCheck.notApplicable();
    final out = <Finding>[];
    final g = project.appGradle;
    if (g != null) {
      final re = RegExp(
          r'''(?<![\['"])\b(storePassword|keyPassword)\s*(=\s*)?["']([^"'$\n\[\]]{3,})["']''');
      for (final m in re.allMatches(stripCComments(g.text))) {
        out.add(inFile(g.path, lineAt(g.text, m.start),
            '${m.group(1)} is hardcoded in ${g.path}.',
            messageAr: '${m.group(1)} مكتوب في ${g.path}.',
            snippet: '${m.group(1)} = ${redact(m.group(3)!)}'));
      }
    }
    final files = project.findFiles('android', (r) =>
        r.endsWith('.jks') ||
        r.endsWith('.keystore') ||
        r.endsWith('/key.properties'));
    for (final f in files) {
      if (f.endsWith('debug.keystore')) continue;
      if (!project.isGitIgnored(f)) {
        out.add(inFile(f, null, '$f is not in .gitignore and may be committed.',
            messageAr: '$f مش موجود في .gitignore وممكن يكون اترفع على git.'));
      }
    }
    return RuleCheck(out);
  }
}

class MinSdkRule extends Rule {
  const MinSdkRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-A10',
        title: Bilingual('Very old Android versions supported', 'التطبيق بيدعم إصدارات Android قديمة جداً'),
        description: Bilingual(
            'Android versions below 7.0 (API 24) miss important security fixes, such as distrusting user CAs by default.',
            'إصدارات Android أقل من 7.0 (API 24) ناقصها إصلاحات أمنية مهمة، زي عدم الثقة في شهادات المستخدم افتراضياً.'),
        fix: Bilingual('Raise minSdk to 24 or higher.', 'ارفع الـ minSdk لـ 24 أو أكتر.'),
        severity: Severity.low,
        l2Severity: Severity.medium,
        masvs: ['MASVS-CODE-1'],
        maswe: ['MASWE-0041'],
        cwe: 'CWE-1104',
        profiles: _all,
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final g = project.appGradle;
    if (g == null) return RuleCheck.notApplicable();
    final re = RegExp(r'minSdk(Version)?\s*(=\s*)?(\d+)');
    final m = re.firstMatch(stripCComments(g.text));
    if (m == null) {
      return RuleCheck.notApplicable('minSdk comes from flutter.minSdkVersion');
    }
    final v = int.parse(m.group(3)!);
    if (v < 24) {
      return RuleCheck([
        inFile(g.path, lineOfFirst(g.text, re), 'minSdk is $v.',
            messageAr: 'الـ minSdk = $v.')
      ]);
    }
    return RuleCheck([]);
  }
}

const androidRules = <Rule>[
  DebuggableRule(),
  AllowBackupRule(),
  CleartextManifestRule(),
  NetworkSecurityConfigRule(),
  PinExpirationRule(),
  ExportedComponentRule(),
  MinifyDisabledRule(),
  DebugSigningRule(),
  SigningSecretsRule(),
  MinSdkRule(),
];
