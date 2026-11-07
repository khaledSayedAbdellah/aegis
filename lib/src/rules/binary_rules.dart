/// Rules that inspect the compiled APK.
///
/// They focus on what the source cannot show: values injected at build time,
/// manifest entries merged from plugins, whether obfuscation really happened,
/// and which certificate actually signed the app. When the source project is
/// also available, problems that a source rule already reports are skipped so
/// nothing is counted twice.
library;

import 'dart:convert';

import 'package:xml/xml.dart';

import '../binary/apk.dart';
import '../model.dart';
import '../project.dart';
import '../util.dart';
import 'android_rules.dart';
import 'dart_rules.dart';
import 'protection_rules.dart' show findCalls;
import 'rule.dart';

const _all = {MasProfile.l1, MasProfile.l2, MasProfile.r};

/// Whether [rule] already reports a problem in the source project, so the
/// binary rule should not report it again.
Future<bool> reportedBySource(Rule rule, Project p, ProfileSet profile) async {
  if (!p.hasSource) return false;
  if (p.config.disabledRules.contains(rule.meta.id)) return true;
  try {
    final c = await rule.check(p, profile);
    return c.applicable && c.findings.isNotEmpty;
  } catch (_) {
    return false;
  }
}

RuleCheck? _requireApk(Project p, {bool flutter = false}) {
  final apk = p.apk;
  if (apk == null) return RuleCheck.notApplicable('No APK given (--apk)');
  if (apk.manifest == null) {
    return RuleCheck.notApplicable('Could not decode AndroidManifest.xml');
  }
  if (flutter && !apk.isFlutter) {
    return RuleCheck.notApplicable('Not a Flutter APK');
  }
  return null;
}

String _notInSource(Project p, String en) => p.hasSource ? ' $en' : '';

// ---------------------------------------------------------------------------

class DebugBuildRule extends Rule {
  const DebugBuildRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-B01',
        title: Bilingual('A debug (JIT) Flutter build was shipped', 'نسخة Flutter debug (JIT) هي اللي اتبنت'),
        description: Bilingual(
            'Debug builds contain kernel_blob.bin, the whole Dart program in an easy-to-decompile form with all names, and run with debugging services enabled.',
            'نسخ الـ debug فيها kernel_blob.bin، وده برنامج Dart كله بصيغة سهل تتفك وبكل الأسماء، وكمان خدمات الـ debugging بتبقى شغالة.'),
        fix: Bilingual('Distribute only builds made with flutter build apk --release (or appbundle).',
            'متوزعش غير النسخ اللي اتعملت بـ flutter build apk --release أو appbundle.'),
        severity: Severity.critical,
        masvs: ['MASVS-RESILIENCE-4', 'MASVS-RESILIENCE-3'],
        maswe: ['MASWE-0061'],
        cwe: 'CWE-489',
        profiles: _all,
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final missing = _requireApk(project, flutter: true);
    if (missing != null) return missing;
    final apk = project.apk!;
    if (!apk.isDebugFlutterBuild) return RuleCheck([]);
    return RuleCheck([
      inFile(apk.location('assets/flutter_assets/kernel_blob.bin'), null,
          'kernel_blob.bin is present: this is a debug build, not a release build.',
          messageAr: 'kernel_blob.bin موجود: دي نسخة debug مش release.')
    ]);
  }
}

class BinaryDebuggableRule extends Rule {
  const BinaryDebuggableRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-B02',
        title: Bilingual('The APK is debuggable', 'الـ APK قابل للـ debugging'),
        description: Bilingual(
            'The final manifest inside the APK has android:debuggable="true", so anyone can attach a debugger to the installed app.',
            'الـ manifest النهائي جوه الـ APK فيه android:debuggable="true"، يعني أي حد يقدر يوصل debugger بالتطبيق بعد ما يتثبت.'),
        fix: Bilingual(
            'Find what sets it (a build type, flavor or library manifest) and remove it from release builds.',
            'دوّر على اللي بيحطه (build type أو flavor أو manifest بتاع مكتبة) وشيله من الـ release.'),
        severity: Severity.critical,
        masvs: ['MASVS-RESILIENCE-4'],
        maswe: ['MASWE-0063'],
        cwe: 'CWE-489',
        profiles: _all,
      );

  @override
  Future<RuleCheck> check(Project project, ProfileSet profile) async {
    final missing = _requireApk(project);
    if (missing != null) return missing;
    final apk = project.apk!;
    final app = apk.application;
    if (app == null || androidAttr(app, 'debuggable') != 'true') return RuleCheck([]);
    if (await reportedBySource(const DebuggableRule(), project, profile)) {
      return RuleCheck.notApplicable('Already reported by AEG-A01');
    }
    return RuleCheck([
      inFile(apk.location('AndroidManifest.xml'), null,
          'android:debuggable="true" in the final manifest.${_notInSource(project, 'It is not in your source manifest, so the build configuration or a library adds it.')}',
          messageAr: 'android:debuggable="true" موجود في الـ manifest النهائي.${project.hasSource ? ' ومش موجود في الـ manifest بتاعك، يعني إعدادات البيلد أو مكتبة هي اللي ضافته.' : ''}')
    ]);
  }
}

class BinaryManifestNetworkRule extends Rule {
  const BinaryManifestNetworkRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-B03',
        title: Bilingual('Final manifest weakens backup or network security', 'الـ manifest النهائي بيضعّف الـ backup أو أمان الشبكة'),
        description: Bilingual(
            'Libraries can merge attributes such as usesCleartextTraffic or allowBackup into your manifest, and a network security config from a library can relax TLS rules. What ships is the merged result.',
            'المكتبات ممكن تضيف attributes زي usesCleartextTraffic أو allowBackup للـ manifest، وممكن network security config من مكتبة يخفف قواعد الـ TLS. واللي بيتشحن هو النتيجة النهائية بعد الدمج.'),
        fix: Bilingual(
            'Override the merged value in your manifest with tools:replace (for example tools:replace="android:usesCleartextTraffic") and set the safe value.',
            'اعمل override للقيمة في الـ manifest بتاعك بـ tools:replace (مثلاً tools:replace="android:usesCleartextTraffic") وحط القيمة الآمنة.'),
        severity: Severity.high,
        masvs: ['MASVS-NETWORK-1', 'MASVS-STORAGE-2'],
        maswe: ['MASWE-0026', 'MASWE-0006'],
        cwe: 'CWE-319',
        profiles: _all,
      );

  @override
  Future<RuleCheck> check(Project project, ProfileSet profile) async {
    final missing = _requireApk(project);
    if (missing != null) return missing;
    final apk = project.apk!;
    final app = apk.application;
    final out = <Finding>[];
    final manifestLoc = apk.location('AndroidManifest.xml');
    final suffix = _notInSource(project, 'Your source manifest does not set this, so a library or build variant does.');
    final suffixAr = project.hasSource ? ' والـ manifest بتاعك مش فيه كده، يعني مكتبة أو build variant هي السبب.' : '';

    if (app != null) {
      final backup = androidAttr(app, 'allowBackup');
      final hasRules = androidAttr(app, 'dataExtractionRules') != null ||
          androidAttr(app, 'fullBackupContent') != null;
      if (backup != 'false' &&
          !hasRules &&
          !await reportedBySource(const AllowBackupRule(), project, profile)) {
        out.add(inFile(manifestLoc, null,
            'Backup is enabled in the final manifest (allowBackup=${backup ?? 'default true'}).$suffix',
            messageAr: 'الـ backup شغال في الـ manifest النهائي (allowBackup=${backup ?? 'true افتراضياً'}).$suffixAr'));
      }
      if (androidAttr(app, 'usesCleartextTraffic') == 'true' &&
          !await reportedBySource(const CleartextManifestRule(), project, profile)) {
        out.add(inFile(manifestLoc, null,
            'usesCleartextTraffic="true" in the final manifest.$suffix',
            messageAr: 'usesCleartextTraffic="true" في الـ manifest النهائي.$suffixAr'));
      }
    }

    final nsc = apk.networkSecurityConfig;
    if (nsc != null &&
        !await reportedBySource(const NetworkSecurityConfigRule(), project, profile)) {
      final (entry, doc) = nsc;
      final loc = apk.location(entry);
      for (final tag in const ['base-config', 'domain-config']) {
        for (final e in doc.findAllElements(tag)) {
          if (e.getAttribute('cleartextTrafficPermitted') == 'true') {
            out.add(inFile(loc, null, '<$tag cleartextTrafficPermitted="true"> in the shipped network security config.',
                messageAr: '<$tag cleartextTrafficPermitted="true"> في الـ network security config اللي اتشحن.'));
          }
        }
      }
      for (final c in doc.findAllElements('certificates')) {
        if (c.getAttribute('src') != 'user') continue;
        final inDebug = c.ancestors.whereType<XmlElement>().any((a) => a.name.local == 'debug-overrides');
        if (!inDebug) {
          out.add(inFile(loc, null, 'The shipped network security config trusts user-installed CAs.',
              messageAr: 'الـ network security config اللي اتشحن بيثق في شهادات المستخدم.'));
        }
      }
    }
    return RuleCheck(out);
  }
}

bool _isLauncherOrLink(XmlElement e) {
  for (final f in e.findElements('intent-filter')) {
    final actions = f.findElements('action').map((a) => androidAttr(a, 'name'));
    final cats = f.findElements('category').map((a) => androidAttr(a, 'name'));
    if (actions.contains('android.intent.action.MAIN') &&
        cats.contains('android.intent.category.LAUNCHER')) {
      return true;
    }
    if (actions.contains('android.intent.action.VIEW')) return true;
  }
  return false;
}

bool _declaredInSource(String binaryName, Set<String> sourceNames) {
  for (final s in sourceNames) {
    if (s == binaryName) return true;
    if (s.startsWith('.') && binaryName.endsWith(s)) return true;
    if (!s.contains('.') && binaryName.endsWith('.$s')) return true;
  }
  return false;
}

class PluginExportedComponentRule extends Rule {
  const PluginExportedComponentRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-B04',
        title: Bilingual('Library adds an exported component without permission', 'مكتبة بتضيف مكوّن exported من غير permission'),
        description: Bilingual(
            'Plugins merge their own activities, services, receivers and providers into your app. An exported one without a permission can be started by any app on the device.',
            'الـ plugins بتضيف activities و services و receivers و providers بتاعتها لتطبيقك. ولو واحد منهم exported من غير permission، أي تطبيق على الجهاز يقدر يشغّله.'),
        fix: Bilingual(
            'Check whether the component must be public. If not, override it in your manifest with android:exported="false" and tools:replace="android:exported", or update the plugin.',
            'اتأكد إن المكوّن لازم يكون public. لو لأ، اعمله override في الـ manifest بتاعك بـ android:exported="false" و tools:replace="android:exported"، أو حدّث الـ plugin.'),
        severity: Severity.medium,
        masvs: ['MASVS-PLATFORM-1'],
        maswe: ['MASWE-0018'],
        cwe: 'CWE-926',
        profiles: _all,
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final missing = _requireApk(project);
    if (missing != null) return missing;
    final apk = project.apk!;
    final sourceNames = <String>{};
    final src = project.androidManifestXml;
    if (src != null) {
      for (final tag in const ['activity', 'activity-alias', 'service', 'receiver', 'provider']) {
        for (final e in src.findAllElements(tag)) {
          final n = androidAttr(e, 'name');
          if (n != null) sourceNames.add(n);
        }
      }
    }
    final out = <Finding>[];
    for (final tag in const ['activity', 'activity-alias', 'service', 'receiver', 'provider']) {
      for (final e in apk.manifest!.findAllElements(tag)) {
        if (androidAttr(e, 'exported') != 'true') continue;
        if (androidAttr(e, 'permission') != null) continue;
        if (tag == 'provider' &&
            (androidAttr(e, 'readPermission') != null || androidAttr(e, 'writePermission') != null)) {
          continue;
        }
        if (_isLauncherOrLink(e)) continue;
        final name = androidAttr(e, 'name') ?? tag;
        if (project.hasSource && _declaredInSource(name, sourceNames)) continue;
        out.add(inFile(apk.location('AndroidManifest.xml'), null,
            '<$tag $name> is exported without a permission${project.hasSource ? ' (added by a library)' : ''}.',
            messageAr: '<$tag $name> متعمله export من غير permission${project.hasSource ? ' (ضافته مكتبة)' : ''}.'));
      }
    }
    return RuleCheck(out);
  }
}

const sensitivePermissions = {
  'android.permission.READ_SMS',
  'android.permission.RECEIVE_SMS',
  'android.permission.SEND_SMS',
  'android.permission.READ_CALL_LOG',
  'android.permission.WRITE_CALL_LOG',
  'android.permission.PROCESS_OUTGOING_CALLS',
  'android.permission.READ_CONTACTS',
  'android.permission.WRITE_CONTACTS',
  'android.permission.GET_ACCOUNTS',
  'android.permission.ACCESS_FINE_LOCATION',
  'android.permission.ACCESS_BACKGROUND_LOCATION',
  'android.permission.RECORD_AUDIO',
  'android.permission.CAMERA',
  'android.permission.READ_PHONE_STATE',
  'android.permission.READ_PHONE_NUMBERS',
  'android.permission.BODY_SENSORS',
  'android.permission.ACTIVITY_RECOGNITION',
  'android.permission.READ_EXTERNAL_STORAGE',
  'android.permission.WRITE_EXTERNAL_STORAGE',
  'android.permission.MANAGE_EXTERNAL_STORAGE',
  'android.permission.READ_MEDIA_IMAGES',
  'android.permission.READ_MEDIA_VIDEO',
  'android.permission.QUERY_ALL_PACKAGES',
  'android.permission.REQUEST_INSTALL_PACKAGES',
  'android.permission.SYSTEM_ALERT_WINDOW',
  'android.permission.USE_FULL_SCREEN_INTENT',
  'android.permission.SCHEDULE_EXACT_ALARM',
  'android.permission.BIND_ACCESSIBILITY_SERVICE',
};

class PluginPermissionsRule extends Rule {
  const PluginPermissionsRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-B05',
        title: Bilingual('Sensitive permissions added by libraries', 'صلاحيات حساسة ضافتها مكتبات'),
        description: Bilingual(
            'Plugins can merge permissions you never asked for. Each sensitive permission widens what an attacker gets if the app is compromised, and Google Play may reject or restrict apps that request them without a reason.',
            'الـ plugins ممكن تضيف صلاحيات انت مطلبتهاش. كل صلاحية حساسة بتوسّع اللي المهاجم ياخده لو التطبيق اتخترق، وكمان Google Play ممكن يرفض أو يقيّد التطبيق لو طالبها من غير سبب.'),
        fix: Bilingual(
            'Remove unneeded permissions in your manifest with <uses-permission android:name="..." tools:node="remove"/>.',
            'شيل الصلاحيات اللي مش محتاجها من الـ manifest بتاعك بـ <uses-permission android:name="..." tools:node="remove"/>.'),
        severity: Severity.low,
        l2Severity: Severity.medium,
        masvs: ['MASVS-PRIVACY-1'],
        maswe: ['MASWE-0066'],
        cwe: 'CWE-250',
        profiles: _all,
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final missing = _requireApk(project);
    if (missing != null) return missing;
    final apk = project.apk!;
    final declared = <String>{};
    final src = project.androidManifestXml;
    if (src != null) {
      for (final tag in const ['uses-permission', 'uses-permission-sdk-23']) {
        for (final e in src.findAllElements(tag)) {
          final n = androidAttr(e, 'name');
          if (n != null) declared.add(n);
        }
      }
    }
    final added = <String>{};
    for (final tag in const ['uses-permission', 'uses-permission-sdk-23']) {
      for (final e in apk.manifest!.findAllElements(tag)) {
        final n = androidAttr(e, 'name');
        if (n == null || !sensitivePermissions.contains(n)) continue;
        if (androidAttr(e, 'maxSdkVersion') != null) continue;
        if (project.hasSource && declared.contains(n)) continue;
        added.add(n);
      }
    }
    if (added.isEmpty) return RuleCheck([]);
    final list = (added.toList()..sort()).map((n) => n.replaceFirst('android.permission.', '')).join(', ');
    return RuleCheck([
      inFile(apk.location('AndroidManifest.xml'), null,
          project.hasSource
              ? 'Added by libraries, not in your manifest: $list.'
              : 'Sensitive permissions requested: $list.',
          messageAr: project.hasSource
              ? 'ضافتها مكتبات ومش موجودة في الـ manifest بتاعك: $list.'
              : 'صلاحيات حساسة مطلوبة: $list.')
    ]);
  }
}

const _textAssetExt = {
  'json', 'env', 'txt', 'yaml', 'yml', 'xml', 'properties', 'js', 'html', 'cfg', 'ini', 'conf', 'plist',
};

class BinarySecretsRule extends Rule {
  const BinarySecretsRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-B06',
        title: Bilingual('Secret inside the APK', 'سر (secret) جوه الـ APK'),
        description: Bilingual(
            'Values passed with --dart-define, --dart-define-from-file or generated by tools such as envied are compiled into libapp.so as plain strings. They never appear in your source, so source scanners miss them, but `strings` on the APK reveals them.',
            'القيم اللي بتتبعت بـ --dart-define أو --dart-define-from-file أو اللي بتعملها أدوات زي envied، بتتحط في libapp.so كـ strings عادية. مش بتظهر في السورس فأدوات فحص السورس مش بتشوفها، لكن أمر strings على الـ APK بيطلعها.'),
        fix: Bilingual(
            'Do not ship secret keys in the app at all. Call your backend, which holds the key, or use short-lived tokens issued per user.',
            'متحطش مفاتيح سرية في التطبيق خالص. خلي التطبيق ينادي الـ backend اللي معاه المفتاح، أو استخدم tokens قصيرة العمر لكل مستخدم.'),
        severity: Severity.high,
        masvs: ['MASVS-STORAGE-1'],
        maswe: ['MASWE-0004'],
        cwe: 'CWE-798',
        profiles: _all,
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final missing = _requireApk(project);
    if (missing != null) return missing;
    final apk = project.apk!;
    final patterns = [
      for (final pat in knownSecretPatterns)
        if (pat.name != 'Google API key') (pat.name, RegExp(pat.re)),
    ];
    final sourceText = project.dartFiles.map((f) => f.source).join('\n');
    final reported = <String>{};
    final out = <Finding>[];

    void scan(String entry, List<String> strings, String kind) {
      for (var i = 0; i < strings.length; i++) {
        final s = strings[i];
        for (final (name, re) in patterns) {
          for (final m in re.allMatches(s)) {
            // In a binary the PEM lines are separate strings: the key data, if
            // any, is in the next one.
            if (name == 'Private key' &&
                !pemBodyFollows(s, m.end, next: i + 1 < strings.length ? strings[i + 1] : null)) {
              continue;
            }
            _report(project, apk, entry, kind, name, m.group(0)!, sourceText, reported, out);
          }
        }
        if (s.contains('eyJ')) {
          for (final m in RegExp(r'eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}').allMatches(s)) {
            if (jwtRole(m.group(0)!) == 'service_role') {
              _report(project, apk, entry, kind, 'Supabase service_role key', m.group(0)!, sourceText, reported, out);
            }
          }
        }
      }
    }

    final libapp = apk.libappEntry;
    if (libapp != null) scan(libapp, apk.libappStrings, 'dart');
    for (final e in apk.zip.entries.values) {
      final n = e.name;
      final resources = n == 'resources.arsc' || n == 'resources.pb';
      if (RegExp(r'(^|/)classes\d*\.dex$').hasMatch(n) || resources) {
        final bytes = apk.zip.readEntry(e);
        scan(n, printableStrings(bytes, min: 8), resources ? 'resources' : 'dex');
      } else if (n.startsWith('assets/') && e.size < 2 * 1024 * 1024) {
        final base = n.split('/').last.toLowerCase();
        final ext = base.contains('.') ? base.split('.').last : '';
        if (_textAssetExt.contains(ext) || base.startsWith('.env')) {
          final text = latin1.decode(apk.zip.readEntry(e), allowInvalid: true);
          scan(n, [text], 'asset');
        }
      }
    }
    return RuleCheck(out);
  }

  void _report(Project project, ApkContext apk, String entry, String kind, String name,
      String value, String sourceText, Set<String> reported, List<Finding> out) {
    if (!reported.add(value)) return;
    if (project.hasSource && sourceText.contains(value)) return; // AEG-D01 reports it
    final String where;
    final String whereAr;
    switch (kind) {
      case 'dart':
        where = project.hasSource
            ? 'in the compiled Dart code but not in your Dart source: it was injected at build time (--dart-define, --dart-define-from-file or a generator such as envied)'
            : 'in the compiled Dart code (libapp.so)';
        whereAr = project.hasSource
            ? 'في كود Dart المتكمبل ومش في السورس: يعني اتحط وقت البيلد (--dart-define أو --dart-define-from-file أو أداة زي envied)'
            : 'في كود Dart المتكمبل (libapp.so)';
      case 'dex':
        where = 'in $entry (Java/Kotlin code, BuildConfig or a native SDK)';
        whereAr = 'في $entry (كود Java/Kotlin أو BuildConfig أو SDK native)';
      case 'resources':
        where = 'in $entry (string resources or resValue)';
        whereAr = 'في $entry (string resources أو resValue)';
      default:
        where = 'in the bundled file $entry';
        whereAr = 'في الملف المتضاف $entry';
    }
    out.add(inFile(apk.location(entry), null, '$name found $where.',
        messageAr: 'لقيت $name $whereAr.', snippet: redact(value)));
  }
}

/// Private Flutter framework classes present in any MaterialApp. Their names
/// survive in libapp.so unless the build used --obfuscate.
const _frameworkClassNames = {
  '_MaterialAppState',
  '_WidgetsAppState',
  '_NavigatorState',
  '_OverlayState',
  '_ModalScopeState',
  '_FocusInheritedScope',
  '_RenderTheater',
  '_TheaterParentData',
  '_ScaffoldState',
  '_InkResponseState',
  '_RootRestorationScopeState',
  '_SharedAppDataState',
};

class ObfuscationAppliedRule extends Rule {
  const ObfuscationAppliedRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-B07',
        title: Bilingual('The shipped Dart code is not obfuscated', 'كود Dart اللي اتشحن مش متعمله obfuscation'),
        description: Bilingual(
            'Readable class names in libapp.so mean the release was built without --obfuscate, so tools like blutter recover a readable map of your code, including your security checks.',
            'وجود أسماء كلاسات مقروءة في libapp.so معناه إن الـ release اتبنى من غير --obfuscate، فأدوات زي blutter بتطلع خريطة مقروءة للكود بتاعك، ومنها فحوصات الأمان.'),
        fix: Bilingual(
            'Build with flutter build apk --release --obfuscate --split-debug-info=build/symbols and keep the symbols for crash reports.',
            'اعمل البيلد بـ flutter build apk --release --obfuscate --split-debug-info=build/symbols، واحتفظ بالـ symbols عشان تقرا تقارير الـ crash.'),
        severity: Severity.low,
        l2Severity: Severity.medium,
        masvs: ['MASVS-RESILIENCE-3'],
        maswe: ['MASWE-0059'],
        cwe: 'CWE-656',
        profiles: _all,
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final missing = _requireApk(project, flutter: true);
    if (missing != null) return missing;
    final apk = project.apk!;
    if (apk.isDebugFlutterBuild) return RuleCheck.notApplicable('Debug build (see AEG-B01)');
    if (apk.libappEntry == null) return RuleCheck.notApplicable('No libapp.so in the APK');

    final ident = RegExp(r'[A-Za-z_$][A-Za-z0-9_$]{5,}');
    final tokens = <String>{};
    for (final s in apk.libappStrings) {
      for (final m in ident.allMatches(s)) {
        tokens.add(m.group(0)!);
      }
    }
    final frameworkHits = _frameworkClassNames.where(tokens.contains).toList()..sort();

    final own = <String>{};
    for (final f in project.dartFiles) {
      for (var i = 0; i + 1 < f.tokens.length; i++) {
        final t = f.tokens[i];
        final n = f.tokens[i + 1];
        if (t.isIdent && t.text == 'class' && n.isIdent && n.text.length >= 8) {
          own.add(n.text);
        }
      }
    }
    final ownHits = own.where(tokens.contains).toList()..sort();
    final ownRatio = own.isEmpty ? 0.0 : ownHits.length / own.length;

    // A real non-obfuscated build keeps nearly all of these names. A name or
    // two can survive obfuscation (entry points, names used as strings in
    // routes or logs), so isolated hits do not count against the build.
    final readable = frameworkHits.length >= 3 || (own.length >= 5 && ownRatio >= 0.3);
    final obfuscated = frameworkHits.length <= 1 && (own.length < 5 || ownRatio < 0.1);
    if (readable) {
      final examples = [...frameworkHits.take(3), ...ownHits.take(3)].join(', ');
      return RuleCheck([
        inFile(apk.location(apk.libappEntry!), null,
            'Readable class names in libapp.so ($examples${ownHits.isEmpty ? '' : '; ${ownHits.length} of your ${own.length} classes'}).',
            messageAr: 'فيه أسماء كلاسات مقروءة في libapp.so ($examples${ownHits.isEmpty ? '' : '؛ ${ownHits.length} من ${own.length} كلاس بتوعك'}).')
      ]);
    }
    if (obfuscated) return RuleCheck([]);
    return RuleCheck.notApplicable(
        'Inconclusive: ${frameworkHits.length} framework and ${ownHits.length} own class names found');
  }
}

class BundledSecretFilesRule extends Rule {
  const BundledSecretFilesRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-B08',
        title: Bilingual('Secret file shipped inside the APK', 'ملف أسرار جوه الـ APK'),
        description: Bilingual(
            'Files under flutter_assets are stored as-is. A .env, private key or service-account file in the APK can be extracted by unzipping it.',
            'الملفات اللي جوه flutter_assets بتتخزن زي ما هي. أي ملف .env أو private key أو service-account جوه الـ APK ممكن يتطلع بمجرد فك الضغط.'),
        fix: Bilingual('Remove the file from the assets and keep secrets on the server.',
            'شيل الملف من الـ assets وخلي الأسرار على السيرفر.'),
        severity: Severity.high,
        masvs: ['MASVS-STORAGE-1'],
        maswe: ['MASWE-0004'],
        cwe: 'CWE-540',
        profiles: _all,
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final missing = _requireApk(project, flutter: true);
    if (missing != null) return missing;
    final apk = project.apk!;
    final sourceReported = project.hasSource
        ? riskyAssetPaths(project).map((e) => e.$1).toSet()
        : const <String>{};
    final out = <Finding>[];
    for (final entry in apk.flutterAssets) {
      final rel = entry.substring('assets/flutter_assets/'.length);
      if (!riskyAssetFile.hasMatch(rel)) continue;
      if (sourceReported.contains(rel)) continue; // AEG-D09 reports it
      out.add(inFile(apk.location(entry), null, '$rel is inside the APK.',
          messageAr: '$rel موجود جوه الـ APK.'));
    }
    return RuleCheck(out);
  }
}

class DebugCertificateRule extends Rule {
  const DebugCertificateRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-B09',
        title: Bilingual('APK signed with the Android debug certificate', 'الـ APK متوقع بشهادة Android Debug'),
        description: Bilingual(
            'The debug keystore is shared by every developer machine. Anyone can sign a modified copy with the same certificate, and stores reject debug-signed apps.',
            'الـ debug keystore موجود على أي جهاز مطور. أي حد يقدر يوقّع نسخة معدّلة بنفس الشهادة، والمتاجر بترفض التطبيقات المتوقعة بيه.'),
        fix: Bilingual('Sign release builds with your own release/upload keystore.',
            'وقّع نسخ الـ release بالـ keystore بتاعك (release أو upload).'),
        severity: Severity.high,
        masvs: ['MASVS-RESILIENCE-2'],
        cwe: 'CWE-321',
        profiles: _all,
      );

  @override
  Future<RuleCheck> check(Project project, ProfileSet profile) async {
    final missing = _requireApk(project);
    if (missing != null) return missing;
    final apk = project.apk!;
    if (apk.certificates.isEmpty) return RuleCheck.notApplicable('The APK is not signed');
    final debug = apk.certificates.where((c) => c.isAndroidDebug).toList();
    if (debug.isEmpty) return RuleCheck([]);
    if (await reportedBySource(const DebugSigningRule(), project, profile)) {
      return RuleCheck.notApplicable('Already reported by AEG-A08');
    }
    return RuleCheck([
      inFile(apk.location('META-INF'), null,
          'Signed with CN=Android Debug (${debug.first.scheme}).',
          messageAr: 'متوقع بشهادة CN=Android Debug (${debug.first.scheme}).')
    ]);
  }
}

class RaspSigningHashRule extends Rule {
  const RaspSigningHashRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-B10',
        title: Bilingual('freeRASP does not know this APK\'s certificate', 'freeRASP مش عارف شهادة الـ APK ده'),
        description: Bilingual(
            'freeRASP compares the running app\'s signing certificate with signingCertHashes. If the certificate that signed this APK is missing, every install of it triggers onAppIntegrity, and if your reaction blocks the app, real users are locked out.',
            'freeRASP بيقارن شهادة التوقيع بتاعة التطبيق بالـ signingCertHashes. لو الشهادة اللي وقّعت الـ APK ده مش موجودة، كل تثبيت ليه هيشغّل onAppIntegrity، ولو رد الفعل بيقفل التطبيق، المستخدمين الحقيقيين هيتقفل عليهم.'),
        fix: Bilingual(
            'Add the Base64 SHA-256 shown in the finding to signingCertHashes. For Google Play, also add the Play App Signing certificate hash from Play Console.',
            'ضيف الـ SHA-256 بصيغة Base64 اللي ظاهر في النتيجة لـ signingCertHashes. ولو على Google Play، ضيف كمان hash شهادة Play App Signing من Play Console.'),
        severity: Severity.high,
        masvs: ['MASVS-RESILIENCE-2'],
        maswe: ['MASWE-0057'],
        cwe: 'CWE-693',
        profiles: _all,
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final missing = _requireApk(project);
    if (missing != null) return missing;
    if (!project.hasSource || !project.usesPackage('freerasp')) {
      return RuleCheck.notApplicable('freeRASP not used in the source');
    }
    final apk = project.apk!;
    if (apk.certificates.isEmpty) return RuleCheck.notApplicable('The APK is not signed');
    final configured = <String>{};
    String? packageName;
    var loc = '';
    int? line;
    for (final (f, c) in findCalls(project, {'AndroidConfig'})) {
      final args = f.args(c.open);
      final hashes = f.namedArg(args, 'signingCertHashes');
      if (hashes != null) {
        for (var k = hashes.start; k <= hashes.end; k++) {
          final t = f.tokens[k];
          if (t.isString && (t.value ?? '').isNotEmpty) configured.add(t.value!);
        }
        loc = f.path;
        line = f.lineOfToken(hashes.start);
      }
      final pkg = f.namedArg(args, 'packageName');
      if (pkg != null && f.tokens[pkg.start].isString) {
        packageName = f.tokens[pkg.start].value;
      }
    }
    if (configured.isEmpty) {
      return RuleCheck.notApplicable('No literal signingCertHashes (see AEG-P03)');
    }
    final out = <Finding>[];
    final apkHashes = apk.certificates.map((c) => c.sha256Base64).toList();
    final signerConfigured = apkHashes.any(configured.contains);
    if (apk.isBundle) {
      // Google Play re-signs bundles with the app signing key, which is not
      // in the file. The certificate here is the upload key.
      final c = apk.certificates.first;
      final others = configured.where((h) => !apkHashes.contains(h));
      if (signerConfigured && others.isEmpty) {
        out.add(inFile(loc, line,
            'signingCertHashes only has the upload key that signed ${apk.fileName} ("${c.commonName ?? 'unknown'}", ${c.sha256Base64}). '
                'Google Play re-signs the app with the app signing key, so every install from Play will trigger onAppIntegrity. '
                'Add the app signing key SHA-256 from Play Console (Test and release > App integrity > App signing), converted to Base64.',
            messageAr: 'الـ signingCertHashes فيها بس الـ upload key اللي وقّع ${apk.fileName} ("${c.commonName ?? 'unknown'}"، ${c.sha256Base64}). '
                'Google Play بيعيد توقيع التطبيق بالـ app signing key، فكل تثبيت من Play هيشغّل onAppIntegrity. '
                'ضيف الـ SHA-256 بتاع الـ app signing key من Play Console (Test and release > App integrity > App signing) بعد تحويله لـ Base64.'));
      }
    } else if (!signerConfigured) {
      final c = apk.certificates.first;
      out.add(inFile(loc, line,
          '${apk.fileName} is signed by "${c.commonName ?? 'unknown'}" with SHA-256 ${c.sha256Base64}, which is not in signingCertHashes.',
          messageAr: '${apk.fileName} متوقع بشهادة "${c.commonName ?? 'unknown'}" والـ SHA-256 بتاعها ${c.sha256Base64}، وده مش موجود في signingCertHashes.'));
    }
    if (packageName != null && apk.packageName != null && packageName != apk.packageName) {
      out.add(inFile(loc, line,
          'freeRASP packageName "$packageName" differs from the APK package "${apk.packageName}".',
          messageAr: 'الـ packageName في freeRASP "$packageName" مختلف عن package الـ APK "${apk.packageName}".'));
    }
    if (out.isEmpty && apk.isBundle && !signerConfigured) {
      return RuleCheck.notApplicable(
          'App bundle: Google Play signs the installed app, so compare signingCertHashes with the app signing key in Play Console (AEG-M04)');
    }
    return RuleCheck(out);
  }
}

class BinarySdkLevelsRule extends Rule {
  const BinarySdkLevelsRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-B11',
        title: Bilingual('Old Android SDK levels in the APK', 'إصدارات Android SDK قديمة في الـ APK'),
        description: Bilingual(
            'A low targetSdk keeps old, less secure platform behaviors switched on, and a minSdk below 24 lets the app run on Android versions without important security fixes.',
            'الـ targetSdk القديم بيخلي سلوكيات قديمة وأقل أماناً شغالة، والـ minSdk الأقل من 24 بيسمح للتطبيق يشتغل على إصدارات Android ناقصها إصلاحات أمنية مهمة.'),
        fix: Bilingual('Raise targetSdk to the latest level required by Google Play and minSdk to 24 or higher.',
            'ارفع الـ targetSdk لآخر إصدار مطلوب في Google Play، والـ minSdk لـ 24 أو أكتر.'),
        severity: Severity.medium,
        masvs: ['MASVS-CODE-1'],
        maswe: ['MASWE-0041', 'MASWE-0042'],
        cwe: 'CWE-1104',
        profiles: _all,
      );

  @override
  Future<RuleCheck> check(Project project, ProfileSet profile) async {
    final missing = _requireApk(project);
    if (missing != null) return missing;
    final apk = project.apk!;
    final out = <Finding>[];
    final target = apk.targetSdk;
    final min = apk.minSdk;
    if (target == null && min == null) return RuleCheck.notApplicable('No uses-sdk in the manifest');
    final loc = apk.location('AndroidManifest.xml');
    if (target != null && target < 34) {
      out.add(inFile(loc, null, 'targetSdk is $target.', messageAr: 'الـ targetSdk = $target.'));
    }
    if (min != null && min < 24 && !await reportedBySource(const MinSdkRule(), project, profile)) {
      out.add(inFile(loc, null, 'minSdk is $min.', messageAr: 'الـ minSdk = $min.'));
    }
    return RuleCheck(out);
  }
}

const binaryRules = <Rule>[
  DebugBuildRule(),
  BinaryDebuggableRule(),
  BinaryManifestNetworkRule(),
  PluginExportedComponentRule(),
  PluginPermissionsRule(),
  BinarySecretsRule(),
  ObfuscationAppliedRule(),
  BundledSecretFilesRule(),
  DebugCertificateRule(),
  RaspSigningHashRule(),
  BinarySdkLevelsRule(),
];
