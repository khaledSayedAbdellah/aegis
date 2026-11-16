/// Sign-in flows and platform IPC: OAuth, PendingIntent, FileProvider, task
/// affinity, APK signature schemes, the iOS privacy manifest and dynamic
/// code loading.
library;

import 'dart:io';

import 'package:path/path.dart' as p;
import 'package:xml/xml.dart';

import '../binary/dex.dart';
import '../l10n/messages.g.dart';
import '../model.dart';
import '../project.dart';
import '../security/evidence.dart';
import '../security/native_analysis.dart' show withoutComments;
import 'rule.dart';

const _all = {MasProfile.l1, MasProfile.l2, MasProfile.r};

int _lineAt(String text, int offset) =>
    '\n'.allMatches(text.substring(0, offset)).length + 1;

/// The text between the `(` at [open] and its matching `)`.
String? _parenthesized(String code, int open) {
  var depth = 0;
  for (var i = open; i < code.length; i++) {
    if (code[i] == '(') depth++;
    if (code[i] == ')' && --depth == 0) return code.substring(open + 1, i);
  }
  return null;
}

/// A literal `minSdk` / `targetSdk` from the app's Gradle files, or null when
/// it comes from Flutter or a variable.
int? _gradleSdk(Project project, String name) {
  for (final path in const [
    'android/app/build.gradle',
    'android/app/build.gradle.kts',
    'app/build.gradle',
    'app/build.gradle.kts',
  ]) {
    final f = File(project.abs(path));
    if (!f.existsSync()) continue;
    final m = RegExp('$name(?:Version)?\\s*(?:=\\s*|\\()?\\s*(\\d+)')
        .firstMatch(f.readAsStringSync());
    if (m != null) return int.parse(m[1]!);
  }
  return null;
}

class OAuthFlowRule extends Rule {
  const OAuthFlowRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-P13',
        title: Bilingual(En.oauthTitle, Ar.oauthTitle),
        passTitleText: Bilingual(En.oauthPass, Ar.oauthPass),
        description: Bilingual(En.oauthDescription, Ar.oauthDescription),
        fix: Bilingual(En.oauthFix, Ar.oauthFix),
        severity: Severity.high,
        masvs: ['MASVS-AUTH-1'],
        cwe: 'CWE-345',
        profiles: _all,
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final out = <Finding>[];
    final pkce =
        project.dartFiles.any((f) => f.source.contains('code_challenge'));
    // flutter_appauth and package:oauth2 add PKCE themselves; any other
    // code flow (flutter_web_auth, url_launcher, a WebView) is built by hand.
    final manualFlow = !project.usesPackage('flutter_appauth') &&
        !project.usesPackage('oauth2');
    for (final f in project.dartFiles) {
      // package:oauth2 with a client secret.
      for (final c in f.calls({'AuthorizationCodeGrant'})) {
        final secret = f.namedArg(f.args(c.open), 'secret');
        if (secret == null || f.text(secret.start, secret.end) == 'null') {
          continue;
        }
        out.add(at(f, c.nameIndex, En.oauthClientSecret,
            messageAr: Ar.oauthClientSecret));
      }
      var reportedCode = false;
      for (final i in f.stringIndexes()) {
        final v = f.tokens[i].value ?? '';
        if (RegExp(r'response_type=(?:id_token(?:%20|\+| ))?token\b')
            .hasMatch(v)) {
          out.add(at(f, i, En.oauthImplicit, messageAr: Ar.oauthImplicit));
        } else if (v == 'client_secret' || v.contains('client_secret=')) {
          out.add(
              at(f, i, En.oauthClientSecret, messageAr: Ar.oauthClientSecret));
        } else if (manualFlow &&
            !pkce &&
            !reportedCode &&
            v.contains('response_type=code')) {
          reportedCode = true;
          out.add(at(f, i, En.oauthNoPkce, messageAr: Ar.oauthNoPkce));
        }
      }
    }
    return RuleCheck(out);
  }
}

class PendingIntentRule extends Rule {
  const PendingIntentRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-A15',
        title: Bilingual(En.pendingIntentTitle, Ar.pendingIntentTitle),
        passTitleText: Bilingual(En.pendingIntentPass, Ar.pendingIntentPass),
        description:
            Bilingual(En.pendingIntentDescription, Ar.pendingIntentDescription),
        fix: Bilingual(En.pendingIntentFix, Ar.pendingIntentFix),
        severity: Severity.medium,
        masvs: ['MASVS-PLATFORM-1'],
        maswe: ['MASWE-0032'],
        cwe: 'CWE-927',
        profiles: _all,
      );

  static final _explicit =
      RegExp(r'Intent\(\s*[^,()]+,\s*[\w.]+(?:::class\.java|\.class)\s*\)');

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final target = _gradleSdk(project, 'targetSdk');
    final out = <Finding>[];
    for (final file in [
      ...project.androidNativeSources,
      ...project.sharedNativeSources
    ]) {
      final code = withoutComments(file.text);
      for (final m in RegExp(
              r'PendingIntent\.get(?:Activity|Activities|Broadcast|Service|ForegroundService)\s*\(')
          .allMatches(code)) {
        var args = _parenthesized(code, m.end - 1);
        if (args == null) continue;
        // Flags passed in a variable: `val flags = ... FLAG_MUTABLE`.
        for (final name in RegExp(r'\b([a-z]\w*)\b')
            .allMatches(args)
            .map((m) => m[1]!)
            .toList()) {
          // The nearest declaration before the call.
          final decl =
              RegExp('\\b(?:val|var|final|int)\\s+$name\\b[^=\\n]*=([^\\n;]*)')
                  .allMatches(code)
                  .where((d) => d.start < m.start)
                  .lastOrNull;
          if (decl != null) args = '$args ${decl[1]}';
        }
        // Flags returned by a helper in the same file: `mutableFlags()`.
        for (final name in RegExp(r'\b([a-z]\w*)\s*\(\s*\)')
            .allMatches(args!)
            .map((m) => m[1]!)
            .toSet()) {
          final body = _functionBody(code, name);
          if (body != null && body.contains('FLAG_')) args = '$args $body';
        }
        if (args!.contains('FLAG_IMMUTABLE')) continue;
        final mutable = args.contains('FLAG_MUTABLE');
        // Before Android 12 (targetSdk 31) a PendingIntent with no flag is
        // mutable.
        if (!mutable && (target == null || target >= 31)) continue;
        if (_explicitIntent(code, args)) continue;
        out.add(inFile(file.path, _lineAt(code, m.start),
            mutable ? En.pendingIntentMutable : En.pendingIntentNoFlag,
            messageAr:
                mutable ? Ar.pendingIntentMutable : Ar.pendingIntentNoFlag));
      }
    }
    return RuleCheck(out);
  }

  /// The wrapped Intent names its target class, inline or where the
  /// variable passed is created.
  static bool _explicitIntent(String code, String args) {
    if (_explicit.hasMatch(args)) return true;
    for (final name
        in RegExp(r'\b([a-z]\w*)\b').allMatches(args).map((m) => m[1]!)) {
      final decl = RegExp(
              '(?:val|var|Intent|final)\\s+$name\\s*(?::\\s*Intent\\s*)?=\\s*([^\\n;]+)')
          .firstMatch(code);
      if (decl != null && _explicit.hasMatch(decl[1]!)) return true;
      if (RegExp(
              '$name\\.(?:setClass|setComponent|setClassName)\\(|$name\\.component\\s*=')
          .hasMatch(code)) {
        return true;
      }
    }
    return false;
  }
}

/// The text of the Kotlin or Java function [name] declared in [code], up to
/// the next declaration, or null.
String? _functionBody(String code, String name) {
  final m = RegExp(
          '\\b(?:fun|int|Int|static\\s+int)\\s+${RegExp.escape(name)}\\s*\\(')
      .firstMatch(code);
  if (m == null) return null;
  final rest = code.substring(m.end);
  final next = RegExp(
          r'\n\s*(?:(?:private|public|internal|protected|override|static|final)\s+)*(?:fun|class|object)\s')
      .firstMatch(rest);
  final end = next?.start ?? (rest.length < 2000 ? rest.length : 2000);
  return rest.substring(0, end);
}

/// FileProvider path elements that share far more than intended:
/// (element, path) for each.
List<(String, String)> broadProviderPaths(XmlDocument doc) => [
      for (final e in doc.descendantElements)
        if (_broadPath(e.name.local, e.getAttribute('path')))
          (e.name.local, e.getAttribute('path') ?? ''),
    ];

bool _broadPath(String element, String? path) =>
    element == 'root-path' ||
    (const {'external-path', 'files-path'}.contains(element) &&
        const {'.', '/', ''}.contains(path ?? ''));

class FileProviderPathsRule extends Rule {
  const FileProviderPathsRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-A16',
        title: Bilingual(En.fileProviderTitle, Ar.fileProviderTitle),
        passTitleText: Bilingual(En.fileProviderPass, Ar.fileProviderPass),
        description:
            Bilingual(En.fileProviderDescription, Ar.fileProviderDescription),
        fix: Bilingual(En.fileProviderFix, Ar.fileProviderFix),
        severity: Severity.medium,
        masvs: ['MASVS-PLATFORM-1'],
        maswe: ['MASWE-0018'],
        cwe: 'CWE-552',
        profiles: _all,
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final out = <Finding>[];
    for (final dir in const ['android/app/src/main/res', 'app/src/main/res']) {
      final res = Directory(project.abs(dir));
      if (!res.existsSync()) continue;
      for (final e in res.listSync(recursive: true)) {
        if (e is! File ||
            !e.path.endsWith('.xml') ||
            !p.split(e.path).any((s) => s.startsWith('xml'))) {
          continue;
        }
        final String text;
        try {
          text = e.readAsStringSync();
        } catch (_) {
          continue;
        }
        if (!text.contains('<paths')) continue;
        for (final m in RegExp(
                r'<(root-path|external-path|files-path|external-files-path|cache-path)\b[^>]*>')
            .allMatches(text)) {
          final tag = m[1]!;
          final path =
              RegExp(r'''path\s*=\s*["']([^"']*)["']''').firstMatch(m[0]!)?[1];
          if (!_broadPath(tag, path)) continue;
          out.add(inFile(project.rel(e.path), _lineAt(text, m.start),
              En.fileProvider(element: tag, path: path ?? ''),
              messageAr: Ar.fileProvider(element: tag, path: path ?? '')));
        }
      }
    }
    return RuleCheck(out);
  }
}

class TaskHijackingRule extends Rule {
  const TaskHijackingRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-A17',
        title: Bilingual(En.taskHijackTitle, Ar.taskHijackTitle),
        passTitleText: Bilingual(En.taskHijackPass, Ar.taskHijackPass),
        description:
            Bilingual(En.taskHijackDescription, Ar.taskHijackDescription),
        fix: Bilingual(En.taskHijackFix, Ar.taskHijackFix),
        severity: Severity.low,
        masvs: ['MASVS-PLATFORM-1'],
        cwe: 'CWE-1021',
        profiles: _all,
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final manifest = project.androidManifestXml;
    if (manifest == null) return RuleCheck.notApplicable();
    // Android 11 (API 30) fixed the StrandHogg attacks this enables.
    final min = _gradleSdk(project, 'minSdk');
    if (min != null && min >= 30) return RuleCheck([]);
    final file = project.androidManifest?.path ?? 'AndroidManifest.xml';
    final text = project.androidManifest?.text ?? '';
    final out = <Finding>[];
    for (final e in manifest.findAllElements('activity')) {
      final name = androidAttr(e, 'name') ?? '';
      final affinity = androidAttr(e, 'taskAffinity');
      final reparenting = androidAttr(e, 'allowTaskReparenting') == 'true';
      final singleTask = androidAttr(e, 'launchMode') == 'singleTask';
      final custom = affinity != null && affinity.isNotEmpty;
      if (!reparenting && !(custom && singleTask)) continue;
      final at = text.indexOf(name.isEmpty ? '<activity' : name);
      out.add(inFile(file, at < 0 ? null : _lineAt(text, at),
          En.taskHijack(activity: name),
          messageAr: Ar.taskHijack(activity: name)));
    }
    return RuleCheck(out);
  }
}

class V1OnlySignatureRule extends Rule {
  const V1OnlySignatureRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-B15',
        title: Bilingual(En.v1OnlyTitle, Ar.v1OnlyTitle),
        passTitleText: Bilingual(En.v1OnlyPass, Ar.v1OnlyPass),
        description: Bilingual(En.v1OnlyDescription, Ar.v1OnlyDescription),
        fix: Bilingual(En.v1OnlyFix, Ar.v1OnlyFix),
        severity: Severity.high,
        masvs: ['MASVS-RESILIENCE-2'],
        maswe: ['MASWE-0057'],
        cwe: 'CWE-347',
        profiles: _all,
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final apk = project.apk;
    // App bundles are always signed with jarsigner (v1); Google Play signs
    // the APKs it serves.
    if (apk == null || apk.isBundle) return RuleCheck.notApplicable();
    final certs = apk.certificates;
    if (certs.isEmpty || certs.any((c) => c.scheme != 'v1')) {
      return RuleCheck([]);
    }
    // Android 7.0 (API 24) verifies the v2 scheme; older devices accept a
    // v1-only APK changed by Janus (CVE-2017-13156).
    final min = apk.minSdk;
    if (min != null && min >= 24) return RuleCheck([]);
    return RuleCheck([
      inFile(
          '${apk.fileName}!/META-INF', null, En.v1Only(minSdk: '${min ?? '?'}'),
          messageAr: Ar.v1Only(minSdk: '${min ?? '?'}'))
    ]);
  }
}

/// Required-reason APIs (Apple, 2024) in the app's own code.
final _requiredReason = RegExp(
    r'\b(?:UserDefaults|NSUserDefaults|systemUptime|mach_absolute_time|'
    r'volumeAvailableCapacity\w*|NSFileSystemFreeSize|NSFileSystemSize|'
    r'creationDate|modificationDate|NSFileCreationDate|NSFileModificationDate|'
    r'contentModificationDateKey|creationDateKey|activeInputModes)\b');

class PrivacyManifestRule extends Rule {
  const PrivacyManifestRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-I14',
        title: Bilingual(En.privacyManifestTitle, Ar.privacyManifestTitle),
        passTitleText:
            Bilingual(En.privacyManifestPass, Ar.privacyManifestPass),
        description: Bilingual(
            En.privacyManifestDescription, Ar.privacyManifestDescription),
        fix: Bilingual(En.privacyManifestFix, Ar.privacyManifestFix),
        severity: Severity.low,
        masvs: ['MASVS-PRIVACY-1'],
        maswe: ['MASWE-0073'],
        profiles: _all,
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final ipa = project.ipa;
    if (ipa != null) {
      if (ipa.archive.contains('${ipa.appPath}/PrivacyInfo.xcprivacy')) {
        return RuleCheck([]);
      }
      final main = ipa.staticAnalysis.binaries
          .where((b) => b.path == '${ipa.appPath}/${ipa.executable}')
          .firstOrNull;
      final api = main?.slices
          .expand((s) => [...s.symbols, ...s.strings])
          .map((t) => _requiredReason.firstMatch(t)?[0])
          .whereType<String>()
          .firstOrNull;
      if (api == null) return RuleCheck([]);
      return RuleCheck([
        inFile(
            '${ipa.label}!/${ipa.appPath}', null, En.privacyManifest(api: api),
            messageAr: Ar.privacyManifest(api: api))
      ]);
    }
    if (!project.hasIos || project.iosNativeSources.isEmpty) {
      return RuleCheck.notApplicable();
    }
    final dirs = {
      for (final f in project.iosNativeSources) p.dirname(f.path),
    };
    final manifest = dirs
        .map((d) => File(project.abs(p.join(d, 'PrivacyInfo.xcprivacy'))))
        .where((f) => f.existsSync())
        .firstOrNull;
    final declared = manifest == null ? null : _declaredCategories(manifest);
    final out = <Finding>[];
    final reported = <String>{};
    for (final f in project.iosNativeSources) {
      // Headers declare APIs; the .m / .swift files are where they are used.
      if (f.path.endsWith('.h')) continue;
      final code = withoutComments(f.text);
      for (final m in _requiredReason.allMatches(code)) {
        final api = m[0]!;
        if (declared == null) {
          // No manifest: one finding is enough.
          return RuleCheck([
            inFile(f.path, _lineAt(code, m.start), En.privacyManifest(api: api),
                messageAr: Ar.privacyManifest(api: api))
          ]);
        }
        final category = _category(api);
        if (declared.contains(category) || !reported.add(category)) continue;
        out.add(inFile(f.path, _lineAt(code, m.start),
            En.privacyManifestCategory(category: category, api: api),
            messageAr:
                Ar.privacyManifestCategory(category: category, api: api)));
      }
    }
    return RuleCheck(out);
  }

  /// Apple's category for a required-reason API.
  static String _category(String api) => switch (api) {
        'UserDefaults' ||
        'NSUserDefaults' =>
          'NSPrivacyAccessedAPICategoryUserDefaults',
        'systemUptime' ||
        'mach_absolute_time' =>
          'NSPrivacyAccessedAPICategorySystemBootTime',
        'activeInputModes' => 'NSPrivacyAccessedAPICategoryActiveKeyboards',
        _
            when api.startsWith('volumeAvailableCapacity') ||
                api.startsWith('NSFileSystem') =>
          'NSPrivacyAccessedAPICategoryDiskSpace',
        _ => 'NSPrivacyAccessedAPICategoryFileTimestamp',
      };

  /// The NSPrivacyAccessedAPIType values a manifest declares; null when the
  /// file can't be read (then it is not judged).
  static Set<String>? _declaredCategories(File manifest) {
    try {
      final text = manifest.readAsStringSync();
      return {
        for (final m
            in RegExp(r'NSPrivacyAccessedAPICategory\w+').allMatches(text))
          m[0]!,
      };
    } catch (_) {
      return <String>{
        'NSPrivacyAccessedAPICategoryUserDefaults',
        'NSPrivacyAccessedAPICategorySystemBootTime',
        'NSPrivacyAccessedAPICategoryActiveKeyboards',
        'NSPrivacyAccessedAPICategoryDiskSpace',
        'NSPrivacyAccessedAPICategoryFileTimestamp',
      };
    }
  }
}

class DynamicCodeLoadingRule extends Rule {
  const DynamicCodeLoadingRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-C04',
        title: Bilingual(En.dynamicCodeTitle, Ar.dynamicCodeTitle),
        passTitleText: Bilingual(En.dynamicCodePass, Ar.dynamicCodePass),
        description:
            Bilingual(En.dynamicCodeDescription, Ar.dynamicCodeDescription),
        fix: Bilingual(En.dynamicCodeFix, Ar.dynamicCodeFix),
        severity: Severity.high,
        masvs: ['MASVS-CODE-4'],
        maswe: ['MASWE-0049'],
        cwe: 'CWE-94',
        profiles: _all,
      );

  /// Paths outside the app's own package.
  static final _outside = RegExp(
      r'getExternal\w*|Environment\.|externalCacheDir|getCacheDir|cacheDir|'
      r'getFilesDir|filesDir|[Dd]ownload|sdcard|/data/local|'
      r'documentDirectory|cachesDirectory|NSTemporaryDirectory|temporaryDirectory|'
      r'NSDocumentDirectory|NSCachesDirectory');

  /// [args] point outside the app, directly or through a variable declared
  /// in [code] (`let docs = ...documentDirectory...`).
  static bool _outsidePath(String code, String args) {
    if (_outside.hasMatch(args)) return true;
    for (final name
        in RegExp(r'\b([a-z]\w*)\b').allMatches(args).map((m) => m[1]!)) {
      final decl =
          RegExp('\\b(?:let|var|val|final)\\s+$name\\b[^=\\n]*=([^\\n;]+)')
              .firstMatch(code);
      if (decl != null && _outside.hasMatch(decl[1]!)) return true;
    }
    return false;
  }

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final out = <Finding>[];
    void scan(List<ProjectFile> files, RegExp call,
        bool Function(String code, String args) unsafe) {
      for (final file in files) {
        final code = withoutComments(file.text);
        for (final m in call.allMatches(code)) {
          final args = _parenthesized(code, m.end - 1) ?? '';
          if (!unsafe(code, args)) continue;
          final api = m[0]!.replaceAll(RegExp(r'[\s(]+$'), '');
          out.add(inFile(
              file.path, _lineAt(code, m.start), En.dynamicCode(api: api),
              messageAr: Ar.dynamicCode(api: api)));
        }
      }
    }

    final android = [
      ...project.androidNativeSources,
      ...project.sharedNativeSources
    ];
    // Any dex loader: apps load their own code without one.
    scan(android, RegExp(r'\b(?:DexClassLoader|InMemoryDexClassLoader)\s*\('),
        (_, __) => true);
    scan(android, RegExp(r'\b(?:PathClassLoader|System\.load)\s*\('),
        _outsidePath);
    scan(
        project.iosNativeSources,
        RegExp(r'\bdlopen\s*\(|\bBundle\s*\(\s*(?=path)|bundleWithPath:'),
        (code, args) =>
            !args.contains('Bundle.main') && _outsidePath(code, args));
    // JavaScript evaluated from strings (React Native and web code).
    scan(project.scriptSources, RegExp(r'\beval\s*\(|\bnew\s+Function\s*\('),
        (_, args) => !RegExp(r'''^\s*(['"`])[^'"`]*\1\s*$''').hasMatch(args));
    _overTheAir(project);
    return RuleCheck(out);
  }
}

/// Over-the-air code updates replace the app's code outside the store:
/// listed as evidence for review.
void _overTheAir(Project project) {
  String read(String path) {
    try {
      final f = File(project.abs(path));
      return f.existsSync() ? f.readAsStringSync() : '';
    } catch (_) {
      return '';
    }
  }

  final packageJson = read('package.json');
  final tools = [
    if (packageJson.contains('"react-native-code-push"')) 'CodePush',
    if (packageJson.contains('"expo-updates"')) 'Expo Updates',
    if (File(project.abs('shorebird.yaml')).existsSync() ||
        project.usesPackage('shorebird_code_push'))
      'Shorebird',
  ];
  if (tools.isEmpty) return;
  final list = tools.join(', ');
  project.securityEvidence.add(SecurityEvidence('AEG-C04', '.',
      Bilingual(En.otaUpdates(tools: list), Ar.otaUpdates(tools: list)),
      status: 'facts', data: {'tools': tools}));
}

const platformIpcRules = <Rule>[
  OAuthFlowRule(),
  PendingIntentRule(),
  FileProviderPathsRule(),
  TaskHijackingRule(),
  PrivacyManifestRule(),
  DynamicCodeLoadingRule(),
];

class FileProviderApkRule extends Rule {
  const FileProviderApkRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-B16',
        title: Bilingual(En.fileProviderTitle, Ar.fileProviderTitle),
        passTitleText: Bilingual(En.fileProviderPass, Ar.fileProviderPass),
        description:
            Bilingual(En.fileProviderDescription, Ar.fileProviderDescription),
        fix: Bilingual(En.fileProviderFix, Ar.fileProviderFix),
        severity: Severity.medium,
        masvs: ['MASVS-PLATFORM-1'],
        maswe: ['MASWE-0018'],
        cwe: 'CWE-552',
        profiles: _all,
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final apk = project.apk;
    final manifest = apk?.manifest;
    if (apk == null || manifest == null) return RuleCheck.notApplicable();
    final out = <Finding>[];
    final seen = <String>{};
    for (final meta in manifest.findAllElements('meta-data')) {
      if (androidAttr(meta, 'name') != 'android.support.FILE_PROVIDER_PATHS') {
        continue;
      }
      final reference = androidAttr(meta, 'resource');
      if (reference == null) continue;
      final List<String> paths;
      try {
        paths = apk.xmlResourcePaths(reference);
      } on FormatException {
        continue;
      }
      for (final path in paths) {
        if (!seen.add(path)) continue;
        final XmlDocument doc;
        try {
          doc = apk.readXmlResource(path);
        } on FormatException {
          continue;
        }
        for (final (element, value) in broadProviderPaths(doc)) {
          out.add(inFile('${apk.fileName}!/$path', null,
              En.fileProvider(element: element, path: value),
              messageAr: Ar.fileProvider(element: element, path: value)));
        }
      }
    }
    return RuleCheck(out);
  }
}

/// Libraries that load code at run time as part of how they work.
final _loaderLibraries =
    RegExp(r'^(?:com\.google\.android\.gms\.|com\.google\.firebase\.|'
        r'com\.google\.android\.play\.|androidx\.|android\.|kotlin\.|'
        r'com\.facebook\.soloader\.|io\.flutter\.|com\.android\.)');

/// A Java package name inside a string: `com.google.ads.Thing`,
/// `Lcom/facebook/x;`.
final _packageName = RegExp(
    r'\b(?:com|org|net|io|androidx|me|dev|co)[./][a-z][a-z0-9_]*(?:[./][a-z][a-z0-9_]*)+');

/// R8's `mapping.txt` for the APK at [apkPath], when the build left it
/// next to the APK or in Gradle's `outputs/mapping/<variant>/`: its path
/// and the original names of [wanted] renamed classes.
(String, Map<String, String>)? _mapping(String apkPath, Set<String> wanted) {
  if (wanted.isEmpty) return null;
  final dir = p.dirname(apkPath);
  final candidates = <String>[p.join(dir, 'mapping.txt')];
  final outputs = RegExp(r'^(.*[/\\]outputs)[/\\]').firstMatch(apkPath)?[1];
  if (outputs != null) {
    final root = Directory(p.join(outputs, 'mapping'));
    if (root.existsSync()) {
      final variants = [
        for (final d in root.listSync())
          if (d is Directory &&
              File(p.join(d.path, 'mapping.txt')).existsSync())
            p.basename(d.path)
      ];
      final name = p.basenameWithoutExtension(apkPath).toLowerCase();
      // `app-prod-release.apk` -> `prodRelease`; fall back to the only one.
      final match = variants.where(
          (v) => name.replaceAll(RegExp(r'^app-|-'), '') == v.toLowerCase());
      final pick = match.isNotEmpty
          ? match.first
          : variants.length == 1
              ? variants.single
              : variants.contains('release')
                  ? 'release'
                  : null;
      if (pick != null) candidates.add(p.join(root.path, pick, 'mapping.txt'));
    }
  }
  for (final path in candidates) {
    final f = File(path);
    if (!f.existsSync()) continue;
    final out = <String, String>{};
    final line = RegExp(r'^(\S+) -> (\S+):$');
    for (final l in f.readAsLinesSync()) {
      if (l.startsWith(' ') || l.startsWith('#')) continue;
      final m = line.firstMatch(l);
      if (m != null && wanted.contains(m[2])) out[m[2]!] = m[1]!;
    }
    return (path, out);
  }
  return null;
}

/// A class name R8 shortened: no package left (`-repackageclasses`), or
/// only one- to three-letter names (`a.b.C`).
bool _renamed(String className) {
  final parts = className.split('.');
  return parts.length == 1 || parts.every((p) => p.length <= 3);
}

class DynamicCodeApkRule extends Rule {
  const DynamicCodeApkRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-B17',
        title: Bilingual(En.dynamicCodeTitle, Ar.dynamicCodeTitle),
        passTitleText: Bilingual(En.dynamicCodePass, Ar.dynamicCodePass),
        description:
            Bilingual(En.dynamicCodeDescription, Ar.dynamicCodeDescription),
        fix: Bilingual(En.dynamicCodeFix, Ar.dynamicCodeFix),
        severity: Severity.high,
        masvs: ['MASVS-CODE-4'],
        maswe: ['MASWE-0049'],
        cwe: 'CWE-94',
        profiles: _all,
      );

  static const _loaders = {
    'dalvik.system.DexClassLoader',
    'dalvik.system.InMemoryDexClassLoader',
  };

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final apk = project.apk;
    if (apk == null) return RuleCheck.notApplicable();
    final users = <String, String>{}; // class -> loader
    final hints = <String, Set<String>>{}; // class -> package names it uses
    for (final e in apk.zip.entries.values) {
      if (!RegExp(r'(^|/)classes\d*\.dex$').hasMatch(e.name)) continue;
      if (e.size > 96 * 1024 * 1024) continue;
      final usage = readDexUsage(
          apk.zip.readEntry(e),
          (s) => s.length < 160 && _packageName.hasMatch(s)
              ? {'pkg:${_packageName.firstMatch(s)![0]!.replaceAll('/', '.')}'}
              : const {},
          classLabels: (c) => _loaders.contains(c) ? {c} : const {});
      usage.users.forEach((cls, labels) {
        final loader = labels.where(_loaders.contains).firstOrNull;
        if (loader == null) return;
        users.putIfAbsent(cls, () => loader.split('.').last);
        (hints[cls] ??= {}).addAll([
          for (final l in labels)
            if (l.startsWith('pkg:')) l.substring(4)
        ]);
      });
    }
    final own = apk.packageName;
    final out = <Finding>[];
    final libraries = <String>[];
    final unknown = <String>[];
    // R8's mapping.txt gives renamed classes their real names back.
    final mapping = _mapping(apk.path, {
      for (final c in users.keys)
        if (_renamed(c)) c
    });
    if (mapping != null && mapping.$2.isNotEmpty) {
      project.securityEvidence.add(SecurityEvidence(
          meta.id,
          '${apk.fileName}!/classes.dex',
          Bilingual(En.dynamicCodeMapping(file: mapping.$1),
              Ar.dynamicCodeMapping(file: mapping.$1)),
          status: 'facts',
          data: {'mapping': mapping.$1}));
    }
    for (final e in users.entries) {
      var owner = e.key;
      final original = mapping?.$2[e.key];
      if (original != null) {
        // `com.acme.app.dev` still keeps its code in `com.acme.*`.
        final prefix = own?.split('.').take(2).join('.');
        if (_loaderLibraries.hasMatch(original) ||
            (prefix != null && !original.startsWith('$prefix.'))) {
          libraries.add('${e.key} ($original)');
          continue;
        }
        owner = '$original (${e.key})';
      } else if (_renamed(e.key)) {
        // R8 renamed the class (and may have moved it out of its package):
        // the package names in its strings are the only clue to its owner.
        final used = hints[e.key] ?? const <String>{};
        final mine =
            own != null && used.any((h) => h.startsWith('$own.') || h == own);
        final library =
            used.where((h) => own == null || !h.startsWith(own)).firstOrNull;
        if (!mine && library != null) {
          libraries.add('${e.key} ($library)');
          continue;
        }
        if (!mine) {
          unknown.add(e.key);
          continue;
        }
        owner = '${e.key} ($own)';
      } else if (_loaderLibraries.hasMatch(e.key)) {
        libraries.add(e.key);
        continue;
      }
      out.add(inFile('${apk.fileName}!/classes.dex', null,
          En.dynamicCodeApk(loader: e.value, owner: owner),
          messageAr: Ar.dynamicCodeApk(loader: e.value, owner: owner)));
    }
    if (unknown.isNotEmpty) {
      final list = (unknown..sort()).take(8).join(', ');
      project.securityEvidence.add(SecurityEvidence(
          meta.id,
          '${apk.fileName}!/classes.dex',
          Bilingual(En.dynamicCodeRenamed(classes: list),
              Ar.dynamicCodeRenamed(classes: list)),
          status: 'facts',
          data: {'renamedClasses': unknown}));
    }
    if (libraries.isNotEmpty) {
      final list = (libraries..sort()).take(5).join(', ');
      project.securityEvidence.add(SecurityEvidence(
          meta.id,
          '${apk.fileName}!/classes.dex',
          Bilingual(En.dynamicCodeLibraries(classes: list),
              Ar.dynamicCodeLibraries(classes: list)),
          status: 'facts',
          data: {'classes': libraries}));
    }
    return RuleCheck(out);
  }
}
