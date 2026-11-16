/// Sign-in flows and platform IPC: OAuth, PendingIntent, FileProvider, task
/// affinity, APK signature schemes, the iOS privacy manifest and dynamic
/// code loading.
library;

import 'dart:io';

import 'package:path/path.dart' as p;
import 'package:xml/xml.dart';

import '../l10n/messages.g.dart';
import '../model.dart';
import '../project.dart';
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
    final manualFlow = project.usesPackage('flutter_web_auth') ||
        project.usesPackage('flutter_web_auth_2');
    for (final f in project.dartFiles) {
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
        final args = _parenthesized(code, m.end - 1);
        if (args == null || args.contains('FLAG_IMMUTABLE')) continue;
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
          final broad = tag == 'root-path' ||
              (const {'external-path', 'files-path'}.contains(tag) &&
                  const {'.', '/', ''}.contains(path ?? ''));
          if (!broad) continue;
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
    final hasManifest = dirs.any((d) =>
        File(project.abs(p.join(d, 'PrivacyInfo.xcprivacy'))).existsSync());
    if (hasManifest) return RuleCheck([]);
    for (final f in project.iosNativeSources) {
      final code = withoutComments(f.text);
      final m = _requiredReason.firstMatch(code);
      if (m == null) continue;
      return RuleCheck([
        inFile(f.path, _lineAt(code, m.start), En.privacyManifest(api: m[0]!),
            messageAr: Ar.privacyManifest(api: m[0]!))
      ]);
    }
    return RuleCheck([]);
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
    return RuleCheck(out);
  }
}

const platformIpcRules = <Rule>[
  OAuthFlowRule(),
  PendingIntentRule(),
  FileProviderPathsRule(),
  TaskHijackingRule(),
  PrivacyManifestRule(),
  DynamicCodeLoadingRule(),
];
