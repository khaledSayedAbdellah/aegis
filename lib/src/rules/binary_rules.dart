/// Rules that inspect the compiled APK.
///
/// They focus on what the source cannot show: values injected at build time,
/// manifest entries merged from plugins, whether obfuscation really happened,
/// and which certificate actually signed the app. When the source project is
/// also available, problems that a source rule already reports are skipped so
/// nothing is counted twice.
library;

import '../l10n/messages.g.dart';

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
        title: Bilingual(En.binaryRulesADebugJitFlutterBuildWasShipped,
            Ar.binaryRulesADebugJitFlutterBuildWasShipped),
        description: Bilingual(
            En.binaryRulesDebugBuildsContainKernelBlobBinTheWholeDartProgram,
            Ar.binaryRulesDebugBuildsContainKernelBlobBinTheWholeDartProgram),
        fix: Bilingual(
            En.binaryRulesDistributeOnlyBuildsMadeWithFlutterBuildApk,
            Ar.binaryRulesDistributeOnlyBuildsMadeWithFlutterBuildApk),
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
          En.binaryRulesKernelBlobBinIsPresentThisIsADebugBuild,
          messageAr: Ar.binaryRulesKernelBlobBinIsPresentThisIsADebugBuild)
    ]);
  }
}

class BinaryDebuggableRule extends Rule {
  const BinaryDebuggableRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-B02',
        title: Bilingual(
            En.binaryRulesTheApkIsDebuggable, Ar.binaryRulesTheApkIsDebuggable),
        description: Bilingual(
            En.binaryRulesTheFinalManifestInsideTheApkHasAndroidDebuggableTrue,
            Ar.binaryRulesTheFinalManifestInsideTheApkHasAndroidDebuggableTrue),
        fix: Bilingual(En.binaryRulesFindWhatSetsItABuildTypeFlavor,
            Ar.binaryRulesFindWhatSetsItABuildTypeFlavor),
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
    if (app == null || androidAttr(app, 'debuggable') != 'true') {
      return RuleCheck([]);
    }
    if (await reportedBySource(const DebuggableRule(), project, profile)) {
      return RuleCheck.notApplicable('Already reported by AEG-A01');
    }
    return RuleCheck([
      inFile(
          apk.location('AndroidManifest.xml'),
          null,
          En.binaryRulesAndroidDebuggableTrueInTheFinalManifest(
              value1: _notInSource(project,
                  'It is not in your source manifest, so the build configuration or a library adds it.')),
          messageAr: Ar.binaryRulesAndroidDebuggableTrueInTheFinalManifest(
              value1: project.hasSource
                  ? ' ومش موجود في الـ manifest بتاعك، يعني إعدادات البيلد أو مكتبة هي اللي ضافته.'
                  : ''))
    ]);
  }
}

class BinaryManifestNetworkRule extends Rule {
  const BinaryManifestNetworkRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-B03',
        title: Bilingual(
            En.binaryRulesFinalManifestWeakensBackupOrNetworkSecurity,
            Ar.binaryRulesFinalManifestWeakensBackupOrNetworkSecurity),
        description: Bilingual(
            En.binaryRulesLibrariesCanMergeAttributesSuchAsUsescleartexttrafficOr,
            Ar.binaryRulesLibrariesCanMergeAttributesSuchAsUsescleartexttrafficOr),
        fix: Bilingual(En.binaryRulesOverrideTheMergedValueInYourManifestWith,
            Ar.binaryRulesOverrideTheMergedValueInYourManifestWith),
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
    final suffix = _notInSource(project,
        'Your source manifest does not set this, so a library or build variant does.');
    final suffixAr = project.hasSource
        ? ' والـ manifest بتاعك مش فيه كده، يعني مكتبة أو build variant هي السبب.'
        : '';

    if (app != null) {
      final backup = androidAttr(app, 'allowBackup');
      final hasRules = androidAttr(app, 'dataExtractionRules') != null ||
          androidAttr(app, 'fullBackupContent') != null;
      if (backup != 'false' &&
          !hasRules &&
          !await reportedBySource(const AllowBackupRule(), project, profile)) {
        out.add(inFile(
            manifestLoc,
            null,
            En.binaryRulesBackupIsEnabledInTheFinalManifestAllowbackup(
                value1: backup ?? 'default true', suffix: suffix),
            messageAr:
                Ar.binaryRulesBackupIsEnabledInTheFinalManifestAllowbackup(
                    value1: backup ?? 'true افتراضياً', suffix: suffixAr)));
      }
      if (androidAttr(app, 'usesCleartextTraffic') == 'true' &&
          !await reportedBySource(
              const CleartextManifestRule(), project, profile)) {
        out.add(inFile(
            manifestLoc,
            null,
            En.binaryRulesUsescleartexttrafficTrueInTheFinalManifest(
                suffix: suffix),
            messageAr: Ar.binaryRulesUsescleartexttrafficTrueInTheFinalManifest(
                suffix: suffixAr)));
      }
    }

    final List<(String, XmlDocument)> configs;
    try {
      configs = apk.networkSecurityConfigs;
    } catch (e) {
      return RuleCheck.incompleteLocalized(
          En.binaryNetworkConfigUnreadable(error: e),
          Ar.binaryNetworkConfigUnreadable(error: e),
          out);
    }
    // Each packaged variant may differ from the source and from the other variants.
    for (final (entry, doc) in configs) {
      final loc = apk.location(entry);
      for (final tag in const ['base-config', 'domain-config']) {
        for (final e in doc.findAllElements(tag)) {
          if (e.getAttribute('cleartextTrafficPermitted') == 'true') {
            out.add(inFile(
                loc,
                null,
                En.binaryRulesCleartexttrafficpermittedTrueInTheShippedNetworkSecurityConfig(
                    tag: tag),
                messageAr: Ar
                    .binaryRulesCleartexttrafficpermittedTrueInTheShippedNetworkSecurityConfig(
                        tag: tag)));
          }
        }
      }
      for (final c in doc.findAllElements('certificates')) {
        if (c.getAttribute('src') != 'user') continue;
        final inDebug = c.ancestors
            .whereType<XmlElement>()
            .any((a) => a.name.local == 'debug-overrides');
        if (!inDebug) {
          out.add(inFile(loc, null,
              En.binaryRulesTheShippedNetworkSecurityConfigTrustsUserInstalledCas,
              messageAr: Ar
                  .binaryRulesTheShippedNetworkSecurityConfigTrustsUserInstalledCas));
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
    if (actions.contains('android.intent.action.VIEW') &&
        cats.contains('android.intent.category.BROWSABLE')) {
      return true;
    }
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
        title: Bilingual(
            En.binaryRulesLibraryAddsAnExportedComponentWithoutPermission,
            Ar.binaryRulesLibraryAddsAnExportedComponentWithoutPermission),
        description: Bilingual(
            En.binaryRulesPluginsMergeTheirOwnActivitiesServicesReceiversAnd,
            Ar.binaryRulesPluginsMergeTheirOwnActivitiesServicesReceiversAnd),
        fix: Bilingual(En.binaryRulesCheckWhetherTheComponentMustBePublicIf,
            Ar.binaryRulesCheckWhetherTheComponentMustBePublicIf),
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
      for (final tag in const [
        'activity',
        'activity-alias',
        'service',
        'receiver',
        'provider'
      ]) {
        for (final e in src.findAllElements(tag)) {
          final n = androidAttr(e, 'name');
          if (n != null) sourceNames.add(n);
        }
      }
    }
    final out = <Finding>[];
    for (final tag in const [
      'activity',
      'activity-alias',
      'service',
      'receiver',
      'provider'
    ]) {
      for (final e in apk.manifest!.findAllElements(tag)) {
        if (androidAttr(e, 'exported') != 'true') continue;
        if (androidAttr(e, 'permission') != null) continue;
        if (tag == 'provider' &&
            (androidAttr(e, 'readPermission') != null ||
                androidAttr(e, 'writePermission') != null)) {
          continue;
        }
        if (_isLauncherOrLink(e)) continue;
        final name = androidAttr(e, 'name') ?? tag;
        if (project.hasSource && _declaredInSource(name, sourceNames)) continue;
        out.add(inFile(
            apk.location('AndroidManifest.xml'),
            null,
            En.binaryRulesIsExportedWithoutAPermission(
                tag: tag,
                name: name,
                value3: project.hasSource ? ' (added by a library)' : ''),
            messageAr: Ar.binaryRulesIsExportedWithoutAPermission(
                tag: tag,
                name: name,
                value3: project.hasSource ? ' (ضافته مكتبة)' : '')));
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
        title: Bilingual(En.binaryRulesSensitivePermissionsAddedByLibraries,
            Ar.binaryRulesSensitivePermissionsAddedByLibraries),
        description: Bilingual(
            En.binaryRulesPluginsCanMergePermissionsYouNeverAskedFor,
            Ar.binaryRulesPluginsCanMergePermissionsYouNeverAskedFor),
        fix: Bilingual(
            En.binaryRulesRemoveUnneededPermissionsInYourManifestWithUsesPermission,
            Ar.binaryRulesRemoveUnneededPermissionsInYourManifestWithUsesPermission),
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
    final list = (added.toList()..sort())
        .map((n) => n.replaceFirst('android.permission.', ''))
        .join(', ');
    return RuleCheck([
      inFile(
          apk.location('AndroidManifest.xml'),
          null,
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
  'json',
  'env',
  'txt',
  'yaml',
  'yml',
  'xml',
  'properties',
  'js',
  'html',
  'cfg',
  'ini',
  'conf',
  'plist',
};

class BinarySecretsRule extends Rule {
  const BinarySecretsRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-B06',
        title: Bilingual(
            En.binaryRulesSecretInsideTheApk, Ar.binaryRulesSecretInsideTheApk),
        description: Bilingual(
            En.binaryRulesValuesPassedWithDartDefineDartDefineFromFileOrGeneratedBy,
            Ar.binaryRulesValuesPassedWithDartDefineDartDefineFromFileOrGeneratedBy),
        fix: Bilingual(En.binaryRulesDoNotShipSecretKeysInTheApp,
            Ar.binaryRulesDoNotShipSecretKeysInTheApp),
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
                !pemBodyFollows(s, m.end,
                    next: i + 1 < strings.length ? strings[i + 1] : null)) {
              continue;
            }
            _report(project, apk, entry, kind, name, m.group(0)!, sourceText,
                reported, out);
          }
        }
        if (s.contains('eyJ')) {
          for (final m in RegExp(
                  r'eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}')
              .allMatches(s)) {
            if (jwtRole(m.group(0)!) == 'service_role') {
              _report(project, apk, entry, kind, 'Supabase service_role key',
                  m.group(0)!, sourceText, reported, out);
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
        scan(n, printableStrings(bytes, min: 8),
            resources ? 'resources' : 'dex');
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

  void _report(
      Project project,
      ApkContext apk,
      String entry,
      String kind,
      String name,
      String value,
      String sourceText,
      Set<String> reported,
      List<Finding> out) {
    if (!reported.add(value)) return;
    if (project.hasSource && sourceText.contains(value)) {
      return; // AEG-D01 reports it
    }
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
    out.add(inFile(apk.location(entry), null,
        En.binaryRulesFound(name: name, where: where),
        messageAr: Ar.binaryRulesFound(name: name, where: whereAr),
        snippet: redact(value)));
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
        title: Bilingual(En.binaryRulesTheShippedDartCodeIsNotObfuscated,
            Ar.binaryRulesTheShippedDartCodeIsNotObfuscated),
        description: Bilingual(
            En.binaryRulesReadableClassNamesInLibappSoMeanTheRelease,
            Ar.binaryRulesReadableClassNamesInLibappSoMeanTheRelease),
        fix: Bilingual(
            En.binaryRulesBuildWithFlutterBuildApkReleaseObfuscateSplitDebugInfoBuildSymbols,
            Ar.binaryRulesBuildWithFlutterBuildApkReleaseObfuscateSplitDebugInfoBuildSymbols),
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
    if (apk.isDebugFlutterBuild) {
      return RuleCheck.notApplicable('Debug build (see AEG-B01)');
    }
    if (apk.libappEntry == null) {
      return RuleCheck.notApplicable('No libapp.so in the APK');
    }

    final ident = RegExp(r'[A-Za-z_$][A-Za-z0-9_$]{5,}');
    final tokens = <String>{};
    for (final s in apk.libappStrings) {
      for (final m in ident.allMatches(s)) {
        tokens.add(m.group(0)!);
      }
    }
    final frameworkHits = _frameworkClassNames.where(tokens.contains).toList()
      ..sort();

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
    final readable =
        frameworkHits.length >= 3 || (own.length >= 5 && ownRatio >= 0.3);
    final obfuscated =
        frameworkHits.length <= 1 && (own.length < 5 || ownRatio < 0.1);
    if (readable) {
      final examples =
          [...frameworkHits.take(3), ...ownHits.take(3)].join(', ');
      return RuleCheck([
        inFile(
            apk.location(apk.libappEntry!),
            null,
            En.binaryRulesReadableClassNamesInLibappSo(
                examples: examples,
                value2: ownHits.isEmpty
                    ? ''
                    : '; ${ownHits.length} of your ${own.length} classes'),
            messageAr: Ar.binaryRulesReadableClassNamesInLibappSo(
                examples: examples,
                value2: ownHits.isEmpty
                    ? ''
                    : '؛ ${ownHits.length} من ${own.length} كلاس بتوعك'))
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
        title: Bilingual(En.binaryRulesSecretFileShippedInsideTheApk,
            Ar.binaryRulesSecretFileShippedInsideTheApk),
        description: Bilingual(
            En.binaryRulesFilesUnderFlutterAssetsAreStoredAsIsAEnv,
            Ar.binaryRulesFilesUnderFlutterAssetsAreStoredAsIsAEnv),
        fix: Bilingual(En.binaryRulesRemoveTheFileFromTheAssetsAndKeep,
            Ar.binaryRulesRemoveTheFileFromTheAssetsAndKeep),
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
      out.add(inFile(
          apk.location(entry), null, En.binaryRulesIsInsideTheApk(rel: rel),
          messageAr: Ar.binaryRulesIsInsideTheApk(rel: rel)));
    }
    return RuleCheck(out);
  }
}

class DebugCertificateRule extends Rule {
  const DebugCertificateRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-B09',
        title: Bilingual(En.binaryRulesApkSignedWithTheAndroidDebugCertificate,
            Ar.binaryRulesApkSignedWithTheAndroidDebugCertificate),
        description: Bilingual(
            En.binaryRulesTheDebugKeystoreIsSharedByEveryDeveloper,
            Ar.binaryRulesTheDebugKeystoreIsSharedByEveryDeveloper),
        fix: Bilingual(
            En.binaryRulesSignReleaseBuildsWithYourOwnReleaseUploadKeystore,
            Ar.binaryRulesSignReleaseBuildsWithYourOwnReleaseUploadKeystore),
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
    if (apk.certificates.isEmpty) {
      return RuleCheck.notApplicable('The APK is not signed');
    }
    final debug = apk.certificates.where((c) => c.isAndroidDebug).toList();
    if (debug.isEmpty) return RuleCheck([]);
    if (await reportedBySource(const DebugSigningRule(), project, profile)) {
      return RuleCheck.notApplicable('Already reported by AEG-A08');
    }
    return RuleCheck([
      inFile(apk.location('META-INF'), null,
          En.binaryRulesSignedWithCnAndroidDebug(value1: debug.first.scheme),
          messageAr: Ar.binaryRulesSignedWithCnAndroidDebug(
              value1: debug.first.scheme))
    ]);
  }
}

class RaspSigningHashRule extends Rule {
  const RaspSigningHashRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-B10',
        title: Bilingual(En.binaryRulesFreeraspDoesNotKnowThisApkSCertificate,
            Ar.binaryRulesFreeraspDoesNotKnowThisApkSCertificate),
        description: Bilingual(
            En.binaryRulesFreeraspComparesTheRunningAppSSigningCertificateWith,
            Ar.binaryRulesFreeraspComparesTheRunningAppSSigningCertificateWith),
        fix: Bilingual(En.binaryRulesAddTheBase64Sha256ShownInTheFinding,
            Ar.binaryRulesAddTheBase64Sha256ShownInTheFinding),
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
    if (apk.certificates.isEmpty) {
      return RuleCheck.notApplicable('The APK is not signed');
    }
    final configured = <String>{};
    String? packageName;
    var loc = '';
    int? line;
    // Named first: Dart 3.0.0's compiler crashes on a pattern `for` whose
    // iterable contains a set literal.
    final androidConfigs = findCalls(project, {'AndroidConfig'});
    for (final (f, c) in androidConfigs) {
      final args = f.args(c.open);
      final hashes = f.namedArg(args, 'signingCertHashes');
      if (hashes != null) {
        for (var k = hashes.start; k <= hashes.end; k++) {
          final t = f.tokens[k];
          if (t.isString && (t.value ?? '').isNotEmpty) {
            configured.add(t.value!);
          }
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
      return RuleCheck.notApplicable(
          'No literal signingCertHashes (see AEG-P03)');
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
        out.add(inFile(
            loc,
            line,
            En.binaryRulesSigningcerthashesOnlyHasTheUploadKeyThatSigned(
                value1: apk.fileName,
                value2: c.commonName ?? 'unknown',
                value3: c.sha256Base64),
            messageAr:
                Ar.binaryRulesSigningcerthashesOnlyHasTheUploadKeyThatSigned(
                    value1: apk.fileName,
                    value2: c.commonName ?? 'unknown',
                    value3: c.sha256Base64)));
      }
    } else if (!signerConfigured) {
      final c = apk.certificates.first;
      out.add(inFile(
          loc,
          line,
          En.binaryRulesIsSignedByWithSha256(
              value1: apk.fileName,
              value2: c.commonName ?? 'unknown',
              value3: c.sha256Base64),
          messageAr: Ar.binaryRulesIsSignedByWithSha256(
              value1: apk.fileName,
              value2: c.commonName ?? 'unknown',
              value3: c.sha256Base64)));
    }
    if (packageName != null &&
        apk.packageName != null &&
        packageName != apk.packageName) {
      out.add(inFile(
          loc,
          line,
          En.binaryRulesFreeraspPackagenameDiffersFromTheApk(
              packageName: packageName, value2: apk.packageName),
          messageAr: Ar.binaryRulesFreeraspPackagenameDiffersFromTheApk(
              packageName: packageName, value2: apk.packageName)));
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
        title: Bilingual(En.binaryRulesOldAndroidSdkLevelsInTheApk,
            Ar.binaryRulesOldAndroidSdkLevelsInTheApk),
        description: Bilingual(
            En.binaryRulesALowTargetsdkKeepsOldLessSecurePlatform,
            Ar.binaryRulesALowTargetsdkKeepsOldLessSecurePlatform),
        fix: Bilingual(En.binaryRulesRaiseTargetsdkToTheLatestLevelRequiredBy,
            Ar.binaryRulesRaiseTargetsdkToTheLatestLevelRequiredBy),
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
    if (target == null && min == null) {
      return RuleCheck.notApplicable('No uses-sdk in the manifest');
    }
    final loc = apk.location('AndroidManifest.xml');
    if (target != null && target < 34) {
      out.add(inFile(loc, null, En.binaryRulesTargetsdkIs(target: target),
          messageAr: Ar.binaryRulesTargetsdkIs(target: target)));
    }
    if (min != null &&
        min < 24 &&
        !await reportedBySource(const MinSdkRule(), project, profile)) {
      out.add(inFile(loc, null, En.binaryRulesMinsdkIs(min: min),
          messageAr: Ar.binaryRulesMinsdkIs(min: min)));
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
