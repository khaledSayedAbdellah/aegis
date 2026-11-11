/// Rules for Android configuration: manifest, Gradle and network config.
library;

import '../l10n/messages.g.dart';

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
        title: Bilingual(En.androidRulesAndroidAppIsDebuggable, Ar.androidRulesAndroidAppIsDebuggable),
        description: Bilingual(En.androidRulesADebuggableReleaseLetsAnyoneAttachADebugger, Ar.androidRulesADebuggableReleaseLetsAnyoneAttachADebugger),
        fix: Bilingual(En.androidRulesRemoveAndroidDebuggableFromAndroidmanifestXmlAndNeverSetDebuggableIsdebuggable, Ar.androidRulesRemoveAndroidDebuggableFromAndroidmanifestXmlAndNeverSetDebuggableIsdebuggable),
        severity: Severity.critical,
        masvs: ['MASVS-RESILIENCE-4'],
        maswe: ['MASWE-0063'],
        cwe: 'CWE-489',
        profiles: _all,
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final m = project.androidManifest;
    if (m == null && !project.hasAndroid) return RuleCheck.notApplicable('No Android project');
    if (m == null || project.androidManifestXml?.rootElement.name.local != 'manifest') {
      return RuleCheck.incompleteLocalized(En.androidManifestUnreadable, Ar.androidManifestUnreadable);
    }
    final out = <Finding>[];
    final app = firstElement(project.androidManifestXml!, 'application');
    if (app != null && androidAttr(app, 'debuggable') == 'true') {
      out.add(inFile(m.path, lineOfFirst(m.text, 'android:debuggable'),
          En.androidRulesAndroidDebuggableTrueIsSetInTheMainManifest,
          messageAr: Ar.androidRulesAndroidDebuggableTrueIsSetInTheMainManifest));
    }
    final g = project.appGradle;
    if (g != null) {
      final release = _releaseBlock(g.text);
      if (release != null &&
          RegExp(r'(isDebuggable\s*=\s*true|debuggable\s*(=\s*)?true)')
              .hasMatch(release)) {
        out.add(inFile(g.path, lineOfFirst(g.text, RegExp(r'[dD]ebuggable\s*(=\s*)?true')),
            En.androidRulesTheReleaseBuildTypeIsDebuggable,
            messageAr: Ar.androidRulesTheReleaseBuildTypeIsDebuggable));
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
        title: Bilingual(En.androidRulesAppDataCanBeBackedUp, Ar.androidRulesAppDataCanBeBackedUp),
        description: Bilingual(En.androidRulesWithBackupAllowedTheDefaultTokensAndDatabases, Ar.androidRulesWithBackupAllowedTheDefaultTokensAndDatabases),
        fix: Bilingual(En.androidRulesSetAndroidAllowbackupFalseOrDefineAndroidDataextractionrulesAndroidFullbackupcontentThat, Ar.androidRulesSetAndroidAllowbackupFalseOrDefineAndroidDataextractionrulesAndroidFullbackupcontentThat),
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
    if (hasRules) return RuleCheck.incompleteLocalized(En.platformBackupReferenceOnly, Ar.platformBackupReferenceOnly);
    if (v == 'true') {
      return RuleCheck([
        inFile(m.path, lineOfFirst(m.text, 'android:allowBackup'),
            En.androidRulesAndroidAllowbackupTrueWithoutBackupRules,
            messageAr: Ar.androidRulesAndroidAllowbackupTrueWithoutBackupRules)
      ]);
    }
    return RuleCheck([
      inFile(m.path, lineOfFirst(m.text, '<application'),
          En.androidRulesAndroidAllowbackupIsNotSetSoBackupIsEnabled,
          messageAr: Ar.androidRulesAndroidAllowbackupIsNotSetSoBackupIsEnabled)
    ]);
  }
}

class CleartextManifestRule extends Rule {
  const CleartextManifestRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-A03',
        title: Bilingual(En.androidRulesCleartextHttpTrafficAllowedAndroid, Ar.androidRulesCleartextHttpTrafficAllowedAndroid),
        description: Bilingual(En.androidRulesUsescleartexttrafficTrueLetsTheAppSendDataOverPlain, Ar.androidRulesUsescleartexttrafficTrueLetsTheAppSendDataOverPlain),
        fix: Bilingual(En.androidRulesRemoveAndroidUsescleartexttrafficTrueIfOneDevHostNeedsHttp, Ar.androidRulesRemoveAndroidUsescleartexttrafficTrueIfOneDevHostNeedsHttp),
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
            En.androidRulesAndroidUsescleartexttrafficTrueIsSet,
            messageAr: Ar.androidRulesAndroidUsescleartexttrafficTrueIsSet)
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
        title: Bilingual(En.androidRulesWeakNetworkSecurityConfig, Ar.androidRulesWeakNetworkSecurityConfig),
        description: Bilingual(En.androidRulesTheNetworkSecurityConfigAllowsCleartextTrafficOr, Ar.androidRulesTheNetworkSecurityConfigAllowsCleartextTrafficOr),
        fix: Bilingual(En.androidRulesSetCleartexttrafficpermittedFalseAndKeepCertificatesSrcUserOnlyInside, Ar.androidRulesSetCleartexttrafficpermittedFalseAndKeepCertificatesSrcUserOnlyInside),
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
    if (f == null || xml == null || xml.rootElement.name.local != 'network-security-config') {
      final ref = project.networkSecurityConfigReference;
      return ref == null || ref == '@null'
          ? RuleCheck.notApplicable('No network security config')
          : RuleCheck.incompleteLocalized(En.sourceNetworkConfigUnreadable(ref: ref), Ar.sourceNetworkConfigUnreadable(ref: ref));
    }
    final out = <Finding>[];
    for (final tag in const ['base-config', 'domain-config']) {
      for (final e in xml.findAllElements(tag)) {
        if (e.getAttribute('cleartextTrafficPermitted') == 'true') {
          out.add(inFile(f.path, lineOfFirst(f.text, 'cleartextTrafficPermitted="true"'),
              En.androidRulesCleartexttrafficpermittedTrueAllowsHttp(tag: tag),
              messageAr: Ar.androidRulesCleartexttrafficpermittedTrueAllowsHttp(tag: tag)));
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
            En.androidRulesUserInstalledCaCertificatesAreTrustedInReleaseBuilds,
            messageAr: Ar.androidRulesUserInstalledCaCertificatesAreTrustedInReleaseBuilds));
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
        title: Bilingual(En.androidRulesCertificatePinsHaveExpired, Ar.androidRulesCertificatePinsHaveExpired),
        description: Bilingual(En.androidRulesAfterThePinSetExpirationDateAndroidStopsEnforcing, Ar.androidRulesAfterThePinSetExpirationDateAndroidStopsEnforcing),
        fix: Bilingual(En.androidRulesRotateThePinsAndMoveTheExpirationDate, Ar.androidRulesRotateThePinsAndMoveTheExpirationDate),
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
            En.androidRulesPinSetExpiredOn(exp: exp), messageAr: Ar.androidRulesPinSetExpiredOn(exp: exp)));
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
        title: Bilingual(En.androidRulesExportedComponentWithoutPermission, Ar.androidRulesExportedComponentWithoutPermission),
        description: Bilingual(En.androidRulesAnyAppOnTheDeviceCanStartAn, Ar.androidRulesAnyAppOnTheDeviceCanStartAn),
        fix: Bilingual(En.androidRulesSetAndroidExportedFalseUnlessTheComponentMustBePublic, Ar.androidRulesSetAndroidExportedFalseUnlessTheComponentMustBePublic),
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
            En.androidRulesIsExportedWithoutAndroidPermission(tag: tag, name: name),
            messageAr: Ar.androidRulesIsExportedWithoutAndroidPermission(tag: tag, name: name)));
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
      if (actions.contains('android.intent.action.VIEW') && cats.contains('android.intent.category.BROWSABLE')) return true;
    }
    return false;
  }
}

class MinifyDisabledRule extends Rule {
  const MinifyDisabledRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-A07',
        title: Bilingual(En.androidRulesR8ShrinkingObfuscationDisabled, Ar.androidRulesR8ShrinkingObfuscationDisabled),
        description: Bilingual(En.androidRulesFlutterEnablesR8ForReleaseBuildsByDefault, Ar.androidRulesFlutterEnablesR8ForReleaseBuildsByDefault),
        fix: Bilingual(En.androidRulesRemoveMinifyenabledFalseIsminifyenabledFalseFrom, Ar.androidRulesRemoveMinifyenabledFalseIsminifyenabledFalseFrom),
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
            En.androidRulesTheReleaseBuildTypeDisablesR8MinifyenabledFalse,
            messageAr: Ar.androidRulesTheReleaseBuildTypeDisablesR8MinifyenabledFalse)
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
        title: Bilingual(En.androidRulesReleaseBuildSignedWithTheDebugKey, Ar.androidRulesReleaseBuildSignedWithTheDebugKey),
        description: Bilingual(En.androidRulesTheFlutterTemplateSignsReleaseBuildsWithThe, Ar.androidRulesTheFlutterTemplateSignsReleaseBuildsWithThe),
        fix: Bilingual(En.androidRulesCreateAReleaseKeystoreLoadItFromKeyProperties, Ar.androidRulesCreateAReleaseKeystoreLoadItFromKeyProperties),
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
            En.androidRulesReleaseUsesSigningconfigsDebug,
            messageAr: Ar.androidRulesReleaseUsesSigningconfigsDebug)
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
        title: Bilingual(En.androidRulesSigningSecretsExposed, Ar.androidRulesSigningSecretsExposed),
        description: Bilingual(En.androidRulesKeystorePasswordsInBuildGradleOrKeystoresKeyProperties, Ar.androidRulesKeystorePasswordsInBuildGradleOrKeystoresKeyProperties),
        fix: Bilingual(En.androidRulesReadPasswordsFromKeyPropertiesOrEnvironmentVariablesAnd, Ar.androidRulesReadPasswordsFromKeyPropertiesOrEnvironmentVariablesAnd),
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
            En.androidRulesIsHardcodedIn(value1: m.group(1), value2: g.path),
            messageAr: Ar.androidRulesIsHardcodedIn(value1: m.group(1), value2: g.path),
            snippet: '${m.group(1)} = ${redact(m.group(3)!)}'));
      }
    }
    final files = project.findFiles(project.androidSourceRoot, (r) =>
        r.endsWith('.jks') ||
        r.endsWith('.keystore') ||
        r.endsWith('/key.properties'));
    for (final f in files) {
      if (f.endsWith('debug.keystore')) continue;
      if (!project.isGitIgnored(f)) {
        out.add(inFile(f, null, En.androidRulesIsNotInGitignoreAndMayBe(f: f),
            messageAr: Ar.androidRulesIsNotInGitignoreAndMayBe(f: f)));
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
        title: Bilingual(En.androidRulesVeryOldAndroidVersionsSupported, Ar.androidRulesVeryOldAndroidVersionsSupported),
        description: Bilingual(En.androidRulesAndroidVersionsBelow70Api24MissImportant, Ar.androidRulesAndroidVersionsBelow70Api24MissImportant),
        fix: Bilingual(En.androidRulesRaiseMinsdkTo24OrHigher, Ar.androidRulesRaiseMinsdkTo24OrHigher),
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
        inFile(g.path, lineOfFirst(g.text, re), En.androidRulesMinsdkIs(v: v),
            messageAr: Ar.androidRulesMinsdkIs(v: v))
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
