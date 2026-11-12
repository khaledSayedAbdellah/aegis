/// Rules that verify protections are wired correctly, not just installed.
///
/// This is what makes aegis different from a plain checklist scanner: it
/// checks whether your RASP is started, configured for *your* app, and whether
/// a detected threat triggers a real reaction.
library;

import '../l10n/messages.g.dart';

import 'dart:io';

import 'package:xml/xml.dart';

import '../dart_scanner.dart';
import '../model.dart';
import '../project.dart';
import '../util.dart';
import 'dart_rules.dart' show guardedByDebug;
import 'rule.dart';

const _all = {MasProfile.l1, MasProfile.l2, MasProfile.r};
const _r = {MasProfile.r};
const _l2 = {MasProfile.l2};
const _l2r = {MasProfile.l2, MasProfile.r};

const raspPackages = [
  'freerasp',
  'safe_device',
  'flutter_jailbreak_detection',
  'jailbreak_root_detection',
  'flutter_neo_shield',
  'flutter_app_security',
  'trust_fall',
];

/// Dart files that import [package].
List<DartFile> filesImporting(Project p, String package) =>
    p.dartFiles.where((f) => f.importsPackage(package)).toList();

/// Calls to [name] whose receiver chain contains all of [receivers].
List<(DartFile, CallSite)> findCalls(Project p, Set<String> names,
    {List<String> receivers = const []}) {
  final out = <(DartFile, CallSite)>[];
  for (final f in p.dartFiles) {
    for (final c in f.calls(names)) {
      if (receivers.every(c.receivers.contains)) out.add((f, c));
    }
  }
  return out;
}

final _localLogging = RegExp(
    r'^(await\s+)?(print|debugPrint|log|developer\s*\.\s*log|_?log(ger)?\s*\.\s*\w+|Logger\s*\(\s*\)\s*\.\s*\w+|debugger|assert)\s*\(');

/// Whether the callback value at [a] does nothing but local logging.
/// Returns null when it cannot be decided (e.g. a tear-off defined elsewhere).
bool? isTrivialReaction(Project p, DartFile f, Arg a) {
  final first = f.tokens[a.start];
  if (a.start == a.end) {
    if (first.isIdent && first.text == 'null') return true;
    if (first.isIdent) {
      // Tear-off: look for the function body in the same or other files.
      for (final file in [f, ...p.dartFiles.where((x) => x != f)]) {
        final body = file.functionBody(first.text);
        if (body != null) return _trivialBody(file, body.start, body.end);
      }
      return null;
    }
  }
  if (first.isPunct('(')) {
    final close = f.matchOf(a.start);
    if (close == null || close >= a.end) return null;
    var b = close + 1;
    final asyncTok = f.at(b);
    if (asyncTok != null && asyncTok.isIdent && asyncTok.text == 'async') b++;
    return _trivialBody(f, b, a.end);
  }
  return null;
}

bool _trivialBody(DartFile f, int start, int end) {
  final t = f.at(start);
  if (t == null) return true;
  if (t.isPunct('=>')) {
    final expr = f.text(start + 1, end).trim();
    if (expr.isEmpty || expr == 'null' || expr == '{}') return true;
    return _localLogging.hasMatch(expr);
  }
  if (t.isPunct('{')) {
    final close = f.matchOf(start) ?? end;
    if (close == start + 1) return true; // empty block
    final statements = <String>[];
    var s = start + 1;
    var k = start + 1;
    while (k < close) {
      final tk = f.tokens[k];
      if (tk.isPunct('{') || tk.isPunct('(') || tk.isPunct('[')) {
        final m = f.matchOf(k);
        if (m != null && m < close) {
          k = m + 1;
          continue;
        }
      }
      if (tk.isPunct(';')) {
        statements.add(f.text(s, k - 1).trim());
        s = k + 1;
      }
      k++;
    }
    if (s < close) statements.add(f.text(s, close - 1).trim());
    return statements
        .where((st) => st.isNotEmpty && st != 'return')
        .every(_localLogging.hasMatch);
  }
  return false;
}

/// `applicationId` from the app Gradle file.
String? androidApplicationId(Project p) {
  final g = p.appGradle;
  if (g == null) return null;
  final m = RegExp(r'''applicationId\s*(=\s*)?["']([^"']+)["']''')
      .firstMatch(stripCComments(g.text));
  return m?.group(2);
}

/// `PRODUCT_BUNDLE_IDENTIFIER` values of the Runner target.
Set<String> iosBundleIds(Project p) {
  final f = File(p.abs('ios/Runner.xcodeproj/project.pbxproj'));
  if (!f.existsSync()) return const {};
  final ids = <String>{};
  for (final m in RegExp(r'PRODUCT_BUNDLE_IDENTIFIER\s*=\s*"?([^";]+)"?;')
      .allMatches(f.readAsStringSync())) {
    final id = m.group(1)!.trim();
    if (id.endsWith('RunnerTests') || id.contains(r'$(')) continue;
    ids.add(id);
  }
  return ids;
}

List<String> _stringList(DartFile f, Arg a) {
  final out = <String>[];
  for (var k = a.start; k <= a.end; k++) {
    final t = f.tokens[k];
    if (t.isString) out.add(t.value ?? '');
  }
  return out;
}

// ---------------------------------------------------------------------------

class RaspPresenceRule extends Rule {
  const RaspPresenceRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-P01',
        title: Bilingual(En.protectionRulesNoRuntimeProtectionRasp,
            Ar.protectionRulesNoRuntimeProtectionRasp),
        description: Bilingual(
            En.protectionRulesWithoutRaspTheAppCannotTellWhenIt,
            Ar.protectionRulesWithoutRaspTheAppCannotTellWhenIt),
        fix: Bilingual(En.protectionRulesAddARaspSdkSuchAsFreeraspStart,
            Ar.protectionRulesAddARaspSdkSuchAsFreeraspStart),
        severity: Severity.high,
        masvs: ['MASVS-RESILIENCE-1', 'MASVS-RESILIENCE-4'],
        maswe: ['MASWE-0051', 'MASWE-0064', 'MASWE-0065'],
        cwe: 'CWE-919',
        profiles: _r,
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    if (!project.isFlutterApp) return RuleCheck.notApplicable();
    final has = raspPackages.any(project.usesPackage);
    if (has) return RuleCheck([]);
    return RuleCheck([
      inFile('pubspec.yaml', null,
          En.protectionRulesNoRaspPackageFoundInDependencies,
          messageAr: Ar.protectionRulesNoRaspPackageFoundInDependencies)
    ]);
  }
}

class FreeRaspWiringRule extends Rule {
  const FreeRaspWiringRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-P02',
        title: Bilingual(En.protectionRulesMissingFreeraspStartupWiring,
            Ar.protectionRulesMissingFreeraspStartupWiring),
        description: Bilingual(
            En.protectionRulesFreeraspOnlyProtectsTheAppAfterTalsecInstanceStartConfigRuns,
            Ar.protectionRulesFreeraspOnlyProtectsTheAppAfterTalsecInstanceStartConfigRuns),
        fix: Bilingual(
            En.protectionRulesInMainWidgetsflutterbindingEnsureinitializedTalsecInstanceAttachlistenerCallbackAwaitTalsecInstanceStartConfig,
            Ar.protectionRulesInMainWidgetsflutterbindingEnsureinitializedTalsecInstanceAttachlistenerCallbackAwaitTalsecInstanceStartConfig),
        severity: Severity.critical,
        masvs: ['MASVS-RESILIENCE-1'],
        maswe: ['MASWE-0051'],
        cwe: 'CWE-693',
        profiles: _all,
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    if (!project.usesPackage('freerasp')) {
      return RuleCheck.notApplicable('freerasp not used');
    }
    const methods = {'start', 'attachListener'};
    final candidates =
        findCalls(project, methods, receivers: ['instance', 'Talsec']);
    final entry =
        project.dartFiles.where((f) => f.path == 'lib/main.dart').firstOrNull;
    final body = entry?.functionBody('main', topLevel: true);
    final direct = <String, int>{};
    if (entry != null && body != null) {
      // Only direct statements in the conventional entry point qualify.
      // Helpers, conditional code and alternate entry points need review.
      final imports = <String>{};
      final tokens = entry.tokens;
      for (var i = 0; i + 1 < body.start; i++) {
        if (tokens[i].text != 'import' ||
            !(tokens[i + 1].value ?? '').startsWith('package:freerasp/')) {
          continue;
        }
        final end = tokens.indexWhere((t) => t.isPunct(';'), i + 2);
        if (end == i + 2) imports.add('Talsec');
        if (end == i + 4 && tokens[i + 2].text == 'as') {
          imports.add('${tokens[i + 3].text}.Talsec');
        }
      }
      // A local declaration with the same identifier makes the binding ambiguous.
      imports.removeWhere((name) {
        final identifier = name.split('.').first;
        for (var i = 1; i < tokens.length - 1; i++) {
          if (tokens[i].text != identifier) continue;
          final previous = tokens[i - 1];
          final next = tokens[i + 1];
          if ({
                'class',
                'enum',
                'mixin',
                'typedef',
                'type',
                'final',
                'var',
                'const'
              }.contains(previous.text) ||
              previous.isIdent && next.isPunct('=')) {
            return true;
          }
        }
        return false;
      });
      var statementStart = body.start + 1;
      final calls = {for (final c in entry.calls(methods)) c.nameIndex: c};
      for (var i = statementStart; i < body.end; i++) {
        if (tokens[i].isPunct(';')) {
          statementStart = i + 1;
          continue;
        }
        if (tokens[i].isPunct('{') ||
            tokens[i].text == 'return' ||
            tokens[i].text == 'throw') {
          break;
        }
        final c = calls[i];
        if (c != null &&
            c.close + 1 < tokens.length &&
            tokens[c.close + 1].isPunct(';') &&
            entry.args(c.open).isNotEmpty) {
          final first = tokens[statementStart].text == 'await'
              ? statementStart + 1
              : statementStart;
          final receiver = tokens.sublist(first, i).map((t) => t.text).join();
          if (imports.any((name) => receiver == '$name.instance.')) {
            direct.putIfAbsent(c.name, () => i);
          }
        }
        final end = entry.matchOf(i);
        if (end != null && end > i) i = end;
      }
    }
    if (direct.length == methods.length &&
        direct['attachListener']! < direct['start']!) {
      return RuleCheck([]);
    }
    final found = candidates.map((c) => c.$2.name).toSet();
    final findings = [
      if (!found.contains('start'))
        inFile('pubspec.yaml', null,
            En.protectionRulesNoFreeraspStartCallWasFoundInThe,
            messageAr: Ar.protectionRulesNoFreeraspStartCallWasFoundInThe),
      if (!found.contains('attachListener'))
        inFile('pubspec.yaml', null,
            En.protectionRulesNoFreeraspListenerRegistrationWasFoundInThe,
            messageAr:
                Ar.protectionRulesNoFreeraspListenerRegistrationWasFoundInThe),
    ];
    final indirect = candidates.isEmpty &&
        project.dartFiles
            .any((f) => f.tokens.any((t) => t.isIdent && t.text == 'Talsec'));
    if (indirect) {
      return RuleCheck.incompleteLocalized(
          En.raspIndirectUnresolved, Ar.raspIndirectUnresolved);
    }
    if (body == null || direct.length != found.length || findings.isEmpty) {
      return RuleCheck.incompleteLocalized(
          En.raspOrderUnverified, Ar.raspOrderUnverified, findings);
    }
    return RuleCheck(findings);
  }
}

class FreeRaspConfigRule extends Rule {
  const FreeRaspConfigRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-P03',
        title: Bilingual(En.protectionRulesFreeraspIsMisconfigured,
            Ar.protectionRulesFreeraspIsMisconfigured),
        description: Bilingual(
            En.protectionRulesFreeraspChecksTheAppAgainstThePackageName,
            Ar.protectionRulesFreeraspChecksTheAppAgainstThePackageName),
        fix: Bilingual(En.protectionRulesUseYourRealApplicationidBundleIdsThe,
            Ar.protectionRulesUseYourRealApplicationidBundleIdsThe),
        severity: Severity.high,
        masvs: ['MASVS-RESILIENCE-2'],
        maswe: ['MASWE-0057'],
        cwe: 'CWE-693',
        profiles: _all,
      );

  /// Values copied from the freeRASP documentation/example.
  static const _docValues = [
    'aheaditec',
    'freeraspExample',
    'AKoRuyLMM91E7lX/Zqp3u4jMmd0A7hH/Iqozu0TMVd0='
  ];

  bool _placeholder(String v) {
    final l = v.toLowerCase();
    return v.trim().isEmpty ||
        _docValues.any((d) => v.contains(d)) ||
        l.contains('your') ||
        l.contains('xxx') ||
        l.contains('todo') ||
        l.contains('replace') ||
        l == 'hash' ||
        l.contains('...');
  }

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    if (!project.usesPackage('freerasp')) return RuleCheck.notApplicable();
    final out = <Finding>[];
    final configs = findCalls(project, {'TalsecConfig'});
    if (configs.isEmpty) {
      return RuleCheck.notApplicable('No TalsecConfig found');
    }
    for (final (f, c) in configs) {
      final args = f.args(c.open);
      final isProd = f.namedArg(args, 'isProd');
      if (isProd != null) {
        final v = f.text(isProd.start, isProd.end).replaceAll(' ', '');
        if (v == 'false' ||
            v == 'kDebugMode' ||
            v == '!kReleaseMode' ||
            v == 'kProfileMode') {
          out.add(at(f, isProd.start,
              En.protectionRulesIsprodIsSoReleaseBuildsRun(v: v),
              messageAr: Ar.protectionRulesIsprodIsSoReleaseBuildsRun(v: v)));
        }
      }
    }

    final appId = androidApplicationId(project);
    // Named first: Dart 3.0.0's compiler crashes on a pattern `for` whose
    // iterable contains a set literal.
    final androidConfigs = findCalls(project, {'AndroidConfig'});
    for (final (f, c) in androidConfigs) {
      final args = f.args(c.open);
      final pkg = f.namedArg(args, 'packageName');
      if (pkg != null) {
        final values = _stringList(f, pkg);
        final v = values.isEmpty ? '' : values.first;
        if (values.isNotEmpty && _placeholder(v)) {
          out.add(at(f, pkg.start,
              En.protectionRulesPackagenameLooksLikeAPlaceholderOr(v: v),
              messageAr:
                  Ar.protectionRulesPackagenameLooksLikeAPlaceholderOr(v: v)));
        } else if (values.isNotEmpty && appId != null && v != appId) {
          out.add(at(
              f,
              pkg.start,
              En.protectionRulesPackagenameDoesNotMatchApplicationid(
                  v: v, appId: appId),
              messageAr: Ar.protectionRulesPackagenameDoesNotMatchApplicationid(
                  v: v, appId: appId)));
        }
      }
      final hashes = f.namedArg(args, 'signingCertHashes');
      if (hashes == null) {
        out.add(at(f, c.nameIndex,
            En.protectionRulesAndroidconfigHasNoSigningcerthashes,
            messageAr: Ar.protectionRulesAndroidconfigHasNoSigningcerthashes));
      } else {
        final hs = _stringList(f, hashes);
        final isLiteralList = f.tokens[hashes.start].isPunct('[');
        if (isLiteralList && hs.isEmpty) {
          out.add(at(
              f, hashes.start, En.protectionRulesSigningcerthashesIsEmpty,
              messageAr: Ar.protectionRulesSigningcerthashesIsEmpty));
        }
        for (final h in hs) {
          if (_placeholder(h)) {
            out.add(at(f, hashes.start,
                En.protectionRulesSigningcerthashesContainsAPlaceholderOrTheDocumentationExample,
                messageAr: Ar
                    .protectionRulesSigningcerthashesContainsAPlaceholderOrTheDocumentationExample));
            break;
          }
          if (RegExp(r'^[0-9A-Fa-f:]{40,}$').hasMatch(h)) {
            out.add(at(f, hashes.start,
                En.protectionRulesASigningHashIsInHexFreeraspExpects,
                messageAr:
                    Ar.protectionRulesASigningHashIsInHexFreeraspExpects));
            break;
          }
        }
        if (isLiteralList && hs.length == 1 && profile.resilience) {
          out.add(at(f, hashes.start,
              En.protectionRulesOnlyOneSigningHashIsConfiguredAppsOn,
              messageAr:
                  Ar.protectionRulesOnlyOneSigningHashIsConfiguredAppsOn));
        }
      }
    }

    final bundleIds = iosBundleIds(project);
    // Named first: Dart 3.0.0's compiler crashes on a pattern `for` whose
    // iterable contains a set literal.
    final iosConfigs = findCalls(project, {'IOSConfig', 'IosConfig'});
    for (final (f, c) in iosConfigs) {
      final args = f.args(c.open);
      final ids = f.namedArg(args, 'bundleIds') ?? f.namedArg(args, 'bundleId');
      if (ids != null) {
        final values = _stringList(f, ids);
        for (final v in values) {
          if (_placeholder(v)) {
            out.add(at(f, ids.start,
                En.protectionRulesBundleidsContainsPlaceholder(v: v),
                messageAr:
                    Ar.protectionRulesBundleidsContainsPlaceholder(v: v)));
          } else if (bundleIds.isNotEmpty && !bundleIds.contains(v)) {
            out.add(at(
                f,
                ids.start,
                En.protectionRulesBundleIdIsNotOneOf(
                    v: v, value2: bundleIds.join(', ')),
                messageAr: Ar.protectionRulesBundleIdIsNotOneOf(
                    v: v, value2: bundleIds.join(', '))));
          }
        }
      }
      final team = f.namedArg(args, 'teamId');
      if (team != null) {
        final values = _stringList(f, team);
        if (values.isNotEmpty &&
            (_placeholder(values.first) || values.first.length != 10)) {
          out.add(at(
              f,
              team.start,
              En.protectionRulesTeamidIsNotAValid10Character(
                  value1: values.first),
              messageAr: Ar.protectionRulesTeamidIsNotAValid10Character(
                  value1: values.first)));
        }
      }
    }
    return RuleCheck(out);
  }
}

class FreeRaspReactionRule extends Rule {
  const FreeRaspReactionRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-P04',
        title: Bilingual(En.protectionRulesThreatsAreDetectedButNothingHappens,
            Ar.protectionRulesThreatsAreDetectedButNothingHappens),
        description: Bilingual(
            En.protectionRulesDetectionWithoutReactionIsNotProtectionCallbacksThat,
            Ar.protectionRulesDetectionWithoutReactionIsNotProtectionCallbacksThat),
        fix: Bilingual(
            En.protectionRulesForOnprivilegedaccessOnhooksOnappintegrityAndOndebugBlockSensitive,
            Ar.protectionRulesForOnprivilegedaccessOnhooksOnappintegrityAndOndebugBlockSensitive),
        severity: Severity.medium,
        l2Severity: Severity.high,
        masvs: [
          'MASVS-RESILIENCE-1',
          'MASVS-RESILIENCE-2',
          'MASVS-RESILIENCE-4'
        ],
        maswe: ['MASWE-0051', 'MASWE-0058', 'MASWE-0064', 'MASWE-0065'],
        cwe: 'CWE-693',
        profiles: _all,
      );

  static const critical = [
    'onPrivilegedAccess',
    'onHooks',
    'onAppIntegrity',
    'onDebug'
  ];
  static const recommended = [
    'onSimulator',
    'onUnofficialStore',
    'onObfuscationIssues',
    'onDeviceBinding'
  ];

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    if (!project.usesPackage('freerasp')) return RuleCheck.notApplicable();
    final callbacks = findCalls(project, {'ThreatCallback'});
    if (callbacks.isEmpty) {
      return RuleCheck.notApplicable('No ThreatCallback (reported by AEG-P02)');
    }
    final out = <Finding>[];
    for (final (f, c) in callbacks) {
      final args = f.args(c.open);
      final names = args.map((a) => a.name).whereType<String>().toSet();
      final wanted = profile.resilience || profile.isL2
          ? [...critical, ...recommended]
          : critical;
      final missing = wanted.where((n) => !names.contains(n)).toList();
      if (missing.isNotEmpty) {
        out.add(at(
            f,
            c.nameIndex,
            En.protectionRulesThreatcallbackDoesNotHandle(
                value1: missing.join(', ')),
            messageAr: Ar.protectionRulesThreatcallbackDoesNotHandle(
                value1: missing.join(', '))));
      }
      final trivial = <String>[];
      for (final a in args) {
        if (a.name == null || !critical.contains(a.name)) continue;
        if (isTrivialReaction(project, f, a) == true) trivial.add(a.name!);
      }
      if (trivial.isNotEmpty) {
        out.add(at(
            f,
            c.nameIndex,
            En.protectionRulesTheseCallbacksOnlyLogOrDoNothing(
                value1: trivial.join(', ')),
            messageAr: Ar.protectionRulesTheseCallbacksOnlyLogOrDoNothing(
                value1: trivial.join(', '))));
      }
    }
    return RuleCheck(out);
  }
}

class AppCheckMissingRule extends Rule {
  const AppCheckMissingRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-P05',
        title: Bilingual(En.protectionRulesFirebaseUsedWithoutAppCheck,
            Ar.protectionRulesFirebaseUsedWithoutAppCheck),
        description: Bilingual(
            En.protectionRulesWithoutAppCheckScriptsAndModifiedAppsCan,
            Ar.protectionRulesWithoutAppCheckScriptsAndModifiedAppsCan),
        fix: Bilingual(
            En.protectionRulesAddFirebaseAppCheckWithPlayIntegrityAndroidAndApp,
            Ar.protectionRulesAddFirebaseAppCheckWithPlayIntegrityAndroidAndApp),
        severity: Severity.medium,
        masvs: ['MASVS-RESILIENCE-2'],
        maswe: ['MASWE-0056', 'MASWE-0054'],
        cwe: 'CWE-346',
        profiles: _l2r,
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    if (!project.usesPackage('firebase_core')) {
      return RuleCheck.notApplicable('Firebase not used');
    }
    if (project.usesPackage('firebase_app_check')) return RuleCheck([]);
    return RuleCheck([
      inFile('pubspec.yaml', null,
          En.protectionRulesFirebaseCoreIsUsedButFirebaseAppCheckIsNot,
          messageAr:
              Ar.protectionRulesFirebaseCoreIsUsedButFirebaseAppCheckIsNot)
    ]);
  }
}

class AppCheckDebugProviderRule extends Rule {
  const AppCheckDebugProviderRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-P06',
        title: Bilingual(En.protectionRulesAppCheckDebugProviderCanReachRelease,
            Ar.protectionRulesAppCheckDebugProviderCanReachRelease),
        description: Bilingual(
            En.protectionRulesTheDebugProviderSkipsDeviceAttestationIfIt,
            Ar.protectionRulesTheDebugProviderSkipsDeviceAttestationIfIt),
        fix: Bilingual(
            En.protectionRulesSelectTheProviderWithKdebugmodeEGAndroidproviderKdebugmode,
            Ar.protectionRulesSelectTheProviderWithKdebugmodeEGAndroidproviderKdebugmode),
        severity: Severity.high,
        masvs: ['MASVS-RESILIENCE-2'],
        maswe: ['MASWE-0056'],
        cwe: 'CWE-489',
        profiles: _all,
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    if (!project.usesPackage('firebase_app_check')) {
      return RuleCheck.notApplicable('firebase_app_check not used');
    }
    final out = <Finding>[];
    for (final f in project.dartFiles) {
      for (var i = 0; i + 2 < f.tokens.length; i++) {
        final t = f.tokens[i];
        if (!t.isIdent) continue;
        final isEnumDebug =
            (t.text == 'AndroidProvider' || t.text == 'AppleProvider') &&
                f.tokens[i + 1].isPunct('.') &&
                f.tokens[i + 2].text == 'debug';
        final isClassDebug = (t.text == 'AndroidDebugProvider' ||
                t.text == 'AppleDebugProvider') &&
            f.tokens[i + 1].isPunct('(');
        if (!isEnumDebug && !isClassDebug) continue;
        final line = f.lineOfToken(i);
        final window = [
          for (var l = line - 2; l <= line + 2; l++) f.lineText(l)
        ].join(' ');
        if (RegExp(r'k(Debug|Release|Profile)Mode').hasMatch(window)) continue;
        if (guardedByDebug(f, i)) continue;
        out.add(at(
            f,
            i,
            En.protectionRulesIsUsedWithoutAKdebugmodeGuard(
                value1: t.text, value2: isEnumDebug ? '.debug' : '()'),
            messageAr: Ar.protectionRulesIsUsedWithoutAKdebugmodeGuard(
                value1: t.text, value2: isEnumDebug ? '.debug' : '()')));
      }
    }
    return RuleCheck(out);
  }
}

class PinningRule extends Rule {
  const PinningRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-P07',
        title: Bilingual(En.protectionRulesNoEffectiveCertificatePinning,
            Ar.protectionRulesNoEffectiveCertificatePinning),
        description: Bilingual(
            En.protectionRulesWithoutPinningAUserInstalledOrCompromisedCaLets,
            Ar.protectionRulesWithoutPinningAUserInstalledOrCompromisedCaLets),
        fix: Bilingual(
            En.protectionRulesPinYourApiHostsAPinSetInNetworkSecurityConfigXml,
            Ar.protectionRulesPinYourApiHostsAPinSetInNetworkSecurityConfigXml),
        severity: Severity.medium,
        masvs: ['MASVS-NETWORK-2'],
        maswe: ['MASWE-0028'],
        cwe: 'CWE-295',
        profiles: _l2,
      );

  static const _pinningPackages = [
    'http_certificate_pinning',
    'ssl_pinning_plugin',
    'certificate_pinning_httpclient',
    'dio_certificate_pinning',
    'flutter_ssl_pinning',
  ];
  static const _networkPackages = [
    'http',
    'dio',
    'chopper',
    'retrofit',
    'graphql',
    'graphql_flutter',
    'web_socket_channel',
    'grpc'
  ];

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final usesNetwork = _networkPackages.any(project.dependsOn) ||
        project.dartFiles.any((f) => f.source.contains('HttpClient('));
    if (!usesNetwork) return RuleCheck.notApplicable('No HTTP client found');

    final out = <Finding>[];
    var evidence = false;
    final nsc = project.networkSecurityConfigXml;
    if (nsc != null) {
      final now = DateTime.now();
      final active = nsc.findAllElements('pin-set').where((s) {
        final exp = DateTime.tryParse(s.getAttribute('expiration') ?? '');
        return exp == null || exp.isAfter(now);
      });
      if (active.isNotEmpty) evidence = true;
    }
    final ats = project.infoPlistData?['NSAppTransportSecurity'];
    if (ats is Map && ats['NSPinnedDomains'] != null) evidence = true;
    if (_pinningPackages.any(project.usesPackage)) evidence = true;

    for (final f in project.dartFiles) {
      if (f.source.contains('CertPinShield')) evidence = true;
      for (final c in f.calls({'SecurityContext'})) {
        final args = f.args(c.open);
        final roots = f.namedArg(args, 'withTrustedRoots');
        final rootsOff =
            roots != null && f.text(roots.start, roots.end).trim() == 'false';
        final loadsCert = f.source.contains('setTrustedCertificates');
        if (loadsCert && rootsOff) {
          evidence = true;
        } else if (loadsCert && !rootsOff) {
          out.add(at(f, c.nameIndex,
              En.protectionRulesSecuritycontextLoadsYourCertificateButKeepsTrustingSystem,
              messageAr: Ar
                  .protectionRulesSecuritycontextLoadsYourCertificateButKeepsTrustingSystem));
          evidence = true;
        }
      }
      for (var i = 0; i + 2 < f.tokens.length; i++) {
        final t = f.tokens[i];
        if (!t.isIdent ||
            !(t.text == 'badCertificateCallback' ||
                t.text == 'validateCertificate')) {
          continue;
        }
        final body = f.text(i, (i + 60).clamp(0, f.tokens.length - 1).toInt());
        if (RegExp(r'(sha256|sha1|fingerprint|\.der|pem)', caseSensitive: false)
            .hasMatch(body)) {
          evidence = true;
        }
      }
    }
    if (!evidence) {
      out.add(inFile(
          null, null, En.protectionRulesNoCertificatePinningFoundForAnAppThat,
          messageAr: Ar.protectionRulesNoCertificatePinningFoundForAnAppThat));
    }
    return RuleCheck(out);
  }
}

class LocalAuthRule extends Rule {
  const LocalAuthRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-P08',
        title: Bilingual(En.protectionRulesBiometricCheckIsOnlyABoolean,
            Ar.protectionRulesBiometricCheckIsOnlyABoolean),
        description: Bilingual(
            En.protectionRulesLocalAuthReturnsTrueFalseWithFridaThatResultIs,
            Ar.protectionRulesLocalAuthReturnsTrueFalseWithFridaThatResultIs),
        fix: Bilingual(
            En.protectionRulesBindBiometricsToAKeyUseBiometricStorageOr,
            Ar.protectionRulesBindBiometricsToAKeyUseBiometricStorageOr),
        severity: Severity.medium,
        masvs: ['MASVS-AUTH-2'],
        maswe: ['MASWE-0020', 'MASWE-0021'],
        cwe: 'CWE-287',
        profiles: _l2,
      );

  static const _cryptoBound = [
    'biometric_storage',
    'flutter_locker',
    'biometric_signature',
    'flutter_biometric_storage'
  ];

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    if (!project.usesPackage('local_auth')) {
      return RuleCheck.notApplicable('local_auth not used');
    }
    final out = <Finding>[];
    final calls = <(DartFile, CallSite)>[];
    for (final f in filesImporting(project, 'local_auth')) {
      calls.addAll(f.calls({'authenticate'}).map((c) => (f, c)));
    }
    if (calls.isEmpty) {
      return RuleCheck.notApplicable(
          'local_auth is a dependency but no authenticate() call was found in the scanned code');
    }
    final bound = _cryptoBound.any(project.usesPackage);
    if (!bound) {
      final (f, c) = calls.first;
      out.add(at(f, c.nameIndex,
          En.protectionRulesBiometricResultIsUsedAsAPlainBoolean,
          messageAr: Ar.protectionRulesBiometricResultIsUsedAsAPlainBoolean));
    }
    for (final (f, c) in calls) {
      final txt = f.text(c.open, c.close).replaceAll(RegExp(r'\s+'), '');
      if (!txt.contains('biometricOnly:true')) {
        out.add(at(f, c.nameIndex,
            En.protectionRulesAuthenticateAllowsFallingBackToDevicePinPasscodeBiometriconly,
            messageAr: Ar
                .protectionRulesAuthenticateAllowsFallingBackToDevicePinPasscodeBiometriconly));
      }
    }
    return RuleCheck(out);
  }
}

class ScreenProtectionRule extends Rule {
  const ScreenProtectionRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-P09',
        title: Bilingual(En.protectionRulesNoScreenshotRecordingProtection,
            Ar.protectionRulesNoScreenshotRecordingProtection),
        description: Bilingual(
            En.protectionRulesSensitiveScreensBalancesOtpsCardsCanBeCaptured,
            Ar.protectionRulesSensitiveScreensBalancesOtpsCardsCanBeCaptured),
        fix: Bilingual(
            En.protectionRulesSetFlagSecureOnAndroidEGScreenProtectorOrFreerasp,
            Ar.protectionRulesSetFlagSecureOnAndroidEGScreenProtectorOrFreerasp),
        severity: Severity.low,
        masvs: ['MASVS-PLATFORM-3'],
        maswe: ['MASWE-0038'],
        cwe: 'CWE-200',
        profiles: _l2,
      );

  static const _packages = [
    'screen_protector',
    'flutter_windowmanager',
    'flutter_windowmanager_plus',
    'no_screenshot',
    'secure_application',
    'flutter_prevent_screenshot',
    'screen_capture_event',
  ];

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    if (!project.isFlutterApp) return RuleCheck.notApplicable();
    if (_packages.any(project.usesPackage)) return RuleCheck([]);
    if (project.androidNativeSources
        .any((s) => s.text.contains('FLAG_SECURE'))) {
      return RuleCheck([]);
    }
    for (final f in project.dartFiles) {
      if (f.source.contains('blockScreenCapture') ||
          f.source.contains('ScreenShield') ||
          f.source.contains('FLAG_SECURE')) {
        return RuleCheck([]);
      }
    }
    return RuleCheck([
      inFile(null, null, En.protectionRulesNoScreenCaptureProtectionFound,
          messageAr: Ar.protectionRulesNoScreenCaptureProtectionFound)
    ]);
  }
}

class ObfuscationBuildRule extends Rule {
  const ObfuscationBuildRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-P10',
        title: Bilingual(En.protectionRulesReleaseBuildsWithoutObfuscate,
            Ar.protectionRulesReleaseBuildsWithoutObfuscate),
        description: Bilingual(
            En.protectionRulesWithoutObfuscateClassAndMethodNamesInLibappSo,
            Ar.protectionRulesWithoutObfuscateClassAndMethodNamesInLibappSo),
        fix: Bilingual(
            En.protectionRulesBuildReleasesWithObfuscateSplitDebugInfoBuildSymbolsAndKeepThe,
            Ar.protectionRulesBuildReleasesWithObfuscateSplitDebugInfoBuildSymbolsAndKeepThe),
        severity: Severity.medium,
        masvs: ['MASVS-RESILIENCE-3'],
        maswe: ['MASWE-0059'],
        cwe: 'CWE-656',
        profiles: _r,
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final re = RegExp(r'flutter\s+build\s+(apk|appbundle|aab|ipa|ios)\b[^\n]*');
    final out = <Finding>[];
    var found = false;
    for (final s in project.buildScripts) {
      // Join shell line continuations so flags on the next line count.
      final text = s.text.replaceAll(RegExp(r'\\\r?\n\s*'), ' ');
      for (final m in re.allMatches(text)) {
        found = true;
        if (!m.group(0)!.contains('--obfuscate')) {
          final head = m.group(0)!;
          final key = head.length > 18 ? head.substring(0, 18) : head;
          final line = lineOfFirst(s.text, key) ?? lineAt(text, m.start);
          out.add(inFile(
              s.path,
              line,
              En.protectionRulesHasNoObfuscate(
                  value1: shorten(m.group(0)!.trim(), 70)),
              messageAr: Ar.protectionRulesHasNoObfuscate(
                  value1: shorten(m.group(0)!.trim(), 70))));
        }
      }
    }
    if (!found) {
      return RuleCheck.notApplicable(
          'No release build command found in CI files (see manual check AEG-M05)');
    }
    return RuleCheck(out);
  }
}

const protectionRules = <Rule>[
  RaspPresenceRule(),
  FreeRaspWiringRule(),
  FreeRaspConfigRule(),
  FreeRaspReactionRule(),
  AppCheckMissingRule(),
  AppCheckDebugProviderRule(),
  PinningRule(),
  LocalAuthRule(),
  ScreenProtectionRule(),
  ObfuscationBuildRule(),
];
