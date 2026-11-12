/// Rules for iOS configuration: Info.plist and entitlements.
library;

import '../l10n/messages.g.dart';

import '../model.dart';
import '../project.dart';
import '../util.dart';
import 'rule.dart';

const _all = {MasProfile.l1, MasProfile.l2, MasProfile.r};

Map<String, Object?>? _ats(Project p) {
  final ats = p.infoPlistData?['NSAppTransportSecurity'];
  return ats is Map<String, Object?> ? ats : null;
}

class AtsArbitraryLoadsRule extends Rule {
  const AtsArbitraryLoadsRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-I01',
        title: Bilingual(En.iosRulesAppTransportSecurityDisabledIos,
            Ar.iosRulesAppTransportSecurityDisabledIos),
        description: Bilingual(
            En.iosRulesNsallowsarbitraryloadsTurnsOffAtsSoTheAppAccepts,
            Ar.iosRulesNsallowsarbitraryloadsTurnsOffAtsSoTheAppAccepts),
        fix: Bilingual(
            En.iosRulesRemoveNsallowsarbitraryloadsAndNsallowsarbitraryloadsinwebcontentAddANarrowNsexceptiondomains,
            Ar.iosRulesRemoveNsallowsarbitraryloadsAndNsallowsarbitraryloadsinwebcontentAddANarrowNsexceptiondomains),
        severity: Severity.high,
        masvs: ['MASVS-NETWORK-1'],
        maswe: ['MASWE-0026'],
        cwe: 'CWE-319',
        profiles: _all,
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final f = project.infoPlist;
    if (f == null || project.infoPlistData == null) {
      return RuleCheck.notApplicable('No ios/Runner/Info.plist');
    }
    final ats = _ats(project);
    if (ats == null) return RuleCheck([]);
    final out = <Finding>[];
    for (final key in const [
      'NSAllowsArbitraryLoads',
      'NSAllowsArbitraryLoadsInWebContent',
      'NSAllowsArbitraryLoadsForMedia'
    ]) {
      if (ats[key] == true) {
        out.add(inFile(
            f.path, lineOfFirst(f.text, key), En.iosRulesIsTrue(key: key),
            messageAr: Ar.iosRulesIsTrue(key: key)));
      }
    }
    return RuleCheck(out);
  }
}

class AtsExceptionsRule extends Rule {
  const AtsExceptionsRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-I02',
        title: Bilingual(En.iosRulesInsecureAtsExceptionDomain,
            Ar.iosRulesInsecureAtsExceptionDomain),
        description: Bilingual(En.iosRulesAnAtsExceptionAllowsHttpOrTlsBelow,
            Ar.iosRulesAnAtsExceptionAllowsHttpOrTlsBelow),
        fix: Bilingual(En.iosRulesServeTheDomainOverHttpsWithTls12,
            Ar.iosRulesServeTheDomainOverHttpsWithTls12),
        severity: Severity.medium,
        masvs: ['MASVS-NETWORK-1'],
        maswe: ['MASWE-0026'],
        cwe: 'CWE-326',
        profiles: _all,
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final f = project.infoPlist;
    if (f == null || project.infoPlistData == null) {
      return RuleCheck.notApplicable();
    }
    final domains = _ats(project)?['NSExceptionDomains'];
    if (domains is! Map<String, Object?>) return RuleCheck([]);
    final out = <Finding>[];
    domains.forEach((domain, cfg) {
      if (cfg is! Map<String, Object?>) return;
      if (const {'localhost', '127.0.0.1'}.contains(domain)) return;
      if (cfg['NSExceptionAllowsInsecureHTTPLoads'] == true ||
          cfg['NSTemporaryExceptionAllowsInsecureHTTPLoads'] == true) {
        out.add(inFile(f.path, lineOfFirst(f.text, domain),
            En.iosRulesAllowsInsecureHttpLoads(domain: domain),
            messageAr: Ar.iosRulesAllowsInsecureHttpLoads(domain: domain)));
      }
      final tls = (cfg['NSExceptionMinimumTLSVersion'] ??
              cfg['NSTemporaryExceptionMinimumTLSVersion'])
          ?.toString();
      if (tls == 'TLSv1.0' || tls == 'TLSv1.1') {
        out.add(inFile(f.path, lineOfFirst(f.text, domain),
            En.iosRulesAllows(domain: domain, tls: tls),
            messageAr: Ar.iosRulesAllows(domain: domain, tls: tls)));
      }
    });
    return RuleCheck(out);
  }
}

class GetTaskAllowRule extends Rule {
  const GetTaskAllowRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-I03',
        title: Bilingual(En.iosRulesDebuggingEntitlementEnabledIos,
            Ar.iosRulesDebuggingEntitlementEnabledIos),
        description: Bilingual(
            En.iosRulesGetTaskAllowLetsDebuggersAttachToTheAppProcess,
            Ar.iosRulesGetTaskAllowLetsDebuggersAttachToTheAppProcess),
        fix: Bilingual(En.iosRulesRemoveGetTaskAllowFromTheReleaseEntitlements,
            Ar.iosRulesRemoveGetTaskAllowFromTheReleaseEntitlements),
        severity: Severity.high,
        masvs: ['MASVS-RESILIENCE-4'],
        maswe: ['MASWE-0063'],
        cwe: 'CWE-489',
        profiles: _all,
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    if (project.ipa == null && !project.hasIos) {
      return RuleCheck.notApplicable();
    }
    if (project.ipa != null && project.entitlements.isEmpty) {
      return RuleCheck.incompleteLocalized(
          En.ipaEntitlementsUnreadable, Ar.ipaEntitlementsUnreadable);
    }
    if (project.entitlements.isEmpty) {
      return RuleCheck.notApplicable('No entitlements file');
    }
    final out = <Finding>[];
    project.entitlements.forEach((path, data) {
      if (project.ipa == null && path.toLowerCase().contains('debug')) return;
      if (data['get-task-allow'] == true) {
        out.add(inFile(path, null, En.iosRulesGetTaskAllowIsTrueIn(path: path),
            messageAr: Ar.iosRulesGetTaskAllowIsTrueIn(path: path)));
      }
    });
    if (project.ipa?.machO.any((slice) => slice.entitlements == null) == true) {
      return RuleCheck.incompleteLocalized(En.ipaEntitlementSlicesUnreadable,
          Ar.ipaEntitlementSlicesUnreadable, out);
    }
    return RuleCheck(out);
  }
}

class FileSharingRule extends Rule {
  const FileSharingRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-I04',
        title: Bilingual(En.iosRulesDocumentsFolderExposedIos,
            Ar.iosRulesDocumentsFolderExposedIos),
        description: Bilingual(
            En.iosRulesUifilesharingenabledLssupportsopeningdocumentsinplaceExposeTheAppSDocumentsFolder,
            Ar.iosRulesUifilesharingenabledLssupportsopeningdocumentsinplaceExposeTheAppSDocumentsFolder),
        fix: Bilingual(En.iosRulesDisableThemUnlessSharingIsAFeatureAnd,
            Ar.iosRulesDisableThemUnlessSharingIsAFeatureAnd),
        severity: Severity.low,
        l2Severity: Severity.medium,
        masvs: ['MASVS-STORAGE-2'],
        maswe: ['MASWE-0002'],
        cwe: 'CWE-552',
        profiles: _all,
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final f = project.infoPlist;
    final data = project.infoPlistData;
    if (f == null || data == null) return RuleCheck.notApplicable();
    final out = <Finding>[];
    for (final key in const [
      'UIFileSharingEnabled',
      'LSSupportsOpeningDocumentsInPlace'
    ]) {
      if (data[key] == true) {
        out.add(inFile(
            f.path, lineOfFirst(f.text, key), En.iosRulesIsTrue2(key: key),
            messageAr: Ar.iosRulesIsTrue2(key: key)));
      }
    }
    return RuleCheck(out);
  }
}

const iosRules = <Rule>[
  AtsArbitraryLoadsRule(),
  AtsExceptionsRule(),
  GetTaskAllowRule(),
  FileSharingRule(),
];
