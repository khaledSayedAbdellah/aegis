/// Checks that require the packaged iOS application.
library;

import '../l10n/messages.g.dart';

import '../model.dart';
import '../project.dart';
import 'rule.dart';

const _all = {MasProfile.l1, MasProfile.l2, MasProfile.r};

class IpaSignatureRule extends Rule {
  const IpaSignatureRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-I05',
        title: Bilingual(En.ipaRulesIpaCodeSignatureFailedVerification, Ar.ipaRulesIpaCodeSignatureFailedVerification),
        passTitleText: Bilingual(En.ipaRulesIpaCodeSignatureVerified, Ar.ipaRulesIpaCodeSignatureVerified),
        description: Bilingual(En.ipaRulesTheReleaseApplicationAndItsNestedCodeShould, Ar.ipaRulesTheReleaseApplicationAndItsNestedCodeShould),
        fix: Bilingual(En.ipaRulesExportTheIntendedReleaseFromXcodeWithValid, Ar.ipaRulesExportTheIntendedReleaseFromXcodeWithValid),
        severity: Severity.high,
        profiles: _all,
        masvs: ['MASVS-RESILIENCE-2'],
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final ipa = project.ipa!;
    final signature = project.iosSignature!;
    if (signature.valid == null) {
      return RuleCheck.incompleteLocalized(signature.evidence, signature.evidenceAr);
    }
    if (signature.valid == true) return RuleCheck(const []);
    return RuleCheck([
      inFile('${ipa.label}!/${ipa.appPath}/${ipa.executable}', null,
          En.ipaRulesAppleCodesignRejectedThePackagedApp,
          messageAr: Ar.ipaRulesAppleCodesignRejectedThePackagedApp,
          snippet: signature.evidence, snippetAr: signature.evidenceAr),
    ]);
  }
}

class IpaBundledSecretsRule extends Rule {
  const IpaBundledSecretsRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-I06',
        title: Bilingual(En.ipaRulesPotentialSecretFilePackagedInIpa, Ar.ipaRulesPotentialSecretFilePackagedInIpa),
        passTitleText: Bilingual(En.ipaRulesPackagedResourcesPassedTheSecretFileCheck, Ar.ipaRulesPackagedResourcesPassedTheSecretFileCheck),
        description: Bilingual(En.ipaRulesAnyoneWithTheIpaCanReadItsPackaged, Ar.ipaRulesAnyoneWithTheIpaCanReadItsPackaged),
        fix: Bilingual(En.ipaRulesRemovePrivateKeysAndSecretConfigurationFilesFrom, Ar.ipaRulesRemovePrivateKeysAndSecretConfigurationFilesFrom),
        severity: Severity.high,
        profiles: _all,
        masvs: ['MASVS-STORAGE-1'],
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final ipa = project.ipa!;
    final secret = RegExp(
        r'(^|/)(\.env(?:\.[^/]+)?|[^/]*service[-_]?account[^/]*\.json|[^/]+\.(?:p12|pfx|key))$',
        caseSensitive: false);
    return RuleCheck([
      for (final path in ipa.archive.entries.keys)
        if (path.startsWith('${ipa.appPath}/') && secret.hasMatch(path))
          inFile(
              '${ipa.label}!/$path', null, En.ipaRulesPotentialSecretFileIsPackaged,
              messageAr: Ar.ipaRulesPotentialSecretFileIsPackaged),
    ]);
  }
}

const ipaRules = <Rule>[IpaSignatureRule(), IpaBundledSecretsRule()];
