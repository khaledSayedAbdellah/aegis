/// OWASP MASVS v2 controls, used for coverage reporting.
library;

import 'l10n/messages.g.dart';

import 'model.dart';

class MasvsControl {
  const MasvsControl(this.id, this.text, {this.resilienceOnly = false});

  final String id;
  final Bilingual text;

  /// Controls that only make sense when the MAS-R profile is selected.
  final bool resilienceOnly;

  String get category => id.split('-')[1];
}

const List<MasvsControl> masvsControls = [
  MasvsControl(
      'MASVS-STORAGE-1',
      Bilingual(En.masvsTheAppSecurelyStoresSensitiveData,
          Ar.masvsTheAppSecurelyStoresSensitiveData)),
  MasvsControl(
      'MASVS-STORAGE-2',
      Bilingual(En.masvsTheAppPreventsLeakageOfSensitiveData,
          Ar.masvsTheAppPreventsLeakageOfSensitiveData)),
  MasvsControl(
      'MASVS-CRYPTO-1',
      Bilingual(En.masvsTheAppEmploysCurrentStrongCryptography,
          Ar.masvsTheAppEmploysCurrentStrongCryptography)),
  MasvsControl(
      'MASVS-CRYPTO-2',
      Bilingual(En.masvsTheAppPerformsKeyManagementAccordingToBest,
          Ar.masvsTheAppPerformsKeyManagementAccordingToBest)),
  MasvsControl(
      'MASVS-AUTH-1',
      Bilingual(En.masvsTheAppUsesSecureAuthenticationAndAuthorizationProtocols,
          Ar.masvsTheAppUsesSecureAuthenticationAndAuthorizationProtocols)),
  MasvsControl(
      'MASVS-AUTH-2',
      Bilingual(En.masvsTheAppPerformsLocalAuthenticationSecurely,
          Ar.masvsTheAppPerformsLocalAuthenticationSecurely)),
  MasvsControl(
      'MASVS-AUTH-3',
      Bilingual(
          En.masvsTheAppSecuresSensitiveOperationsWithAdditionalAuthentication,
          Ar.masvsTheAppSecuresSensitiveOperationsWithAdditionalAuthentication)),
  MasvsControl(
      'MASVS-NETWORK-1',
      Bilingual(En.masvsTheAppSecuresAllNetworkTraffic,
          Ar.masvsTheAppSecuresAllNetworkTraffic)),
  MasvsControl(
      'MASVS-NETWORK-2',
      Bilingual(En.masvsTheAppPerformsIdentityPinningForEndpointsUnder,
          Ar.masvsTheAppPerformsIdentityPinningForEndpointsUnder)),
  MasvsControl(
      'MASVS-PLATFORM-1',
      Bilingual(En.masvsTheAppUsesIpcMechanismsSecurely,
          Ar.masvsTheAppUsesIpcMechanismsSecurely)),
  MasvsControl(
      'MASVS-PLATFORM-2',
      Bilingual(En.masvsTheAppUsesWebviewsSecurely,
          Ar.masvsTheAppUsesWebviewsSecurely)),
  MasvsControl(
      'MASVS-PLATFORM-3',
      Bilingual(En.masvsTheAppUsesTheUserInterfaceSecurely,
          Ar.masvsTheAppUsesTheUserInterfaceSecurely)),
  MasvsControl(
      'MASVS-CODE-1',
      Bilingual(En.masvsTheAppRequiresAnUpToDatePlatformVersion,
          Ar.masvsTheAppRequiresAnUpToDatePlatformVersion)),
  MasvsControl(
      'MASVS-CODE-2',
      Bilingual(En.masvsTheAppHasAMechanismForEnforcingApp,
          Ar.masvsTheAppHasAMechanismForEnforcingApp)),
  MasvsControl(
      'MASVS-CODE-3',
      Bilingual(En.masvsTheAppOnlyUsesSoftwareComponentsWithoutKnown,
          Ar.masvsTheAppOnlyUsesSoftwareComponentsWithoutKnown)),
  MasvsControl(
      'MASVS-CODE-4',
      Bilingual(En.masvsTheAppValidatesAndSanitizesAllUntrustedInputs,
          Ar.masvsTheAppValidatesAndSanitizesAllUntrustedInputs)),
  MasvsControl(
      'MASVS-RESILIENCE-1',
      Bilingual(En.masvsTheAppValidatesTheIntegrityOfThePlatform,
          Ar.masvsTheAppValidatesTheIntegrityOfThePlatform),
      resilienceOnly: true),
  MasvsControl(
      'MASVS-RESILIENCE-2',
      Bilingual(En.masvsTheAppImplementsAntiTamperingMechanisms,
          Ar.masvsTheAppImplementsAntiTamperingMechanisms),
      resilienceOnly: true),
  MasvsControl(
      'MASVS-RESILIENCE-3',
      Bilingual(En.masvsTheAppImplementsAntiStaticAnalysisMechanisms,
          Ar.masvsTheAppImplementsAntiStaticAnalysisMechanisms),
      resilienceOnly: true),
  MasvsControl(
      'MASVS-RESILIENCE-4',
      Bilingual(En.masvsTheAppImplementsAntiDynamicAnalysisTechniques,
          Ar.masvsTheAppImplementsAntiDynamicAnalysisTechniques),
      resilienceOnly: true),
  MasvsControl(
      'MASVS-PRIVACY-1',
      Bilingual(En.masvsTheAppMinimizesAccessToSensitiveDataAnd,
          Ar.masvsTheAppMinimizesAccessToSensitiveDataAnd)),
  MasvsControl(
      'MASVS-PRIVACY-2',
      Bilingual(En.masvsTheAppPreventsIdentificationOfTheUser,
          Ar.masvsTheAppPreventsIdentificationOfTheUser)),
  MasvsControl(
      'MASVS-PRIVACY-3',
      Bilingual(En.masvsTheAppIsTransparentAboutDataCollectionAnd,
          Ar.masvsTheAppIsTransparentAboutDataCollectionAnd)),
  MasvsControl(
      'MASVS-PRIVACY-4',
      Bilingual(En.masvsTheAppOffersUserControlOverTheirData,
          Ar.masvsTheAppOffersUserControlOverTheirData)),
];

/// Category display names.
const Map<String, Bilingual> masvsCategories = {
  'STORAGE': Bilingual(En.masvsStorage, Ar.masvsStorage),
  'CRYPTO': Bilingual(En.masvsCryptography, Ar.masvsCryptography),
  'AUTH': Bilingual(En.masvsAuthentication, Ar.masvsAuthentication),
  'NETWORK': Bilingual(En.masvsNetwork, Ar.masvsNetwork),
  'PLATFORM': Bilingual(En.masvsPlatform, Ar.masvsPlatform),
  'CODE': Bilingual(En.masvsCodeDependencies, Ar.masvsCodeDependencies),
  'RESILIENCE': Bilingual(En.masvsResilience, Ar.masvsResilience),
  'PRIVACY': Bilingual(En.masvsPrivacy, Ar.masvsPrivacy),
};

/// Things no static tool can verify. Listed in every report so a clean score
/// is never mistaken for a clean app.
class ManualCheck {
  const ManualCheck(this.id, this.masvs, this.text,
      {this.profiles = const {MasProfile.l1}});
  final String id;
  final String masvs;
  final Bilingual text;
  final Set<MasProfile> profiles;
}

const List<ManualCheck> manualChecks = [
  ManualCheck(
      'AEG-M01',
      'MASVS-AUTH-1',
      Bilingual(En.masvsTheBackendEnforcesAuthorizationOnEveryEndpointNever,
          Ar.masvsTheBackendEnforcesAuthorizationOnEveryEndpointNever)),
  ManualCheck(
      'AEG-M02',
      'MASVS-AUTH-1',
      Bilingual(En.masvsSessionsTokensExpireAndAreRevokedOnLogoutOn,
          Ar.masvsSessionsTokensExpireAndAreRevokedOnLogoutOn)),
  ManualCheck(
      'AEG-M03',
      'MASVS-RESILIENCE-2',
      Bilingual(En.masvsAttestationVerdictsPlayIntegrityAppAttest,
          Ar.masvsAttestationVerdictsPlayIntegrityAppAttest),
      profiles: {MasProfile.l2, MasProfile.r}),
  ManualCheck(
      'AEG-M04',
      'MASVS-RESILIENCE-2',
      Bilingual(En.masvsThePlayAppSigningCertificateHashFromPlay,
          Ar.masvsThePlayAppSigningCertificateHashFromPlay),
      profiles: {MasProfile.r}),
  ManualCheck(
      'AEG-M05',
      'MASVS-RESILIENCE-3',
      Bilingual(En.masvsTheShippedBinaryIsReallyObfuscatedVerifyThe,
          Ar.masvsTheShippedBinaryIsReallyObfuscatedVerifyThe),
      profiles: {MasProfile.r}),
  ManualCheck(
      'AEG-M06',
      'MASVS-PRIVACY-3',
      Bilingual(En.masvsStorePrivacyLabelsDataSafetyFormMatch,
          Ar.masvsStorePrivacyLabelsDataSafetyFormMatch)),
  ManualCheck(
      'AEG-M07',
      'MASVS-CODE-2',
      Bilingual(En.masvsAForcedUpdateMechanismExistsForCriticalSecurityFixes,
          Ar.masvsAForcedUpdateMechanismExistsForCriticalSecurityFixes),
      profiles: {MasProfile.l2}),
  ManualCheck(
      'AEG-M08',
      'MASVS-CODE-4',
      Bilingual(En.masvsDeepLinksAndPushPayloadsAreValidatedBefore,
          Ar.masvsDeepLinksAndPushPayloadsAreValidatedBefore)),
];
