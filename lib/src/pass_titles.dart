/// Titles shown when a rule passes.
///
/// Rule titles describe the problem ("Android app is debuggable"), which reads
/// wrong next to a check mark. These describe the healthy state instead.
library;

import 'l10n/messages.g.dart';

import 'model.dart';

const Map<String, Bilingual> passTitles = {
  // Protection correctness
  'AEG-P01': Bilingual(En.passTitlesRuntimeProtectionRaspIsPresent,
      Ar.passTitlesRuntimeProtectionRaspIsPresent),
  'AEG-P02': Bilingual(En.passTitlesFreeraspStartupAndListenerCallsFoundInMain,
      Ar.passTitlesFreeraspStartupAndListenerCallsFoundInMain),
  'AEG-P03': Bilingual(En.passTitlesFreeraspConfigurationMatchesTheApp,
      Ar.passTitlesFreeraspConfigurationMatchesTheApp),
  'AEG-P04': Bilingual(En.passTitlesDetectedThreatsTriggerARealReaction,
      Ar.passTitlesDetectedThreatsTriggerARealReaction),
  'AEG-P05': Bilingual(En.passTitlesFirebaseIsProtectedByAppCheck,
      Ar.passTitlesFirebaseIsProtectedByAppCheck),
  'AEG-P06': Bilingual(En.passTitlesAppCheckDebugProviderIsLimitedToDebug,
      Ar.passTitlesAppCheckDebugProviderIsLimitedToDebug),
  'AEG-P07': Bilingual(En.passTitlesCertificatePinningIsInPlace,
      Ar.passTitlesCertificatePinningIsInPlace),
  'AEG-P08': Bilingual(En.passTitlesBiometricsAreBoundToAKey,
      Ar.passTitlesBiometricsAreBoundToAKey),
  'AEG-P09': Bilingual(En.passTitlesScreensAreProtectedFromCapture,
      Ar.passTitlesScreensAreProtectedFromCapture),
  'AEG-P10': Bilingual(En.passTitlesReleaseBuildsUseObfuscate,
      Ar.passTitlesReleaseBuildsUseObfuscate),
  // Android
  'AEG-A01': Bilingual(En.passTitlesAndroidAppIsNotDebuggable,
      Ar.passTitlesAndroidAppIsNotDebuggable),
  'AEG-A02': Bilingual(En.passTitlesAppDataBackupIsRestricted,
      Ar.passTitlesAppDataBackupIsRestricted),
  'AEG-A03': Bilingual(En.passTitlesManifestDoesNotAllowCleartextTraffic,
      Ar.passTitlesManifestDoesNotAllowCleartextTraffic),
  'AEG-A04': Bilingual(En.passTitlesNetworkSecurityConfigIsStrict,
      Ar.passTitlesNetworkSecurityConfigIsStrict),
  'AEG-A05': Bilingual(En.passTitlesCertificatePinsAreNotExpired,
      Ar.passTitlesCertificatePinsAreNotExpired),
  'AEG-A06': Bilingual(En.passTitlesExportedComponentsAreProtected,
      Ar.passTitlesExportedComponentsAreProtected),
  'AEG-A07': Bilingual(En.passTitlesR8ShrinkingObfuscationIsEnabled,
      Ar.passTitlesR8ShrinkingObfuscationIsEnabled),
  'AEG-A08': Bilingual(En.passTitlesReleaseBuildIsNotSignedWithTheDebug,
      Ar.passTitlesReleaseBuildIsNotSignedWithTheDebug),
  'AEG-A09': Bilingual(En.passTitlesSigningSecretsAreNotExposed,
      Ar.passTitlesSigningSecretsAreNotExposed),
  'AEG-A10': Bilingual(
      En.passTitlesMinsdkIs24OrHigher, Ar.passTitlesMinsdkIs24OrHigher),
  // iOS
  'AEG-I01': Bilingual(En.passTitlesAppTransportSecurityIsEnabled,
      Ar.passTitlesAppTransportSecurityIsEnabled),
  'AEG-I02': Bilingual(
      En.passTitlesAtsExceptionsAreSafe, Ar.passTitlesAtsExceptionsAreSafe),
  'AEG-I03': Bilingual(En.passTitlesNoDebuggingEntitlementInRelease,
      Ar.passTitlesNoDebuggingEntitlementInRelease),
  'AEG-I04': Bilingual(En.passTitlesDocumentsFolderIsNotExposed,
      Ar.passTitlesDocumentsFolderIsNotExposed),
  // Dart code
  'AEG-D01': Bilingual(En.passTitlesNoHardcodedSecretsInDartCode,
      Ar.passTitlesNoHardcodedSecretsInDartCode),
  'AEG-D02': Bilingual(En.passTitlesNoCleartextHttpUrlsInCode,
      Ar.passTitlesNoCleartextHttpUrlsInCode),
  'AEG-D03': Bilingual(En.passTitlesTlsCertificatesAreValidated,
      Ar.passTitlesTlsCertificatesAreValidated),
  'AEG-D04': Bilingual(En.passTitlesSensitiveDataIsNotKeptInPlainStorage,
      Ar.passTitlesSensitiveDataIsNotKeptInPlainStorage),
  'AEG-D05': Bilingual(
      En.passTitlesNoWeakCryptography, Ar.passTitlesNoWeakCryptography),
  'AEG-D06': Bilingual(En.passTitlesNoHardcodedEncryptionKeysOrIvs,
      Ar.passTitlesNoHardcodedEncryptionKeysOrIvs),
  'AEG-D07': Bilingual(En.passTitlesSecurityValuesUseASecureRandomGenerator,
      Ar.passTitlesSecurityValuesUseASecureRandomGenerator),
  'AEG-D08': Bilingual(
      En.passTitlesNoSensitiveDataInLogs, Ar.passTitlesNoSensitiveDataInLogs),
  'AEG-D09': Bilingual(En.passTitlesNoSecretFilesBundledAsAssets,
      Ar.passTitlesNoSecretFilesBundledAsAssets),
  'AEG-D10': Bilingual(
      En.passTitlesWebviewsAreLockedDown, Ar.passTitlesWebviewsAreLockedDown),
  // Dependencies
  'AEG-C01': Bilingual(En.passTitlesNoDependenciesWithKnownVulnerabilities,
      Ar.passTitlesNoDependenciesWithKnownVulnerabilities),
  'AEG-C02': Bilingual(
      En.passTitlesDependenciesArePinned, Ar.passTitlesDependenciesArePinned),
  // APK
  'AEG-B01': Bilingual(En.passTitlesTheApkIsAReleaseAotBuild,
      Ar.passTitlesTheApkIsAReleaseAotBuild),
  'AEG-B02': Bilingual(
      En.passTitlesTheApkIsNotDebuggable, Ar.passTitlesTheApkIsNotDebuggable),
  'AEG-B03': Bilingual(
      En.passTitlesFinalManifestKeepsBackupAndNetworkSettingsSafe,
      Ar.passTitlesFinalManifestKeepsBackupAndNetworkSettingsSafe),
  'AEG-B04': Bilingual(En.passTitlesLibrariesAddNoUnprotectedExportedComponents,
      Ar.passTitlesLibrariesAddNoUnprotectedExportedComponents),
  'AEG-B05': Bilingual(En.passTitlesNoSensitivePermissionsAddedByLibraries,
      Ar.passTitlesNoSensitivePermissionsAddedByLibraries),
  'AEG-B06': Bilingual(En.passTitlesNoSecretsFoundInsideTheApk,
      Ar.passTitlesNoSecretsFoundInsideTheApk),
  'AEG-B07': Bilingual(En.passTitlesTheShippedDartCodeIsObfuscated,
      Ar.passTitlesTheShippedDartCodeIsObfuscated),
  'AEG-B08': Bilingual(En.passTitlesNoSecretFilesInsideTheApk,
      Ar.passTitlesNoSecretFilesInsideTheApk),
  'AEG-B09': Bilingual(En.passTitlesTheApkIsSignedWithAReleaseCertificate,
      Ar.passTitlesTheApkIsSignedWithAReleaseCertificate),
  'AEG-B10': Bilingual(En.passTitlesFreeraspKnowsThisApkSCertificate,
      Ar.passTitlesFreeraspKnowsThisApkSCertificate),
  'AEG-B11': Bilingual(
      En.passTitlesApkSdkLevelsAreCurrent, Ar.passTitlesApkSdkLevelsAreCurrent),
};
