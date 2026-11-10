/// AEG-R01..R04: the resilience probe's results as ordinary rules, so they
/// count in the score, the baseline and fail_on like any other finding.
///
/// These rules do not inspect files. `aegis run --mode apk|aab` runs the
/// probe on the emulator first and hands its outcome to the audit
/// ([Project.probe]); each rule reads its own check from it. They only exist
/// in a run that tried the probe, and only count under a profile with MAS-R.
library;

import '../l10n/messages.g.dart';

import 'package:path/path.dart' as p;

import '../model.dart';
import '../probe/probe_model.dart';
import '../probe/probe_report.dart' show probeSimulatorVerdict;
import '../project.dart';
import 'rule.dart';

const _r = {MasProfile.r};

const _fix = Bilingual(En.probeRulesAddRuntimeProtectionRaspThatReactsToThis, Ar.probeRulesAddRuntimeProtectionRaspThatReactsToThis);

const _processFinding = Bilingual(En.probeRulesNoProcessLevelBlockWasObservedUnderTheVerified, Ar.probeRulesNoProcessLevelBlockWasObservedUnderTheVerified);

/// One probe check as a rule.
class ProbeRule extends Rule {
  const ProbeRule(this.checkId, this.meta, this.message);

  /// The [ProbeCheck.id] this rule reports: root, hooking, debugger, repackage.
  final String checkId;

  @override
  final RuleMeta meta;

  /// The finding text when the app did not react. Kept free of timings and
  /// pids so its baseline fingerprint is stable.
  final Bilingual message;

  /// Keep Simulator findings explicitly scoped in every reporter, including
  /// the scored rule summary and SARIF, rather than using physical-iOS titles.
  RuleMeta reportMeta(ProbeReport? report) {
    if (report?.platform != 'ios-simulator' ||
        !['jailbreak', 'ios-repackage'].contains(checkId)) {
      return meta;
    }
    final jailbreak = checkId == 'jailbreak';
    return RuleMeta(
      id: meta.id,
      title: jailbreak
          ? const Bilingual(En.simulatorJailbreakGapTitle, Ar.simulatorJailbreakGapTitle)
          : const Bilingual(En.simulatorSigningGapTitle, Ar.simulatorSigningGapTitle),
      passTitleText: const Bilingual(En.probeReportPartialObservationAppReacted, Ar.probeReportPartialObservationAppReacted),
      description: jailbreak
          ? const Bilingual(En.simulatorJailbreakDescription, Ar.simulatorJailbreakDescription)
          : const Bilingual(En.simulatorSigningDescription, Ar.simulatorSigningDescription),
      fix: meta.fix, severity: meta.severity, l2Severity: meta.l2Severity,
      masvs: meta.masvs, maswe: meta.maswe, cwe: meta.cwe, profiles: meta.profiles,
    );
  }

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final outcome = project.probe;
    if (outcome == null) {
      return RuleCheck.notApplicable('The resilience probe did not run.');
    }
    final report = outcome.report;
    if (report == null) {
      final note = En.probeSkipped(reason: outcome.skipped);
      return outcome.requested ? RuleCheck.incompleteLocalized(note, Ar.probeSkipped(reason: outcome.skippedOf('ar'))) : RuleCheck.notApplicable(note);
    }
    if (report.emulatorError != null) {
      return RuleCheck.incompleteLocalized(En.probeFailed(reason: report.emulatorError), Ar.probeFailed(reason: report.emulatorError));
    }
    if (!report.baselineAlive) {
      return RuleCheck.incompleteLocalized(En.probeControlDead, Ar.probeControlDead);
    }
    ProbeResult? result;
    for (final r in report.results) {
      if (r.check.id == checkId) result = r;
    }
    if (result == null) {
      return RuleCheck.notApplicable('Not part of this probe run (--only).');
    }
    final r = result;
    if (!r.applicable) return RuleCheck.notApplicable(r.note);
    if (r.partialStatus != null) {
      final findings = <Finding>[];
      if (r.partialStatus == ProbeStatus.notBlocked) {
        final jailbreak = checkId == 'jailbreak';
        findings.add(inFile('${p.basename(report.app)}!/runtime', null,
            jailbreak ? En.simulatorJailbreakGapFinding : En.simulatorSigningGapFinding,
            messageAr: jailbreak ? Ar.simulatorJailbreakGapFinding : Ar.simulatorSigningGapFinding,
            snippet: r.evidence, snippetAr: r.evidenceAr));
      }
      // A concrete gap in the exercised scenario is a finding. Full condition
      // coverage remains incomplete, and no partial reaction grants a MASVS pass.
      // Coverage summaries must not hide a failed Simulator verdict behind
      // a limitations-only note. Findings/scoring and strict coverage stay intact.
      return RuleCheck.incompleteLocalized(
          '${probeSimulatorVerdict(r, 'en')} ${r.note ?? ''}'.trim(),
          '${probeSimulatorVerdict(r, 'ar')} ${r.noteAr ?? r.note ?? ''}'.trim(),
          findings);
    }
    return switch (r.status) {
      ProbeStatus.blocked => RuleCheck(const []),
      ProbeStatus.inconclusive => RuleCheck.incompleteLocalized(
          En.probeInconclusive(detail: r.note == null ? '' : ': ${r.note}'),
          Ar.probeInconclusive(detail: r.note == null ? '' : ': ${r.noteAr ?? r.note}')),
      // "<file>!/runtime": the baseline normalises the APK/AAB file name, so a
      // new build with another version in its name still matches.
      ProbeStatus.notBlocked => RuleCheck([
          inFile('${p.basename(report.app)}!/runtime', null,
              r.processOnly ? _processFinding.en : message.en,
              messageAr: r.processOnly ? _processFinding.ar : message.ar,
              snippet: r.evidence, snippetAr: r.evidenceAr),
        ]),
    };
  }
}

const probeRules = <Rule>[
  ProbeRule(
    'root',
    RuleMeta(
      id: 'AEG-R01',
      title: Bilingual(En.probeRulesTheAppContinuesUnderRoot, Ar.probeRulesTheAppContinuesUnderRoot),
      passTitleText: Bilingual(En.probeRulesTheAppReactedOnARootedDevice, Ar.probeRulesTheAppReactedOnARootedDevice),
      description: Bilingual(En.probeRulesAegisTestedTheAppUnderVerifiedRootAvailability, Ar.probeRulesAegisTestedTheAppUnderVerifiedRootAvailability),
      fix: _fix,
      severity: Severity.high,
      masvs: ['MASVS-RESILIENCE-1'],
      profiles: _r,
    ),
    Bilingual(En.probeRulesTheAppReportedThatTheTestedOperationProceeded, Ar.probeRulesTheAppReportedThatTheTestedOperationProceeded),
  ),
  ProbeRule(
    'hooking',
    RuleMeta(
      id: 'AEG-R02',
      title: Bilingual(En.probeRulesTheAppContinuesAfterFridaAttaches, Ar.probeRulesTheAppContinuesAfterFridaAttaches),
      passTitleText: Bilingual(En.probeRulesTheAppReactedToFrida, Ar.probeRulesTheAppReactedToFrida),
      description: Bilingual(En.probeRulesAegisAttachedFridaToTheRunningAppAnd, Ar.probeRulesAegisAttachedFridaToTheRunningAppAnd),
      fix: _fix,
      severity: Severity.high,
      masvs: ['MASVS-RESILIENCE-4'],
      profiles: _r,
    ),
    Bilingual(En.probeRulesTheAppReportedThatTheTestedOperationProceeded2, Ar.probeRulesTheAppReportedThatTheTestedOperationProceeded2),
  ),
  ProbeRule(
    'debugger',
    RuleMeta(
      id: 'AEG-R03',
      title: Bilingual(En.probeRulesTheAppContinuesWithADebuggerAttached, Ar.probeRulesTheAppContinuesWithADebuggerAttached),
      passTitleText: Bilingual(En.probeRulesTheAppReactedToADebugger, Ar.probeRulesTheAppReactedToADebugger),
      description: Bilingual(En.probeRulesAegisAttachedADebuggerAndObservedContinuedExecution, Ar.probeRulesAegisAttachedADebuggerAndObservedContinuedExecution),
      fix: _fix,
      severity: Severity.medium,
      masvs: ['MASVS-RESILIENCE-4'],
      profiles: _r,
    ),
    Bilingual(En.probeRulesTheAppReportedThatTheTestedOperationProceeded3, Ar.probeRulesTheAppReportedThatTheTestedOperationProceeded3),
  ),
  ProbeRule(
    'repackage',
    RuleMeta(
      id: 'AEG-R04',
      title: Bilingual(En.probeRulesAReSignedCopyOfTheAppContinuesRunning, Ar.probeRulesAReSignedCopyOfTheAppContinuesRunning),
      passTitleText: Bilingual(En.probeRulesAReSignedCopyOfTheAppWasRejected, Ar.probeRulesAReSignedCopyOfTheAppWasRejected),
      description: Bilingual(En.probeRulesAegisInstalledACopySignedWithADifferent, Ar.probeRulesAegisInstalledACopySignedWithADifferent),
      fix: _fix,
      severity: Severity.high,
      masvs: ['MASVS-RESILIENCE-2'],
      profiles: _r,
    ),
    Bilingual(En.probeRulesACopyReSignedWithAnotherKeyRanNormally, Ar.probeRulesACopyReSignedWithAnotherKeyRanNormally),
  ),
];

const _iosFix = Bilingual(En.probeRulesConfigureTheIosRuntimeProtectionToRestrictThe, Ar.probeRulesConfigureTheIosRuntimeProtectionToRestrictThe);

const iosProbeRules = <Rule>[
  ProbeRule(
    'jailbreak',
    RuleMeta(id: 'AEG-R05', title: Bilingual(En.probeRulesTheAppContinuesOnJailbrokenIos, Ar.probeRulesTheAppContinuesOnJailbrokenIos),
      passTitleText: Bilingual(En.probeRulesTheAppReactedOnJailbrokenIos, Ar.probeRulesTheAppReactedOnJailbrokenIos),
      description: Bilingual(En.probeRulesTheProbeVerifiedRootAccessOnTheSelected, Ar.probeRulesTheProbeVerifiedRootAccessOnTheSelected),
      fix: _iosFix, severity: Severity.high, masvs: ['MASVS-RESILIENCE-1'], profiles: _r),
    Bilingual(En.probeRulesTheAppReportedContinuedOperationOnJailbrokenIos, Ar.probeRulesTheAppReportedContinuedOperationOnJailbrokenIos),
  ),
  ProbeRule(
    'ios-hooking',
    RuleMeta(id: 'AEG-R06', title: Bilingual(En.probeRulesTheIosAppContinuesWithFridaAttached, Ar.probeRulesTheIosAppContinuesWithFridaAttached),
      passTitleText: Bilingual(En.probeRulesTheIosAppReactedToFrida, Ar.probeRulesTheIosAppReactedToFrida),
      description: Bilingual(En.probeRulesFridaExecutedAScriptInTheAuditedProcess, Ar.probeRulesFridaExecutedAScriptInTheAuditedProcess),
      fix: _iosFix, severity: Severity.high, masvs: ['MASVS-RESILIENCE-4'], profiles: _r),
    Bilingual(En.probeRulesTheIosAppReportedContinuedOperationAfterFrida, Ar.probeRulesTheIosAppReportedContinuedOperationAfterFrida),
  ),
  ProbeRule(
    'ios-debugger',
    RuleMeta(id: 'AEG-R07', title: Bilingual(En.probeRulesTheIosAppContinuesWithADebuggerAttached, Ar.probeRulesTheIosAppContinuesWithADebuggerAttached),
      passTitleText: Bilingual(En.probeRulesTheIosAppReactedToTheDebugger, Ar.probeRulesTheIosAppReactedToTheDebugger),
      description: Bilingual(En.probeRulesLldbAttachedToTheAuditedProcessAndThe, Ar.probeRulesLldbAttachedToTheAuditedProcessAndThe),
      fix: _iosFix, severity: Severity.medium, masvs: ['MASVS-RESILIENCE-4'], profiles: _r),
    Bilingual(En.probeRulesTheIosAppReportedContinuedOperationAfterLldb, Ar.probeRulesTheIosAppReportedContinuedOperationAfterLldb),
  ),
  ProbeRule(
    'ios-repackage',
    RuleMeta(id: 'AEG-R08', title: Bilingual(En.probeRulesTheIosAppContinuesWithADifferentSigning, Ar.probeRulesTheIosAppContinuesWithADifferentSigning),
      passTitleText: Bilingual(En.probeRulesTheIosAppReactedToTheSigningChange, Ar.probeRulesTheIosAppReactedToTheSigningChange),
      description: Bilingual(En.probeRulesTheSameIosPayloadRanWithADifferent, Ar.probeRulesTheSameIosPayloadRanWithADifferent),
      fix: _iosFix, severity: Severity.high, masvs: ['MASVS-RESILIENCE-2'], profiles: _r),
    Bilingual(En.probeRulesTheIosAppReportedContinuedOperationAfterReSigning, Ar.probeRulesTheIosAppReportedContinuedOperationAfterReSigning),
  ),
];
