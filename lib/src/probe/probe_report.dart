/// Renders a [ProbeReport] for the console, en/ar (doc/plans/probe.md §3).
library;

import '../l10n/messages.g.dart';

import 'probe_model.dart';


List<String> probeApkIdentityLines(ProbeReport report, String lang) {
  final identity = report.apkIdentity;
  if (identity == null) return const [];
  final signers = identity.signerSha256.join(', ');
  return [
    L10n(lang).probeReportVerifiedApkSignerSha256(signers: signers),
    if (identity.controlApks.isNotEmpty)
      L10n(lang).probeReportControlApks(value1: identity.controlApks.join(', ')),
    if (identity.rootedApks.isNotEmpty)
      L10n(lang).probeReportRootedApks(value1: identity.rootedApks.join(', ')),
    if (identity.expectedSignerSha256 != null)
      L10n(lang).probeReportTheSignerMatchedTheExpectedFingerprint
    else
      L10n(lang).probeReportNoExpectedSignerFingerprintWasSupplied,
    L10n(lang).probeReportTheInstallableFilesWereSuppliedForThisAab,
  ];
}

/// Marks for operation outcomes, process observations and inconclusive checks.
String probeMark(ProbeStatus s) => switch (s) {
      ProbeStatus.blocked => '✅',
      ProbeStatus.notBlocked => '❌',
      ProbeStatus.inconclusive => '⏸️ ',
    };

/// The check's title in [lang].
String probeCheckTitle(ProbeCheck c, String lang) {
  if (lang != 'ar') return c.title;
  return switch (c.id) {
    'baseline' => Ar.checkBaseline,
    'jailbreak' => Ar.checkJailbreak,
    'ios-debugger' => Ar.checkIosDebugger,
    'ios-hooking' => Ar.checkIosHooking,
    'ios-repackage' => Ar.checkIosRepackage,
    'root' => Ar.checkRoot,
    'debugger' => Ar.checkDebugger,
    'hooking' => Ar.checkHooking,
    'repackage' => Ar.checkRepackage,
    _ => c.title,
  };
}

String probeResultMark(ProbeResult r) => r.partialStatus == null ? probeMark(r.status) : '🧪';

String probeResultTitle(ProbeResult r, String lang) => r.partialStatus == null
    ? probeCheckTitle(r.check, lang)
    : r.check.id == 'jailbreak'
        ? L10n(lang).probeReportJailbreakFileIndicatorsPartialSimulatorTest
        : L10n(lang).probeReportAdHocSigningMetadataChangePartialSimulatorTest;

String? probeNote(ProbeResult r, String lang) => lang == 'ar' ? r.noteAr ?? r.note : r.note;

/// What was observed, in [lang].
String probeEvidence(ProbeResult r, String lang) {
  if (r.partialStatus != null) {
    final label = switch (r.partialStatus!) {
      ProbeStatus.blocked => L10n(lang).probeReportPartialObservationAppReacted,
      ProbeStatus.notBlocked => L10n(lang).probeReportPartialObservationNoProcessBlockObserved,
      ProbeStatus.inconclusive => L10n(lang).probeReportPartialObservationInconclusive,
    };
    return '$label. ${lang == 'ar' ? r.evidenceAr ?? r.evidence : r.evidence}';
  }
  if (lang == 'ar' && r.evidenceAr != null) return r.evidenceAr!;
  if (lang != 'ar' || r.check.id == 'jailbreak' || r.check.id.startsWith('ios-')) return r.evidence;
  if (r.processOnly) {
    return r.status == ProbeStatus.blocked
        ? Ar.androidProcessExit
        : Ar.androidProcessContinued;
  }
  return switch (r.status) {
    ProbeStatus.blocked => Ar.appBlocked,
    ProbeStatus.notBlocked => r.check.id == 'baseline' ? Ar.appAlive : Ar.appOperationContinued,
    ProbeStatus.inconclusive => Ar.appUnknown,
  };
}

/// [resilienceProfile] is whether the active profile includes MAS-R; when it
/// doesn't, a gap is informational rather than a failure.
String renderProbe(ProbeReport r,
    {String lang = 'en', required bool resilienceProfile}) {
  final b = StringBuffer();
  final ios = r.platform != 'android';
  final appName = r.app.split(RegExp(r'[\\/]')).last;
  b.writeln(L10n(lang).probeReportResilienceProbe(appName: appName));
  for (final line in probeApkIdentityLines(r, lang)) {
    b.writeln('  $line');
  }

  if (r.emulatorError != null) {
    b.writeln('  ⏸️  ${L10n(lang).probeReportTheEmulatorOrToolsCouldNotRun}');
    b.writeln('     ${r.emulatorError}');
    b.writeln('');
    b.writeln(L10n(lang).probeReportNothingWasProbedCheckThatAegisSetupFinished);
    return b.toString();
  }

  final baseline = r.results.firstWhere((x) => x.check.id == 'baseline',
      orElse: () => ProbeResult(checkById('baseline'), ProbeStatus.inconclusive));
  if (ios && !r.baselineAlive) {
    b.writeln(L10n(lang).probeReportTheIosControlProcessDidNotStayAlive);
    if (r.baselineNote != null) b.writeln(r.baselineNoteOf(lang));
    return b.toString();
  }
  if (!r.baselineAlive) {
    b.writeln('  ⏸️  ${L10n(lang).probeReportBaselineTheAppDidNotStayAliveOn}');
    if (r.baselineNote != null && r.baselineNote!.trim().isNotEmpty) {
      b.writeln(L10n(lang).probeReportLastLogcatLines);
      for (final line in r.baselineNoteOf(lang)!.split('\n')) {
        b.writeln('       $line');
      }
    }
    for (final x in r.scored) {
      b.writeln('  ⏸️  ${probeResultTitle(x, lang)} — ${x.note ?? probeEvidence(x, lang)}');
    }
    b.writeln('');
    b.writeln(L10n(lang).probeReportInconclusiveARaspThatRefusesToRunOn);
    return b.toString();
  }

  b.writeln('  ✅ ${probeCheckTitle(baseline.check, lang)}  ${probeEvidence(baseline, lang)}');
  if (baseline.note != null) b.writeln('       ${probeNote(baseline, lang)}');
  final w = r.scored
      .map((x) => probeResultTitle(x, lang).length)
      .fold(0, (a, b) => a > b ? a : b);
  for (final x in r.scored) {
    final tag = [x.check.masvs, x.check.mastg].whereType<String>().join(' · ');
    b.writeln('  ${probeResultMark(x)} ${probeResultTitle(x, lang).padRight(w)}  ${probeEvidence(x, lang).padRight(26)}  $tag');
    if (probeNote(x, lang) != null) b.writeln('       ${probeNote(x, lang)}');
  }

  b.writeln('');
  final reacted = r.blocked.length;
  final gaps = r.notBlocked.length;
  final unknown = r.inconclusive.length;
  final partial = r.scored.where((x) => x.partialStatus != null).length;
  if (partial > 0) { b.writeln(L10n(lang).probeReportPartialSimulatorChecksFullIosConditionsRemain(partial: partial)); }
  b.writeln(L10n(lang).probeReportReactedNoBlockObservedInconclusive(reacted: reacted, gaps: gaps, unknown: unknown));
  if (gaps > 0) {
    b.writeln(resilienceProfile
        ? L10n(lang).probeReportTheProbeObservedContinuedExecutionInConditionS(gaps: gaps)
        : L10n(lang).probeReportTheProbeObservedContinuedExecutionInConditionS2(gaps: gaps));
  }

  b.writeln('');
  b.writeln(L10n(lang).probeReportNotes);
  b.writeln(L10n(lang).probeReportAutomaticObservationsCoverProcessBehaviorAppEvents);
  if (!ios) {
    b.writeln(L10n(lang).probeReportThisShowsWhatHappenedOnThisEmulator);
  }
  return b.toString();
}

/// Exit code 2 when an applicable check is incomplete, 1 when a resilience profile
/// has a real gap, else 0.
int probeExitCode(ProbeReport r, {required bool resilienceProfile}) {
  if (r.emulatorError != null) return 2;
  if (!r.baselineAlive) return 2;
  if (r.scored.any((x) => x.applicable && x.status == ProbeStatus.inconclusive) ||
      r.scored.every((x) => !x.applicable)) {
    return 2;
  }
  if (resilienceProfile && r.notBlocked.isNotEmpty) return 1;
  return 0;
}
