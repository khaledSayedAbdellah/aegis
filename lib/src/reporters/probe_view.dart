/// The resilience-probe section shared by the report formats: what ran, what
/// each check observed, and why something could not be judged.
library;

import '../l10n/messages.g.dart';

import '../engine.dart';
import '../probe/probe_model.dart';
import '../probe/probe_report.dart';

/// The rule that reports each probe check.
const probeRuleIds = {
  'root': 'AEG-R01',
  'hooking': 'AEG-R02',
  'debugger': 'AEG-R03',
  'repackage': 'AEG-R04',
  'jailbreak': 'AEG-R05',
  'ios-hooking': 'AEG-R06',
  'ios-debugger': 'AEG-R07',
  'ios-repackage': 'AEG-R08',
};

class ProbeLine {
  ProbeLine(this.status, this.mark, this.title, this.evidence, this.tag, this.ruleId,
      {this.note});
  final ProbeStatus status;
  final String mark;
  final String title;
  final String evidence;

  /// `MASVS-RESILIENCE-1 · MASTG-TEST-0048`.
  final String tag;
  final String? ruleId;
  final String? note;
}

class ProbeView {
  ProbeView({
    required this.heading,
    required this.lines,
    required this.caveats,
    this.message,
    this.details = const [],
    this.baseline,
  });

  final String heading;

  /// Set when nothing could be judged (skipped, emulator error, the app did
  /// not stay alive on a clean emulator); [lines] is then empty.
  final String? message;

  /// Extra lines under [message] (the last logcat lines of a dead baseline).
  final List<String> details;

  /// The baseline line when the probe ran.
  final String? baseline;
  final List<ProbeLine> lines;
  final List<String> caveats;

  /// Null when the run did not try the probe.
  static ProbeView? of(AuditReport r, String lang) {
    final o = r.probe;
    if (o == null) return null;

    final ios = r.binary?.kind == 'IPA';
    final caveats = [
      L10n(lang).probeViewAutomaticObservationsCoverProcessBehaviorAppEventsDescribe,
      if (!ios) L10n(lang).probeViewThisShowsWhatHappenedOnThisEmulatorWith,
    ];
    final report = o.report;
    if (report?.platform == 'ios-simulator') {
      caveats.add(L10n(lang).probeViewSimulatorObservationsApplyOnlyToThisSimulatorBuild);
    }
    final heading = (ios ? L10n(lang).probeViewIosResilienceProbe :
        L10n(lang).probeViewResilienceProbeEmulator) +
        (report == null ? '' : ' — ${report.app.split(RegExp(r'[\\/]')).last}');
    if (report == null) {
      return ProbeView(
          heading: heading,
          lines: const [],
          caveats: const [],
          message: L10n(lang).probeViewSkipped(value1: o.skippedOf(lang)));
    }
    if (report.emulatorError != null) {
      return ProbeView(
          heading: heading,
          lines: const [],
          caveats: const [],
          details: probeApkIdentityLines(report, lang),
          message: L10n(lang).probeViewCouldNotRun(value1: report.emulatorError));
    }
    if (!report.baselineAlive) {
      return ProbeView(
        heading: heading,
        lines: const [],
        caveats: caveats,
        message: ios ? L10n(lang).probeViewTheIosControlProcessDidNotStayAlive : L10n(lang).probeViewTheAppDidNotStayAliveOnA,
        details: [
          ...probeApkIdentityLines(report, lang),
          for (final l in (report.baselineNoteOf(lang) ?? '').split('\n'))
            if (l.trim().isNotEmpty) l.trimRight(),
        ],
      );
    }
    ProbeResult? base;
    for (final x in report.results) {
      if (x.check.id == 'baseline') base = x;
    }
    return ProbeView(
      heading: heading,
      caveats: caveats,
      details: probeApkIdentityLines(report, lang),
      baseline: base == null
          ? null
          : '✅ ${probeCheckTitle(base.check, lang)}: ${probeEvidence(base, lang)}${base.note == null ? '' : ' · ${probeNote(base, lang)}'}',
      lines: [
        for (final x in report.scored)
          ProbeLine(
            x.observedStatus,
            probeResultMark(x).trim(),
            probeResultTitle(x, lang),
            probeEvidence(x, lang),
            [x.check.masvs, x.check.mastg].whereType<String>().join(' · '),
            probeRuleIds[x.check.id],
            note: probeNote(x, lang),
          ),
      ],
    );
  }
}
