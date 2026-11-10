/// Data types for `aegis probe` (doc/plans/probe.md). No I/O.
library;

import '../l10n/messages.g.dart';

/// The outcome of one resilience check.
enum ProbeStatus {
  /// The app blocked the tested operation or exited on its own under the condition.
  blocked,

  /// The process or the tested operation continued under the verified condition.
  notBlocked,

  /// The check did not establish a verdict.
  inconclusive,
}

/// One standard resilience condition, mapped to this repo's MASVS control and
/// the OWASP MASTG test.
class ProbeCheck {
  const ProbeCheck(this.id, this.title, {this.masvs, this.mastg});

  /// Stable key: `baseline`, `root`, `debugger`, `hooking`, `repackage`.
  final String id;
  final String title;

  /// e.g. `MASVS-RESILIENCE-1`. Null for the baseline gate.
  final String? masvs;

  /// A related reference, e.g. `MASTG-TEST-0325`.
  final String? mastg;
}

/// The checks the probe runs, in order. `baseline` is the gate, not scored.
const probeChecks = <ProbeCheck>[
  ProbeCheck('baseline', En.checkBaseline),
  ProbeCheck('root', En.checkRoot,
      masvs: 'MASVS-RESILIENCE-1', mastg: 'MASTG-TEST-0325'),
  ProbeCheck('debugger', En.checkDebugger,
      masvs: 'MASVS-RESILIENCE-4', mastg: 'MASTG-TEST-0353'),
  ProbeCheck('hooking', En.checkHooking,
      masvs: 'MASVS-RESILIENCE-4', mastg: 'MASTG-TEST-0341'),
  ProbeCheck('repackage', En.checkRepackage,
      masvs: 'MASVS-RESILIENCE-2'),
];

ProbeCheck checkById(String id) => probeChecks.firstWhere((c) => c.id == id);

/// The result of one check.
class ProbeResult {
  ProbeResult(this.check, this.status, {this.evidence = '', this.evidenceAr, this.note, this.noteAr, this.applicable = true,
      this.processOnly = false}) : partialStatus = null;

  /// The observation is useful but cannot decide the full iOS condition.
  ProbeResult.partial(this.check, {required ProbeStatus observation,
      required this.evidence, this.evidenceAr, required this.note, required this.noteAr,
      this.processOnly = false})
      : status = ProbeStatus.inconclusive, applicable = true,
        partialStatus = observation;
  final ProbeStatus? partialStatus;
  final String? noteAr;
  final ProbeCheck check;
  final ProbeStatus status;
  final bool applicable;

  /// The verdict describes process behavior during the probe window.
  final bool processOnly;

  /// What was observed, for the report ("process gone after 8s", ...).
  final String evidence;
  final String? evidenceAr;

  /// An extra caveat for this line (e.g. a report-only RASP note).
  final String? note;
}

/// Verified signer information for an AAB's companion APK.
class ProbeApkIdentity {
  const ProbeApkIdentity({
    required this.signerSha256,
    this.expectedSignerSha256,
    this.controlApks = const [],
    this.rootedApks = const [],
  });

  final List<String> signerSha256;
  final String? expectedSignerSha256;
  final List<String> controlApks;
  final List<String> rootedApks;
}

/// The whole probe run.
class ProbeReport {
  ProbeReport({
    required this.app,
    required this.baselineAlive,
    required this.results,
    this.emulatorError,
    this.baselineNote,
    this.baselineNoteAr,
    this.apkIdentity,
    this.platform = 'android',
  });

  /// The app that was probed (file name).
  final String app;
  final String platform;
  final ProbeApkIdentity? apkIdentity;

  /// Set when the emulator or install could not run at all (a tooling
  /// problem, not the app). Distinct from [baselineAlive] being false, which
  /// means the app itself did not stay up on a working emulator.
  final String? emulatorError;

  /// Whether the app stayed alive on the clean emulator. When false, the
  /// scored checks are all inconclusive.
  final bool baselineAlive;

  /// A diagnostic (logcat tail) shown when [baselineAlive] is false.
  final String? baselineNote;
  final String? baselineNoteAr;
  String? baselineNoteOf(String lang) => lang == 'ar' ? baselineNoteAr ?? baselineNote : baselineNote;

  final List<ProbeResult> results;

  Iterable<ProbeResult> get scored => results.where((r) => r.check.id != 'baseline');
  Iterable<ProbeResult> get notBlocked =>
      scored.where((r) => r.status == ProbeStatus.notBlocked);
  Iterable<ProbeResult> get blocked =>
      scored.where((r) => r.status == ProbeStatus.blocked);
  Iterable<ProbeResult> get inconclusive =>
      scored.where((r) => r.status == ProbeStatus.inconclusive);
}

/// What an audit knows about the probe: its report, or why it did not run
/// (no emulator tools, --no-probe, ...). Rules AEG-R01..R04 read it.
class ProbeOutcome {
  const ProbeOutcome.ran(ProbeReport this.report) : skipped = null, skippedAr = null, requested = true;
  const ProbeOutcome.skipped(String this.skipped, {this.requested = true, this.skippedAr}) : report = null;

  final ProbeReport? report;
  final String? skipped;
  final String? skippedAr;
  String? skippedOf(String lang) => lang == 'ar' ? skippedAr ?? skipped : skipped;
  final bool requested;

  /// Whether a requested probe was skipped or left an applicable check undecided.
  bool get incomplete {
    if (!requested) return false;
    final run = report;
    return run == null ||
        run.emulatorError != null ||
        !run.baselineAlive ||
        run.inconclusive.any((check) => check.applicable);
  }
}
