/// Data types for `aegis probe` (docs/plans/probe.md). No I/O.
library;

/// The outcome of one resilience check.
enum ProbeStatus {
  /// The app detected the condition and reacted. Protection works.
  blocked,

  /// The app ran normally under the condition. The expected protection is
  /// absent or ineffective — a finding.
  notBlocked,

  /// The check couldn't run (a tool or the baseline failed). Never a verdict.
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

  /// e.g. `MASTG-TEST-0048`.
  final String? mastg;
}

/// The checks the probe runs, in order. `baseline` is the gate, not scored.
const probeChecks = <ProbeCheck>[
  ProbeCheck('baseline', 'Baseline launch'),
  ProbeCheck('root', 'Root detection',
      masvs: 'MASVS-RESILIENCE-1', mastg: 'MASTG-TEST-0048'),
  ProbeCheck('debugger', 'Debugger detection',
      masvs: 'MASVS-RESILIENCE-4', mastg: 'MASTG-TEST-0045'),
  ProbeCheck('hooking', 'Instrumentation (Frida) detection',
      masvs: 'MASVS-RESILIENCE-4', mastg: 'MASTG-TEST-0046'),
  ProbeCheck('repackage', 'Repackaging / integrity detection',
      masvs: 'MASVS-RESILIENCE-2', mastg: 'MASTG-TEST-0047'),
];

ProbeCheck checkById(String id) => probeChecks.firstWhere((c) => c.id == id);

/// The result of one check.
class ProbeResult {
  ProbeResult(this.check, this.status, {this.evidence = '', this.note});
  final ProbeCheck check;
  final ProbeStatus status;

  /// What was observed, for the report ("process gone after 8s", ...).
  final String evidence;

  /// An extra caveat for this line (e.g. a report-only RASP note).
  final String? note;
}

/// The whole probe run.
class ProbeReport {
  ProbeReport({
    required this.app,
    required this.baselineAlive,
    required this.results,
    this.emulatorError,
  });

  /// The app that was probed (file name).
  final String app;

  /// Set when the emulator or install could not run at all (a tooling
  /// problem, not the app). Distinct from [baselineAlive] being false, which
  /// means the app itself did not stay up on a working emulator.
  final String? emulatorError;

  /// Whether the app stayed alive on the clean emulator. When false, the
  /// scored checks are all inconclusive.
  final bool baselineAlive;

  final List<ProbeResult> results;

  Iterable<ProbeResult> get scored => results.where((r) => r.check.id != 'baseline');
  Iterable<ProbeResult> get notBlocked =>
      scored.where((r) => r.status == ProbeStatus.notBlocked);
  Iterable<ProbeResult> get blocked =>
      scored.where((r) => r.status == ProbeStatus.blocked);
  Iterable<ProbeResult> get inconclusive =>
      scored.where((r) => r.status == ProbeStatus.inconclusive);
}
