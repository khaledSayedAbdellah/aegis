/// Turning a device observation into a [ProbeStatus] (docs/plans/probe.md §3).
///
/// This is where "never decide from memory" lives: a definite verdict is
/// returned only from what was actually observed on the device. No I/O here —
/// the runner gathers the facts, these functions judge them.
library;

import 'probe_model.dart';

/// The pid column of a logcat line in the default `threadtime` format
/// (`11-08 15:29:21.344   951   951 I Tag: msg`), or null for other formats.
final _threadtime = RegExp(r'^\S+\s+\S+\s+(\d+)\s+\d+\s+[VDIWEF]\s');

int? _linePid(String line) {
  final m = _threadtime.firstMatch(line);
  return m == null ? null : int.tryParse(m.group(1)!);
}

/// Every pid the app had in [logcat]: [pid] when known, plus those named by
/// ActivityManager ("Start proc 6301:com.x/…") or a crash header
/// ("Process: com.x, PID: 6301"), so a process that already died is still
/// recognised.
Set<int> appPids(String logcat, String package, {int? pid}) {
  final out = <int>{if (pid != null && pid > 0) pid};
  final q = RegExp.escape(package);
  for (final m in RegExp('Start proc (\\d+):$q[/ ]').allMatches(logcat)) {
    out.add(int.parse(m.group(1)!));
  }
  for (final m in RegExp('Process: $q, PID: (\\d+)').allMatches(logcat)) {
    out.add(int.parse(m.group(1)!));
  }
  return out;
}

/// The lines written by the app's **own** process: lines whose pid column is
/// one of [appPids], plus a `FATAL EXCEPTION` block whose `Process:` line names
/// the package (that block may be logged without a threadtime pid). System
/// lines that merely mention the package — the installer, PackageManager, Play
/// Protect — are left out on purpose: they talk about signatures during any
/// install and are not the app's own behaviour.
List<String> appLines(String logcat, String package, {int? pid}) {
  final pids = appPids(logcat, package, pid: pid);
  final lines = logcat.split('\n');
  final out = <String>[];
  for (var i = 0; i < lines.length; i++) {
    final lp = _linePid(lines[i]);
    if (lp != null) {
      if (pids.contains(lp)) out.add(lines[i]);
    } else if (_isCrashBlockLine(lines, i, package)) {
      out.add(lines[i]);
    }
  }
  return out;
}

/// A line with no threadtime pid that belongs to the app's FATAL block: it
/// mentions FATAL/Process and a `Process: <package>` line sits within a few
/// lines of it.
bool _isCrashBlockLine(List<String> lines, int i, String package) {
  final l = lines[i];
  if (!l.contains('FATAL EXCEPTION') && !l.contains('Process: $package')) return false;
  final from = (i - 3) < 0 ? 0 : i - 3;
  final to = (i + 4) > lines.length ? lines.length : i + 4;
  for (var j = from; j < to; j++) {
    if (lines[j].contains('Process: $package')) return true;
  }
  return false;
}

/// True when the app started at all in [logcat] (a pid appeared for it).
bool appStarted(String logcat, String package, {int? pid}) =>
    appPids(logcat, package, pid: pid).isNotEmpty;

/// True when [logcat] shows the app's **own** process crashing or being
/// killed: a FATAL block from the app, or an ActivityManager line naming the
/// package on the **same** line (`… com.x … has died`, `Killing <pid>:com.x`).
/// Clear logcat before the condition so the uninstall/update kill
/// ("Killing N:com.x …") from reinstalling is not counted.
bool logcatShowsAppDeath(String logcat,
    {required int pid, required String package}) {
  final mine = appLines(logcat, package, pid: pid);
  if (mine.any((l) =>
      l.contains('FATAL EXCEPTION') ||
      l.contains('Process.killProcess') ||
      l.contains('Shutting down VM'))) {
    return true;
  }
  final killing = RegExp('Killing \\d+:${RegExp.escape(package)}');
  for (final line in logcat.split('\n')) {
    if (!line.contains(package)) continue;
    if (line.contains('has died')) return true;
    // A "Killing <pid>:<pkg>" with a system reason ("due to install/update",
    // "remove task", "cached #N") is the OS reclaiming the process, not the
    // app's anti-tampering; only an unexplained kill counts.
    if (killing.hasMatch(line) && !line.contains('due to') && !line.contains('remove')) {
      return true;
    }
  }
  return false;
}

final _exitRecord = RegExp(
    r'\btimestamp=([^\r\n]+?)\s+pid=(\d+)[^\r\n]*\r?\n'
    r'[^\S\r\n]*process=(\S+)\s+reason=(\d+)\b');

/// Android's exit history distinguishes REASON_EXIT_SELF (1) from crashes
/// and external kills. Match the observed process and a new record.
bool observedSelfExit(String before, String after, String package, int pid) {
  Iterable<RegExpMatch> records(String dump) => _exitRecord.allMatches(dump)
      .where((record) => record[2] == '$pid' && record[3] == package);
  final earlier = records(before).map((record) => record[1]).toSet();
  final latest = records(after).firstOrNull;
  return latest != null && latest[4] == '1' && !earlier.contains(latest[1]);
}

/// A best-effort guess at why a re-signed build died.
enum CrashCause { integrityCheck, boundService, unknown }

/// Classifies a repackage-test crash from the app's **own** log lines. The app
/// reading its own signature points to a real integrity check; a Google/Play
/// service auth error points to a key bound to the original cert (not the
/// app's own anti-tampering). Heuristic — a Dart-side check may leave no trace.
CrashCause classifyRepackageReaction(String logcat,
    {required String package, int? pid}) {
  final l = appLines(logcat, package, pid: pid).join('\n').toLowerCase();
  const service = [
    'api_key', 'api key', 'apiexception', 'authorization failure',
    'authfailureerror', 'safetynet', 'play integrity', 'integritymanager',
    'developer_error', 'places api', 'maps api', 'is not authorized',
  ];
  const integrity = [
    'get_signatures', 'get_signing', 'getpackageinfo', 'signinginfo',
    'signatureexception', 'signature mismatch', 'tamper', 'integrity check',
  ];
  final isService = service.any(l.contains);
  final isIntegrity = integrity.any(l.contains);
  if (isIntegrity && !isService) return CrashCause.integrityCheck;
  if (isService && !isIntegrity) return CrashCause.boundService;
  return CrashCause.unknown;
}

/// Reads the app's optional outcome. Null means absent; inconclusive means
/// the app emitted conflicting outcomes for the same check.
ProbeStatus? appProbeVerdict(String logcat, String package, String check, {int? pid}) {
  final pids = pid == null ? appPids(logcat, package) : {pid};
  final statuses = <ProbeStatus>{};
  final event = RegExp(r'\sAegisProbe\s*:\s+' + RegExp.escape(check) +
      r'\s+(blocked|not-blocked)\s*$');
  for (final line in logcat.split('\n')) {
    if (!pids.contains(_linePid(line))) continue;
    final match = event.firstMatch(line);
    if (match == null) continue;
    statuses.add(match[1] == 'blocked' ? ProbeStatus.blocked : ProbeStatus.notBlocked);
  }
  if (statuses.isEmpty) return null;
  return statuses.length == 1 ? statuses.single : ProbeStatus.inconclusive;
}
