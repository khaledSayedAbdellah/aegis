/// Turning a device observation into a [ProbeStatus] (docs/plans/probe.md §3).
///
/// This is where "never decide from memory" lives: a definite verdict is
/// returned only from what was actually observed on the device. No I/O here —
/// the runner gathers the facts, these functions judge them.
library;

import 'probe_model.dart';

/// What the runner observed around one probe condition.
class Observation {
  const Observation({
    required this.setupOk,
    required this.aliveBefore,
    required this.aliveAfter,
    this.appDeathLogged = false,
  });

  /// The condition was applied successfully (tool ran, device cooperated).
  final bool setupOk;

  /// The app's process was running just before the condition.
  final bool aliveBefore;

  /// The app's process was still running after the fixed wait.
  final bool aliveAfter;

  /// logcat showed the app's own process crash or being killed.
  final bool appDeathLogged;

  /// Nothing was set up / observed, so no verdict is possible.
  const Observation.inconclusive()
      : setupOk = false,
        aliveBefore = false,
        aliveAfter = false,
        appDeathLogged = false;
}

/// Maps an observation to a status. Without a successful setup and a live
/// starting point there is no verdict ([ProbeStatus.inconclusive]); the app
/// going away or crashing is a reaction ([ProbeStatus.blocked]); the app
/// still running normally means the protection didn't react
/// ([ProbeStatus.notBlocked]).
ProbeStatus statusOf(Observation o) {
  if (!o.setupOk || !o.aliveBefore) return ProbeStatus.inconclusive;
  if (!o.aliveAfter || o.appDeathLogged) return ProbeStatus.blocked;
  return ProbeStatus.notBlocked;
}

/// True when [logcat] mentions the app's **own** process (by package or pid)
/// and also shows a crash/kill marker, so unrelated log noise doesn't count.
bool logcatShowsAppDeath(String logcat,
    {required int pid, required String package}) {
  final pidWord = RegExp(r'(^|\D)' + pid.toString() + r'($|\D)');
  final mentionsApp = logcat.contains(package) || pidWord.hasMatch(logcat);
  if (!mentionsApp) return false;
  return _deathMarkers.any(logcat.contains);
}

/// A best-effort guess at why a re-signed build died.
enum CrashCause { integrityCheck, boundService, unknown }

/// Classifies a repackage-test crash from [logcat]. A reference to the app
/// reading its own signature points to a real integrity check; a Google/Play
/// service auth error points to a key bound to the original cert (not the
/// app's own anti-tampering). Heuristic — a Dart-side check may leave no trace.
CrashCause classifyRepackageReaction(String logcat) {
  final l = logcat.toLowerCase();
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

const _deathMarkers = [
  'FATAL EXCEPTION',
  'has died',
  'Process.killProcess',
  'Killing ', // ActivityManager: Killing <pid>:<pkg>
  'AndroidRuntime: Shutting down VM',
];
