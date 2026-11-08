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

/// True when [logcat] shows the app's **own** process dying or crashing,
/// matched by package or pid so unrelated log noise doesn't count.
bool logcatShowsAppDeath(String logcat,
    {required int pid, required String package}) {
  final pidWord = RegExp(r'(^|\D)' + pid.toString() + r'($|\D)');
  for (final line in logcat.split('\n')) {
    final mentionsApp = line.contains(package) || pidWord.hasMatch(line);
    if (!mentionsApp) continue;
    for (final marker in _deathMarkers) {
      if (line.contains(marker)) return true;
    }
  }
  return false;
}

const _deathMarkers = [
  'FATAL EXCEPTION',
  'has died',
  'Process.killProcess',
  'Killing ', // ActivityManager: Killing <pid>:<pkg>
  'AndroidRuntime: Shutting down VM',
];
