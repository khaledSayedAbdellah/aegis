import 'dart:io';

import '../probe/messages.dart';
import '../probe/setup.dart';
import '../probe/toolchain.dart';

/// The icon for a tool's state. [blocked] is an installable tool whose
/// dependencies are not present yet.
String _mark(ToolCheck c, {bool blocked = false}) => switch (c.state) {
      ToolState.present => '✅',
      ToolState.installable => blocked ? '⏸️ ' : '⬇️ ',
      ToolState.manual => '❌',
      ToolState.optional => 'ℹ️ ',
    };

/// Renders the detail column for one tool. [blocked] are the dependencies
/// that keep it from being installed this run (from the setup plan).
String _detail(ToolCheck c, Msg m, Toolchain t, List<String>? blocked) {
  if (c.ok) {
    return [
      if (c.version != null) c.version!,
      if (c.path != null) t.tilde(c.path!),
      if (c.source != null) '(${c.source})',
    ].join('  ');
  }
  if (blocked != null) return m.waitingFor(blocked);
  if (c.installable) return m.installHintFor(c.id);
  return m.issue(c);
}

/// The table of tools. An installable tool is ⏸️ only when something it
/// needs can't be installed in the same run (the person installs it first).
void printToolChecks(List<ToolCheck> checks, Msg m, Toolchain t) {
  final blocked = Setup(t).buildPlan(checks).blocked;
  final w =
      checks.map((c) => m.title(c.id).length).fold(0, (a, b) => a > b ? a : b);
  for (final c in checks) {
    final b = blocked[c.id];
    stdout.writeln(
        '  ${_mark(c, blocked: b != null)} ${m.title(c.id).padRight(w)}  ${_detail(c, m, t, b)}');
  }
}
