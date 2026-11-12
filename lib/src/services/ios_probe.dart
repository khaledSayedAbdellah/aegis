import '../l10n/messages.g.dart';
import '../probe/ios_runner.dart';
import '../probe/ios_target.dart';
import '../probe/probe_model.dart';

/// Runs an iOS probe for an already resolved target, without terminal I/O.
Future<ProbeOutcome> runIosProbe(
  String path, {
  required IosProbeSelection selection,
  required String projectRoot,
  Set<String>? only,
  void Function(String)? log,
}) async {
  if (selection.target == IosTarget.simulator &&
      selection.simulatorId == null) {
    return const ProbeOutcome.skipped(En.iosSimulatorMissing,
        skippedAr: Ar.iosSimulatorMissing);
  }
  return IosProbeRunner().run(
    path,
    controlId: selection.controlId,
    jailbreakId: selection.jailbreakId,
    resignedIpa: selection.resignedIpa,
    simulatorId: selection.simulatorId,
    simulatorApp: selection.simulatorApp,
    projectRoot: projectRoot,
    simulatorFlavor: selection.simulatorFlavor,
    simulatorTarget: selection.simulatorEntryPoint,
    xcodeProject: selection.xcodeProject,
    xcodeScheme: selection.xcodeScheme,
    xcodeConfiguration: selection.xcodeConfiguration,
    only: only,
    log: log,
  );
}
