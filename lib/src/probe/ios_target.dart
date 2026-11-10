/// Resolve exactly one iOS runtime environment without falling back to the other.
library;

import '../config.dart';
import '../util.dart';

enum IosTarget { simulator, device }

IosTarget? parseIosTarget(String? input) {
  final choice = parseMenuChoice(input, 2);
  if (choice != null) return IosTarget.values[choice - 1];
  return switch (input?.trim().toLowerCase()) {
    'simulator' => IosTarget.simulator,
    'device' => IosTarget.device,
    _ => null,
  };
}

typedef IosProbeSelection = ({
  IosTarget target,
  String? controlId,
  String? jailbreakId,
  String? resignedIpa,
  String? simulatorId,
  String? simulatorApp,
  String? simulatorFlavor,
  String? simulatorEntryPoint,
});

IosProbeSelection resolveIosProbeSelection({
  required AegisConfig config,
  required String project,
  IosTarget? target,
  String? controlId,
  String? jailbreakId,
  String? resignedIpa,
  String? simulatorId,
  String? simulatorApp,
}) {
  final physicalOptions =
      controlId != null || jailbreakId != null || resignedIpa != null;
  final simulatorOptions = simulatorId != null || simulatorApp != null;
  if (physicalOptions && simulatorOptions ||
      target == IosTarget.simulator && physicalOptions ||
      target == IosTarget.device && simulatorOptions) {
    throw const FormatException('Conflicting iOS target options.');
  }
  // Legacy `probe` callers may omit target. `run --mode ipa` always selects it.
  target ??= physicalOptions
      ? IosTarget.device
      : simulatorOptions ||
              config.iosSimulator != null ||
              config.iosSimulatorApp != null
          ? IosTarget.simulator
          : IosTarget.device;
  final simulator = target == IosTarget.simulator;
  return (
    target: target,
    controlId: simulator ? null : controlId ?? config.iosControlDevice,
    jailbreakId: simulator ? null : jailbreakId ?? config.iosJailbreakDevice,
    resignedIpa: simulator
        ? null
        : resignedIpa ?? AegisConfig.resolve(project, config.iosResignedIpa),
    simulatorId: simulator ? simulatorId ?? config.iosSimulator : null,
    simulatorApp: simulator
        ? simulatorApp ?? AegisConfig.resolve(project, config.iosSimulatorApp)
        : null,
    simulatorFlavor: simulator ? config.iosSimulatorFlavor : null,
    simulatorEntryPoint: simulator ? config.iosSimulatorTarget : null,
  );
}
