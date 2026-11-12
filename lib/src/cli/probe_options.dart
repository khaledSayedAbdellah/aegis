import 'package:args/args.dart';

import '../config.dart';
import '../l10n/messages.g.dart';
import '../probe/ios_target.dart';
import '../probe/probe_model.dart';
import '../services/ios_probe.dart';
import 'terminal.dart';

IosProbeSelection iosSelection(
        ArgResults args, AegisConfig config, String project,
        {IosTarget? target}) =>
    resolveIosProbeSelection(
      config: config,
      project: project,
      target: target ?? parseIosTarget(args['ios-target'] as String?),
      controlId: args['ios-control-device'] as String?,
      jailbreakId: args['ios-jailbreak-device'] as String?,
      resignedIpa: args['ios-resigned-ipa'] as String?,
      simulatorId: args['ios-simulator'] as String?,
      simulatorApp: args['ios-simulator-app'] as String?,
    );

Future<ProbeOutcome> runConfiguredIosProbe(
    String path, ArgResults args, AegisConfig config, String project,
    {Set<String>? only, IosTarget? target}) async {
  final IosProbeSelection selection;
  try {
    selection = iosSelection(args, config, project, target: target);
  } on FormatException {
    return const ProbeOutcome.skipped(En.iosTargetConflict,
        skippedAr: Ar.iosTargetConflict);
  }
  return runIosProbe(path,
      selection: selection, projectRoot: project, only: only, log: logProbe);
}
