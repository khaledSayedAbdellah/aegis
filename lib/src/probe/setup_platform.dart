/// Platform selection and independent, ordered environment preparation.
library;

import '../util.dart';
import 'toolchain.dart';

enum SetupTarget { android, ios, both }

enum SetupPlatform {
  android('Android'),
  ios('iOS');

  const SetupPlatform(this.label);
  final String label;
}

SetupTarget? setupTargetFromFlags({
  bool android = false,
  bool ios = false,
  bool both = false,
  bool aab = false,
}) {
  final targets = [
    if (android || aab) SetupTarget.android,
    if (ios) SetupTarget.ios,
    if (both) SetupTarget.both,
  ];
  if (targets.length > 1) {
    throw const FormatException('Select one setup platform.');
  }
  return targets.singleOrNull;
}

SetupTarget? parseSetupTarget(String? input) {
  final number = parseMenuChoice(input, 3);
  if (number != null) return SetupTarget.values[number - 1];
  return switch (input?.trim().toLowerCase()) {
    'android' => SetupTarget.android,
    'ios' => SetupTarget.ios,
    'both' => SetupTarget.both,
    _ => null,
  };
}

Future<List<ToolCheck>> checkSetupPlatform(
        Toolchain tools, SetupPlatform platform) =>
    platform == SetupPlatform.android
        ? tools.checkAll(aab: true)
        : tools.checkIos();

/// Android finishes before iOS begins. A failure in either stage does not
/// discard the other stage's result or roll back its installed tools.
/// A null [hostOs] means detection failed: attempt iOS after Android and let
/// its tool checks establish availability. Known non-macOS hosts skip iOS.
Future<Map<SetupPlatform, int>> runSetupPlatforms(
  SetupTarget target, {
  required String? hostOs,
  required Future<int> Function(SetupPlatform) prepare,
  required void Function() iosUnsupported,
  required void Function(SetupPlatform, Object) failed,
}) async {
  final platforms = switch (target) {
    SetupTarget.android => [SetupPlatform.android],
    SetupTarget.ios => [SetupPlatform.ios],
    SetupTarget.both => [SetupPlatform.android, SetupPlatform.ios],
  };
  final results = <SetupPlatform, int>{};
  for (final platform in platforms) {
    if (platform == SetupPlatform.ios && hostOs != null && hostOs != 'macos') {
      iosUnsupported();
      results[platform] = 1;
      continue;
    }
    try {
      results[platform] = await prepare(platform);
    } catch (error) {
      failed(platform, error);
      results[platform] = 1;
    }
  }
  return results;
}

int setupExitCode(Map<SetupPlatform, int> results) => results.values.contains(2)
    ? 2
    : results.values.any((code) => code != 0)
        ? 1
        : 0;
