import 'dart:io';

import 'package:aegis/src/config.dart';
import 'package:aegis/src/l10n/messages.g.dart';
import 'package:aegis/src/probe/ios_target.dart';
import 'package:aegis/src/services/android_probe.dart';
import 'package:aegis/src/services/ios_probe.dart';
import 'package:path/path.dart' as p;
import 'package:test/test.dart';

void main() {
  final project = p.absolute('.');
  final aab = p.absolute('test/fixtures/aab/vulnerable.aab');
  final apk = p.absolute('test/fixtures/apk/secure.apk');

  test('Android service preserves missing companion outcome without CLI',
      () async {
    final events = <String>[];
    final outcome = await runAndroidProbe(aab,
        config: AegisConfig.parse(''),
        projectRoot: project,
        log: events.add,
        onRunning: (package, control) => events.add('$package:$control'));
    expect(outcome.report, isNull);
    expect(outcome.skippedOf('en'), En.aabCompanionRequired);
    expect(outcome.skippedOf('ar'), Ar.aabCompanionRequired);
    expect(events, isEmpty, reason: 'No runtime starts for invalid input.');
  });

  test('Android service keeps YAML signer validation and CLI override order',
      () async {
    final config = AegisConfig.parse('probe_cert_sha256: invalid');
    final invalid =
        await runAndroidProbe(aab, config: config, projectRoot: project);
    expect(invalid.skippedOf('en'), En.aabSignerFingerprintInvalid);
    final overridden = await runAndroidProbe(aab,
        config: config,
        projectRoot: project,
        expectedSigner: List.filled(64, 'a').join());
    expect(overridden.skippedOf('en'), En.aabCompanionRequired);
  });

  test('Android service rejects mismatched companion before device access',
      () async {
    final outcome = await runAndroidProbe(aab,
        config: AegisConfig.parse('probe_apk: test/fixtures/apk/secure.apk'),
        projectRoot: project);
    expect(outcome.skippedOf('en'), En.aabCompanionMismatch);
    expect(outcome.skippedOf('ar'), Ar.aabCompanionMismatch);
  });

  test('Android service preserves dedicated AVD validation', () async {
    final outcome = await runAndroidProbe(apk,
        config: AegisConfig.parse(''),
        projectRoot: project,
        controlAvd: 'personal-emulator');
    expect(outcome.skippedOf('en'), En.androidDedicatedAvdsRequired);
  });

  test('iOS service keeps missing Simulator separate from configured device',
      () async {
    final selection = resolveIosProbeSelection(
        config: AegisConfig.parse('ios_control_device: stock-device'),
        project: project,
        target: IosTarget.simulator);
    final outcome = await runIosProbe('unused.ipa',
        selection: selection, projectRoot: project);
    expect(outcome.skippedOf('en'), En.iosSimulatorMissing);
    expect(outcome.skippedOf('ar'), Ar.iosSimulatorMissing);
  });

  test('iOS service preserves host and stock-device prerequisites', () async {
    final selection = resolveIosProbeSelection(
        config: AegisConfig.parse('ios_simulator: simulator-id'),
        project: project,
        target: IosTarget.device);
    final outcome = await runIosProbe('unused.ipa',
        selection: selection, projectRoot: project);
    expect(outcome.skippedOf('en'),
        Platform.isMacOS ? En.iosControlMissing : En.iosRequiresXcode);
  });
}
