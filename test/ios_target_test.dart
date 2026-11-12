import 'dart:convert';
import 'dart:io';

import 'package:aegis/src/config.dart';
import 'package:aegis/src/l10n/messages.g.dart';
import 'package:aegis/src/probe/ios_target.dart';
import 'package:path/path.dart' as p;
import 'package:test/test.dart';

import 'ipa_test.dart' show fixture;

void main() {
  final project = Directory.systemTemp.path;
  final both = AegisConfig.parse('''
ios_simulator: simulator-id
ios_simulator_app: Simulator.app
ios_simulator_flavor: prod
ios_simulator_target: lib/main_prod.dart
ios_control_device: stock-id
ios_jailbreak_device: jailbreak-id
ios_resigned_ipa: resigned.ipa
''');

  test('IPA target menu accepts names and Arabic/Persian digits, no default',
      () {
    expect(parseIosTarget('simulator'), IosTarget.simulator);
    expect(parseIosTarget(' Device '), IosTarget.device);
    expect(parseIosTarget('١'), IosTarget.simulator);
    expect(parseIosTarget('۲'), IosTarget.device);
    for (final value in [null, '', 'both', '3']) {
      expect(parseIosTarget(value), isNull);
    }
  });

  test('Simulator selection discards all physical-device YAML settings', () {
    final selected = resolveIosProbeSelection(
        config: both, project: project, target: IosTarget.simulator);
    expect(selected.simulatorId, 'simulator-id');
    expect(selected.simulatorApp, p.join(project, 'Simulator.app'));
    expect(selected.simulatorFlavor, 'prod');
    expect(selected.simulatorEntryPoint, 'lib/main_prod.dart');
    expect([selected.controlId, selected.jailbreakId, selected.resignedIpa],
        everyElement(isNull));
  });

  test('physical-device selection discards all Simulator YAML settings', () {
    final selected = resolveIosProbeSelection(
        config: both, project: project, target: IosTarget.device);
    expect(selected.controlId, 'stock-id');
    expect(selected.jailbreakId, 'jailbreak-id');
    expect(selected.resignedIpa, p.join(project, 'resigned.ipa'));
    expect([
      selected.simulatorId,
      selected.simulatorApp,
      selected.simulatorFlavor,
      selected.simulatorEntryPoint
    ], everyElement(isNull));
  });

  test(
      'missing selected environment never falls back to the configured other one',
      () {
    final simulator = resolveIosProbeSelection(
        config: AegisConfig.parse('ios_control_device: stock-id'),
        project: project,
        target: IosTarget.simulator);
    expect(simulator.target, IosTarget.simulator);
    expect(simulator.simulatorId, isNull);
    expect(simulator.controlId, isNull);
    final device = resolveIosProbeSelection(
        config: AegisConfig.parse('ios_simulator: simulator-id'),
        project: project,
        target: IosTarget.device);
    expect(device.target, IosTarget.device);
    expect(device.controlId, isNull);
    expect(device.simulatorId, isNull);
  });

  test(
      'CLI overrides apply only to the selected target; conflicting options reject',
      () {
    final simulator = resolveIosProbeSelection(
        config: both,
        project: project,
        target: IosTarget.simulator,
        simulatorId: 'explicit-simulator');
    expect(simulator.simulatorId, 'explicit-simulator');
    final device = resolveIosProbeSelection(
        config: both,
        project: project,
        target: IosTarget.device,
        controlId: 'explicit-device');
    expect(device.controlId, 'explicit-device');
    expect(
        () => resolveIosProbeSelection(
            config: both,
            project: project,
            target: IosTarget.simulator,
            controlId: 'device'),
        throwsFormatException);
    expect(
        () => resolveIosProbeSelection(
            config: both,
            project: project,
            target: IosTarget.device,
            simulatorApp: 'Simulator.app'),
        throwsFormatException);
    expect(
        () => resolveIosProbeSelection(
            config: both,
            project: project,
            simulatorId: 'simulator',
            controlId: 'device'),
        throwsFormatException);
  });

  test('legacy probe callers retain unambiguous target inference', () {
    expect(resolveIosProbeSelection(config: both, project: project).target,
        IosTarget.simulator);
    final device = resolveIosProbeSelection(
        config: both, project: project, controlId: 'explicit-device');
    expect(device.target, IosTarget.device);
    expect(device.simulatorId, isNull);
  });

  group('run --mode ipa', () {
    late Directory work;
    setUp(() {
      work = Directory.systemTemp.createTempSync('aegis-ios-target-');
      fixture(work);
      File(p.join(work.path, 'aegis.yaml'))
          .writeAsStringSync('ipa: probe.ipa\n');
      addTearDown(() => work.deleteSync(recursive: true));
    });
    Future<ProcessResult> run(List<String> extra) =>
        Process.run(Platform.resolvedExecutable, [
          p.absolute('bin/aegis.dart'),
          'run',
          work.path,
          '--mode',
          'ipa',
          '--offline',
          '--strict',
          '--lang',
          'ar',
          '-f',
          'json',
          '-o',
          p.join(work.path, 'report'),
          ...extra,
        ]);

    test('non-interactive IPA run requires a target even when YAML has one',
        () async {
      File(p.join(work.path, 'aegis.yaml')).writeAsStringSync(
          'ipa: probe.ipa\nios_simulator: configured-simulator\n');
      final result = await run([]);
      expect(result.exitCode, 2);
      expect(result.stderr, contains(En.iosTargetRequired));
      expect(File(p.join(work.path, 'report.json')).existsSync(), isFalse);
    });

    test('static-only IPA run requires no runtime target', () async {
      final result = await run(['--no-probe']);
      expect(result.stderr, isNot(contains(En.iosTargetRequired)));
      final report =
          jsonDecode(File(p.join(work.path, 'report.json')).readAsStringSync())
              as Map;
      expect(report['binary']['kind'], 'IPA');
      expect(report['probe']['ran'], isFalse);
    });

    test(
        'selected Simulator missing configuration does not use a physical device',
        () async {
      File(p.join(work.path, 'aegis.yaml'))
          .writeAsStringSync('ipa: probe.ipa\nios_control_device: stock-id\n');
      final result = await run(['--ios-target', 'simulator']);
      expect(result.exitCode, 2);
      final report =
          jsonDecode(File(p.join(work.path, 'report.json')).readAsStringSync())
              as Map;
      expect(report['probe']['skipped'], En.iosSimulatorMissing);
      expect(report['probe']['skippedAr'], Ar.iosSimulatorMissing);
    });

    test(
        'selected physical device missing configuration does not use a Simulator',
        () async {
      File(p.join(work.path, 'aegis.yaml'))
          .writeAsStringSync('ipa: probe.ipa\nios_simulator: simulator-id\n');
      final result = await run(['--ios-target', 'device']);
      expect(result.exitCode, 2);
      final report =
          jsonDecode(File(p.join(work.path, 'report.json')).readAsStringSync())
              as Map;
      expect(report['probe']['skipped'],
          Platform.isMacOS ? En.iosControlMissing : En.iosRequiresXcode);
      expect(report['probe']['ran'], isFalse);
    });

    test('contradictory CLI target options fail before running an audit',
        () async {
      final result = await run(
          ['--ios-target', 'simulator', '--ios-control-device', 'stock-id']);
      expect(result.exitCode, 2);
      expect(result.stderr, contains(En.iosTargetConflict));
      expect(File(p.join(work.path, 'report.json')).existsSync(), isFalse);
    });
  });
}
