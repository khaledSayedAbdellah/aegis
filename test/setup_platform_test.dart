import 'dart:io';

import 'package:aegis/src/probe/host.dart';
import 'package:aegis/src/probe/setup.dart';
import 'package:aegis/src/probe/setup_platform.dart';
import 'package:aegis/src/probe/toolchain.dart';
import 'package:test/test.dart';

import 'support/fake_host.dart';
import 'toolchain_test.dart' show studioMac;

void main() {
  test('explicit flags isolate platforms and retain the AAB alias', () {
    expect(setupTargetFromFlags(), isNull);
    expect(setupTargetFromFlags(android: true), SetupTarget.android);
    expect(setupTargetFromFlags(aab: true), SetupTarget.android);
    expect(setupTargetFromFlags(aab: true, android: true), SetupTarget.android);
    expect(setupTargetFromFlags(ios: true), SetupTarget.ios);
    expect(setupTargetFromFlags(both: true), SetupTarget.both);
    expect(() => setupTargetFromFlags(android: true, ios: true),
        throwsFormatException);
    expect(() => setupTargetFromFlags(aab: true, ios: true),
        throwsFormatException);
    expect(() => setupTargetFromFlags(both: true, android: true),
        throwsFormatException);
  });

  test(
      'menu accepts platform names and Arabic/Persian digits without a default',
      () {
    expect(parseSetupTarget('Android'), SetupTarget.android);
    expect(parseSetupTarget('iOS'), SetupTarget.ios);
    expect(parseSetupTarget(' Both '), SetupTarget.both);
    expect(parseSetupTarget('١'), SetupTarget.android);
    expect(parseSetupTarget('۲'), SetupTarget.ios);
    expect(parseSetupTarget('3'), SetupTarget.both);
    for (final value in [null, '', '0', '4', 'yes']) {
      expect(parseSetupTarget(value), isNull);
    }
  });

  test('Android check includes bundletool and both AVDs, never checks Xcode',
      () async {
    final host = studioMac();
    final tools = Toolchain(host);
    final checks = await checkSetupPlatform(tools, SetupPlatform.android);
    final plan = Setup(tools).buildPlan(checks);
    expect(
        checks.map((c) => c.id),
        containsAll([
          'system-image',
          'control-image',
          'avd',
          'control-avd',
          'bundletool'
        ]));
    expect(checks.singleWhere((c) => c.id == 'bundletool').state,
        ToolState.installable);
    expect(plan.steps.map((s) => s.id), contains('bundletool'));
    expect(
        checks.any((c) => c.id.startsWith('ios-') || c.id == 'xcode'), isFalse);
    expect(host.ran.any((c) => c.contains('xcrun')), isFalse);
  });

  test('iOS check never includes Android tools or images', () async {
    final host = FakeHost()
      ..commands['xcrun --find devicectl'] = Proc(0, '/Xcode/devicectl', '');
    final tools = Toolchain(host);
    final checks = await checkSetupPlatform(tools, SetupPlatform.ios);
    expect(checks.map((c) => c.id),
        containsAll(['xcode', 'ios-gadget', 'ios-simulator-gadget']));
    expect(
        checks.map((c) => c.id),
        isNot(anyOf(
            contains('android-sdk'), contains('bundletool'), contains('avd'))));
    expect(Setup(tools).sdkmanagerPackages(Setup(tools).buildPlan(checks)),
        isEmpty);
    expect(host.ran.any((c) => c.contains('sdkmanager') || c.contains('adb ')),
        isFalse);
  });

  test('Both awaits Android before iOS and keeps Android success if iOS fails',
      () async {
    final events = <String>[];
    final result = await runSetupPlatforms(SetupTarget.both,
        hostOs: 'macos',
        prepare: (platform) async {
          events.add('${platform.name}:start');
          await Future<void>.delayed(const Duration(milliseconds: 1));
          events.add('${platform.name}:done');
          if (platform == SetupPlatform.ios) throw StateError('Xcode failure');
          return 0;
        },
        iosUnsupported: () => fail('Mac must support iOS'),
        failed: (platform, error) => events.add('${platform.name}:error'));
    expect(events, [
      'android:start',
      'android:done',
      'ios:start',
      'ios:done',
      'ios:error'
    ]);
    expect(result, {SetupPlatform.android: 0, SetupPlatform.ios: 1});
    expect(setupExitCode(result), 1);
  });

  test('Both on a known non-Mac prepares Android and reports unsupported iOS',
      () async {
    for (final os in ['linux', 'windows']) {
      final ran = <SetupPlatform>[];
      var unsupported = 0;
      final result = await runSetupPlatforms(SetupTarget.both,
          hostOs: os,
          prepare: (platform) async {
            ran.add(platform);
            return 0;
          },
          iosUnsupported: () => unsupported++,
          failed: (_, error) => fail('$error'));
      expect(ran, [SetupPlatform.android]);
      expect(unsupported, 1);
      expect(result, {SetupPlatform.android: 0, SetupPlatform.ios: 1});
      expect(setupExitCode(result), 1);
    }
  });

  test('unknown host attempts Android first, then iOS independently', () async {
    final ran = <SetupPlatform>[];
    final result = await runSetupPlatforms(SetupTarget.both,
        hostOs: null,
        prepare: (platform) async {
          ran.add(platform);
          return platform == SetupPlatform.android ? 1 : 0;
        },
        iosUnsupported: () => fail('unknown host should be checked'),
        failed: (_, e) => fail('$e'));
    expect(ran, [SetupPlatform.android, SetupPlatform.ios]);
    expect(result[SetupPlatform.ios], 0);
    expect(setupExitCode(result), 1);
  });

  test('single-platform runs never invoke the other platform', () async {
    for (final target in [SetupTarget.android, SetupTarget.ios]) {
      final ran = <SetupPlatform>[];
      final result = await runSetupPlatforms(target,
          hostOs: 'macos',
          prepare: (platform) async {
            ran.add(platform);
            return 0;
          },
          iosUnsupported: () => fail('unexpected'),
          failed: (_, e) => fail('$e'));
      expect(ran.single.name, target.name);
      expect(setupExitCode(result), 0);
    }
  });

  test('iOS-only on non-Mac does not start either installer', () async {
    final result = await runSetupPlatforms(SetupTarget.ios,
        hostOs: 'linux',
        prepare: (_) async {
          fail('must not install');
        },
        iosUnsupported: () {},
        failed: (_, e) => fail('$e'));
    expect(result, {SetupPlatform.ios: 1});
  });

  test('non-interactive setup requires an explicit platform even with --yes',
      () async {
    for (final extra in [
      <String>[],
      ['--yes']
    ]) {
      final result = await Process.run(Platform.resolvedExecutable, [
        File('bin/aegis.dart').absolute.path,
        'setup',
        ...extra,
        '--lang',
        'en'
      ]);
      expect(result.exitCode, 2);
      expect(result.stderr, contains('Select --android, --ios or --both'));
      expect(result.stdout, isNot(contains('Preparing')));
    }
  });

  test('conflicting setup flags fail before checking or installing tools',
      () async {
    for (final flags in [
      ['--android', '--ios'],
      ['--both', '--remove'],
      ['--aab', '--ios']
    ]) {
      final result = await Process.run(Platform.resolvedExecutable, [
        File('bin/aegis.dart').absolute.path,
        'setup',
        ...flags,
        '--yes',
        '--lang',
        'en'
      ]);
      expect(result.exitCode, 2);
      expect(result.stderr, contains('Use one of'));
      expect(result.stdout, isEmpty);
    }
  });
}
