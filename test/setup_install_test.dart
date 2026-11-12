import 'dart:io';

import 'package:aegis/src/probe/setup.dart';
import 'package:aegis/src/probe/pins.dart' as pins;
import 'package:aegis/src/probe/toolchain.dart';
import 'package:crypto/crypto.dart' as crypto;
import 'package:test/test.dart';

import 'support/fake_host.dart';
import 'toolchain_test.dart' show studioMac, studioJbr, sdk;

final xzBytes = File('test/fixtures/toolchain/hello.xz').readAsBytesSync();
final xzSha = crypto.sha256.convert(xzBytes).toString();
const sm = '$sdk/cmdline-tools/latest/bin/sdkmanager';
const avdmanager = '$sdk/cmdline-tools/latest/bin/avdmanager';

/// A fake avdmanager that writes where the real one does: ANDROID_AVD_HOME
/// when set, else `$XDG_CONFIG_HOME/.android/avd` when that is set (GitHub's
/// Linux runners), else `~/.android/avd`.
FakeHost withAvdmanager(FakeHost h) {
  h
    ..addFile(avdmanager)
    ..installed.add(avdmanager);
  h.runEffects[avdmanager] = (args, env) {
    if (args.take(2).join(' ') != 'create avd') return;
    final name = args[args.indexOf('-n') + 1];
    final xdg = h.env('XDG_CONFIG_HOME');
    final home = env?['ANDROID_AVD_HOME'] ??
        h.env('ANDROID_AVD_HOME') ??
        (xdg != null ? '$xdg/.android/avd' : '${h.home}/.android/avd');
    h.addDir('$home/$name.avd');
    h.addFile('$home/$name.ini', 'path=$home/$name.avd');
  };
  return h;
}

void main() {
  test('the SDK packages go in one sdkmanager call, with JAVA_HOME', () async {
    final h = studioMac()..installed.add(sm);
    final err = await Setup(Toolchain(h))
        .installSdk(['build-tools;36.0.0', 'emulator']);
    expect(err, isNull);
    final line = h.ran.singleWhere((c) => c.contains('sdkmanager'));
    expect(line, '$sm --sdk_root=$sdk build-tools;36.0.0 emulator');
    expect(h.envOf[line]?['JAVA_HOME'], studioJbr);
  });

  test('avdmanager gets "no" on stdin and no --force', () async {
    final h = withAvdmanager(studioMac());
    final err = await Setup(Toolchain(h)).install('avd');
    expect(err, isNull);
    final line = h.ran.singleWhere((c) => c.contains('avdmanager'));
    expect(line, contains('create avd -n aegis-probe'));
    expect(line, contains('-d pixel_6'));
    expect(line, isNot(contains('--force')));
    expect(h.inputOf[line], 'no\n');
  });

  test(
      'setup plans both image downloads and creates the control with Google Play',
      () async {
    final h = withAvdmanager(studioMac());
    final toolchain = Toolchain(h);
    final setup = Setup(toolchain);
    final plan = setup.buildPlan(await toolchain.checkAll());
    expect(
        setup.sdkmanagerPackages(plan),
        containsAllInOrder([
          'system-images;android-34;google_apis;arm64-v8a',
          'system-images;android-34;google_apis_playstore;arm64-v8a',
        ]));
    expect(await setup.install('control-avd'), isNull);
    expect(
        h.ran,
        contains('$avdmanager create avd -n aegis-probe-control '
            '-k system-images;android-34;google_apis_playstore;arm64-v8a -d pixel_6'));
  });

  test('iOS setup plans Gadget without Android and rejects a corrupt download',
      () async {
    final h = FakeHost()
      ..answer('xcrun', ['--find', 'devicectl'], stdout: '/usr/bin/devicectl')
      ..answer('python3', ['--version'], stdout: 'Python 3.9.6')
      ..answer('python3', ['-c', 'import venv']);
    final tools = Toolchain(h);
    h.answer(tools.venvExe('frida'), ['--version'], stdout: pins.fridaVersion);
    h.downloads[pins.iosGadgetUrl] = xzBytes;
    h.downloads[pins.iosSimulatorGadgetUrl] = xzBytes;
    final setup = Setup(tools);
    final plan = setup.buildPlan(await tools.checkIos());
    expect(plan.coversEverything, isTrue);
    expect(plan.steps.map((step) => step.id),
        ['ios-gadget', 'ios-simulator-gadget']);
    expect(setup.sdkmanagerPackages(plan), isEmpty);
    final outcomes = await setup.execute(plan);
    expect(outcomes.map((o) => o.error),
        everyElement(contains('checksum mismatch')));
    expect(tools.checkIosGadget().ok, isFalse);
    expect(tools.checkIosGadget(simulator: true).ok, isFalse);
    expect(h.files, isEmpty);
  });

  test('verifiedDownload accepts a file whose SHA-256 matches the pin',
      () async {
    final h = studioMac();
    h.downloads['https://x/f.xz'] = xzBytes;
    final err = await Setup(Toolchain(h)).verifiedDownload('https://x/f.xz',
        '/tmp/f.xz', pins.Pinned(xzSha, xzBytes.length), (_) {});
    expect(err, isNull);
    expect(h.fileExists('/tmp/f.xz'), isTrue);
  });

  test('a checksum mismatch deletes the file and fails', () async {
    final h = studioMac();
    h.downloads['https://x/f.xz'] = xzBytes;
    final err = await Setup(Toolchain(h)).verifiedDownload('https://x/f.xz',
        '/tmp/f.xz', const pins.Pinned('deadbeef', 1), (_) {});
    expect(err, contains('checksum mismatch'));
    expect(h.fileExists('/tmp/f.xz'), isFalse);
  });

  test('a failed download installs nothing', () async {
    final h = studioMac(); // no download registered → 404
    final t = Toolchain(h);
    final err = await Setup(t).install('frida-server');
    expect(err, isNotNull);
    expect(h.fileExists(t.fridaServerPath), isFalse);
  });

  test('frida-server install downloads from the pinned URL', () async {
    final h = studioMac();
    final t = Toolchain(h);
    await Setup(t).install('frida-server');
    expect(h.log, contains('download: ${pins.fridaServerUrl('arm64')}'));
  });

  test('frida: creates the venv and pip-installs the pinned versions',
      () async {
    final h = studioMac();
    final t = Toolchain(h);
    h.installed.add(t.venvExe('python')); // venv python runs after creation
    final err = await Setup(t).install('frida');
    expect(err, isNull);
    expect(h.ran.any((c) => c.contains('-m venv')), isTrue);
    final pipUpgrade =
        h.ran.indexWhere((c) => c.endsWith('-m pip install --upgrade pip'));
    final fridaInstall = h.ran.indexWhere((c) => c.contains('frida=='));
    expect(pipUpgrade, greaterThanOrEqualTo(0));
    expect(pipUpgrade, lessThan(fridaInstall), reason: 'pip is upgraded first');
    expect(
        h.ran.any((c) =>
            c.contains('pip install') &&
            c.contains('frida==${pins.fridaVersion}')),
        isTrue);
  });

  test('execute skips a step whose dependency failed, continues the rest',
      () async {
    final h = FakeHost()
      ..answer('flutter', ['config', '--machine'],
          stdout: '{"android-sdk":"$sdk"}')
      ..addDir(sdk)
      ..addFile(sm); // present as a file, but not runnable → sdkmanager fails
    h.downloads[pins.fridaServerUrl('arm64')] = xzBytes;
    final setup = Setup(Toolchain(h));
    final plan = setup.buildPlan([
      ToolCheck('android-sdk', ToolState.present, path: sdk),
      ToolCheck('cmdline-tools', ToolState.present, path: sm),
      ToolCheck('java', ToolState.present, path: studioJbr),
      ToolCheck('emulator', ToolState.present, path: '/e'),
      ToolCheck('system-image', ToolState.installable),
      ToolCheck('avd', ToolState.installable),
      ToolCheck('frida-server', ToolState.installable),
    ]);
    expect(
        plan.steps.map((s) => s.id), ['system-image', 'avd', 'frida-server']);
    final outcomes = await setup.execute(plan);
    final by = {for (final o in outcomes) o.id: o};
    expect(by['system-image']!.error, isNotNull);
    expect(by['avd']!.skipped, isTrue);
    expect(by['avd']!.skippedFor, contains('system-image'));
    // frida-server has no dependency, so it is attempted (not skipped).
    expect(by['frida-server']!.skipped, isFalse);
  });

  test('tools.json is written with schema and present tools', () async {
    final h = studioMac();
    final t = Toolchain(h);
    final checks = await t.checkAll();
    Setup(t).writeToolsJson(checks);
    final json = h.readText(t.toolsJsonPath);
    expect(json, contains('"schema": 1'));
    expect(json, contains('"java"'));
    expect(json, contains('"android-sdk"'));
    expect(json, isNot(contains('"frida-server"')));
  });

  group('the AVD folder', () {
    test('is pinned for avdmanager, so XDG_CONFIG_HOME cannot move it',
        () async {
      // GitHub's Linux runners set XDG_CONFIG_HOME; avdmanager then writes
      // under it while aegis checks ~/.android/avd.
      final h = withAvdmanager(
          studioMac()..envs['XDG_CONFIG_HOME'] = '/Users/dev/.config');
      final toolchain = Toolchain(h);
      expect(await Setup(toolchain).install('avd'), isNull);
      final line = h.ran.singleWhere((c) => c.contains('avdmanager'));
      expect(h.envOf[line]?['ANDROID_AVD_HOME'], '/Users/dev/.android/avd');
      expect(h.envOf[line]?['JAVA_HOME'], studioJbr);
      expect(h.dirExists('/Users/dev/.android/avd'), isTrue);
      expect((await toolchain.checkAvd()).state, ToolState.present);
      expect(h.dirExists('/Users/dev/.config/.android/avd/aegis-probe.avd'),
          isFalse);
    });

    test('follows ANDROID_AVD_HOME when the user set it', () async {
      final h = withAvdmanager(studioMac()..envs['ANDROID_AVD_HOME'] = '/avds');
      final toolchain = Toolchain(h);
      expect(await Setup(toolchain).install('control-avd'), isNull);
      final line = h.ran.singleWhere((c) => c.contains('avdmanager'));
      expect(h.envOf[line]?['ANDROID_AVD_HOME'], '/avds');
      expect(
          (await toolchain.checkAvd(control: true)).state, ToolState.present);
      expect(
          h.fileExists('/avds/aegis-probe-control.avd/.aegis-created'), isTrue);
    });

    test('an AVD avdmanager put elsewhere fails setup at once', () async {
      final h = studioMac()
        ..addFile(avdmanager)
        ..installed.add(avdmanager);
      // Reports success but writes nothing where aegis looks.
      final err = await Setup(Toolchain(h)).install('avd');
      expect(err, contains('aegis-probe is not in /Users/dev/.android/avd'));
    });
  });

  group('remove', () {
    test('deletes the ~/.aegis items and the AVD, never the SDK', () async {
      final h = studioMac();
      final t = Toolchain(h);
      h.addDir(t.venvDir);
      h.addFile('${t.toolsDir}/frida-server-x');
      h.addFile(t.toolsJsonPath, '{}');
      h.addDir('/Users/dev/.android/avd/aegis-probe.avd');
      h.addFile('/Users/dev/.android/avd/aegis-probe.ini', 'x');
      h
        ..addFile(avdmanager)
        ..installed.add(avdmanager);

      final removed = await Setup(t).remove();
      expect(h.dirExists(t.venvDir), isFalse);
      expect(h.fileExists('${t.toolsDir}/frida-server-x'), isFalse);
      expect(h.fileExists(t.toolsJsonPath), isFalse);
      expect(removed.any((r) => r.contains('AVD')), isTrue);
      expect(
          h.ran.any((c) => c.contains('avdmanager delete avd -n aegis-probe')),
          isTrue);
      expect(h.dirExists(sdk), isTrue);
    });

    test('nothing installed → empty', () async {
      expect(await Setup(Toolchain(studioMac())).remove(), isEmpty);
    });
  });
}
