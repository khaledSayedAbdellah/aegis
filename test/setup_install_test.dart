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

void main() {
  test('the SDK packages go in one sdkmanager call, with JAVA_HOME', () async {
    final h = studioMac()..installed.add(sm);
    final err = await Setup(Toolchain(h)).installSdk(['build-tools;36.0.0', 'emulator']);
    expect(err, isNull);
    final line = h.ran.singleWhere((c) => c.contains('sdkmanager'));
    expect(line, '$sm --sdk_root=$sdk build-tools;36.0.0 emulator');
    expect(h.envOf[line]?['JAVA_HOME'], studioJbr);
  });

  test('avdmanager gets "no" on stdin and no --force', () async {
    final h = studioMac()
      ..addFile(avdmanager)
      ..installed.add(avdmanager);
    final err = await Setup(Toolchain(h)).install('avd');
    expect(err, isNull);
    final line = h.ran.singleWhere((c) => c.contains('avdmanager'));
    expect(line, contains('create avd -n aegis-probe'));
    expect(line, contains('-d pixel_6'));
    expect(line, isNot(contains('--force')));
    expect(h.inputOf[line], 'no\n');
  });

  test('verifiedDownload accepts a file whose SHA-256 matches the pin', () async {
    final h = studioMac();
    h.downloads['https://x/f.xz'] = xzBytes;
    final err = await Setup(Toolchain(h))
        .verifiedDownload('https://x/f.xz', '/tmp/f.xz', pins.Pinned(xzSha, xzBytes.length), (_) {});
    expect(err, isNull);
    expect(h.fileExists('/tmp/f.xz'), isTrue);
  });

  test('a checksum mismatch deletes the file and fails', () async {
    final h = studioMac();
    h.downloads['https://x/f.xz'] = xzBytes;
    final err = await Setup(Toolchain(h)).verifiedDownload(
        'https://x/f.xz', '/tmp/f.xz', const pins.Pinned('deadbeef', 1), (_) {});
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

  test('frida: creates the venv and pip-installs the pinned versions', () async {
    final h = studioMac();
    final t = Toolchain(h);
    h.installed.add(t.venvExe('python')); // venv python runs after creation
    final err = await Setup(t).install('frida');
    expect(err, isNull);
    expect(h.ran.any((c) => c.contains('-m venv')), isTrue);
    final pipUpgrade = h.ran.indexWhere((c) => c.endsWith('-m pip install --upgrade pip'));
    final fridaInstall = h.ran.indexWhere((c) => c.contains('frida=='));
    expect(pipUpgrade, greaterThanOrEqualTo(0));
    expect(pipUpgrade, lessThan(fridaInstall), reason: 'pip is upgraded first');
    expect(h.ran.any((c) => c.contains('pip install') && c.contains('frida==${pins.fridaVersion}')), isTrue);
  });

  test('execute skips a step whose dependency failed, continues the rest', () async {
    final h = FakeHost()
      ..answer('flutter', ['config', '--machine'], stdout: '{"android-sdk":"$sdk"}')
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
    expect(plan.steps.map((s) => s.id), ['system-image', 'avd', 'frida-server']);
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

  group('remove', () {
    test('deletes the ~/.aegis items and the AVD, never the SDK', () async {
      final h = studioMac();
      final t = Toolchain(h);
      h.addDir(t.venvDir);
      h.addFile('${t.toolsDir}/frida-server-x');
      h.addFile(t.toolsJsonPath, '{}');
      h.addDir('/Users/dev/.android/avd/aegis-probe.avd');
      h.addFile('/Users/dev/.android/avd/aegis-probe.ini', 'x');
      h..addFile(avdmanager)..installed.add(avdmanager);

      final removed = await Setup(t).remove();
      expect(h.dirExists(t.venvDir), isFalse);
      expect(h.fileExists('${t.toolsDir}/frida-server-x'), isFalse);
      expect(h.fileExists(t.toolsJsonPath), isFalse);
      expect(removed.any((r) => r.contains('AVD')), isTrue);
      expect(h.ran.any((c) => c.contains('avdmanager delete avd -n aegis-probe')), isTrue);
      expect(h.dirExists(sdk), isTrue);
    });

    test('nothing installed → empty', () async {
      expect(await Setup(Toolchain(studioMac())).remove(), isEmpty);
    });
  });
}
