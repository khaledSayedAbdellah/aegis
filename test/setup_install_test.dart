import 'dart:io';

import 'package:aegis/src/probe/setup.dart';
import 'package:aegis/src/probe/pins.dart' as pins;
import 'package:aegis/src/probe/toolchain.dart';
import 'package:test/test.dart';

import 'support/fake_host.dart';
import 'toolchain_test.dart' show studioMac, studioJbr, sdk;

final xzBytes = File('test/fixtures/toolchain/hello.xz').readAsBytesSync();
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

  test('frida-server is downloaded, unpacked, made executable, .xz removed', () async {
    final h = studioMac();
    final url = pins.fridaServerUrl('arm64');
    h.downloads[url] = xzBytes;
    final t = Toolchain(h);
    final err = await Setup(t).install('frida-server');
    expect(err, isNull);
    expect(h.fileExists(t.fridaServerPath), isTrue);
    expect(String.fromCharCodes(h.readBytes(t.fridaServerPath)), 'frida-server test payload\n');
    expect(h.executable, contains(t.fridaServerPath));
    expect(h.fileExists('${t.fridaServerPath}.xz'), isFalse);
  });

  test('a failed download installs nothing', () async {
    final h = studioMac(); // no download registered → 404
    final t = Toolchain(h);
    final err = await Setup(t).install('frida-server');
    expect(err, isNotNull);
    expect(h.fileExists(t.fridaServerPath), isFalse);
  });

  test('bundletool is downloaded to ~/.aegis/tools', () async {
    final h = studioMac();
    h.downloads[pins.bundletoolUrl] = [1, 2, 3];
    final t = Toolchain(h);
    expect(await Setup(t).install('bundletool'), isNull);
    expect(h.fileExists(t.bundletoolPath), isTrue);
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
    expect(by['frida-server']!.ok, isTrue);
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
}
