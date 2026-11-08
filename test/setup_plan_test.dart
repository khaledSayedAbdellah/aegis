import 'package:aegis/src/probe/setup.dart';
import 'package:aegis/src/probe/toolchain.dart';
import 'package:test/test.dart';

import 'support/fake_host.dart';
import 'toolchain_test.dart' show studioMac;

List<ToolCheck> checks(Map<String, ToolState> states) =>
    [for (final e in states.entries) ToolCheck(e.key, e.value)];

void main() {
  test('everything present: nothing to do', () {
    final plan = Setup(Toolchain(FakeHost())).buildPlan([
      for (final id in toolIds) ToolCheck(id, ToolState.present, path: '/x/$id'),
    ]);
    expect(plan.nothingToDo, isTrue);
    expect(plan.coversEverything, isTrue);
  });

  test('a ready Mac installs only the new tools, in order', () async {
    final all = await Toolchain(studioMac()).checkAll();
    final plan = Setup(Toolchain(studioMac())).buildPlan(all);
    expect(plan.steps.map((s) => s.id),
        ['build-tools', 'emulator', 'system-image', 'avd', 'frida', 'frida-server']);
    expect(plan.present.map((c) => c.id),
        containsAll(['flutter', 'java', 'android-sdk', 'cmdline-tools', 'platform-tools', 'python']));
    expect(plan.optional.single.id, 'bundletool');
    expect(plan.blocked, isEmpty);
  });

  test('frida waits for Python; frida-server does not', () {
    final plan = Setup(Toolchain(FakeHost())).buildPlan(checks({
      'python': ToolState.manual,
      'frida': ToolState.installable,
      'frida-server': ToolState.installable,
    }));
    expect(plan.blocked['frida'], ['python']);
    expect(plan.steps.map((s) => s.id), ['frida-server']);
  });

  test('SDK pieces are blocked when the SDK is absent', () {
    final plan = Setup(Toolchain(FakeHost())).buildPlan(checks({
      'android-sdk': ToolState.manual,
      'cmdline-tools': ToolState.manual,
      'java': ToolState.present,
      'platform-tools': ToolState.installable,
      'build-tools': ToolState.installable,
    }));
    expect(plan.steps, isEmpty);
    expect(plan.blocked['platform-tools'], containsAll(['android-sdk', 'cmdline-tools']));
  });

  test('bundletool only when --aab made it installable', () async {
    final without = Setup(Toolchain(studioMac())).buildPlan(await Toolchain(studioMac()).checkAll());
    expect(without.steps.map((s) => s.id), isNot(contains('bundletool')));
    final withAab = Setup(Toolchain(studioMac())).buildPlan(await Toolchain(studioMac()).checkAll(aab: true));
    expect(withAab.steps.last.id, 'bundletool');
  });

  test('the SDK packages are gathered for one sdkmanager call', () async {
    final setup = Setup(Toolchain(studioMac()));
    final plan = setup.buildPlan(await Toolchain(studioMac()).checkAll());
    expect(setup.sdkmanagerPackages(plan),
        ['build-tools;36.0.0', 'emulator', 'system-images;android-34;google_apis;arm64-v8a']);
  });

  test('tools.json lists only present tools with paths', () {
    final json = Setup(Toolchain(FakeHost())).toolsJson([
      ToolCheck('java', ToolState.present, path: '/jbr', version: '21'),
      ToolCheck('frida', ToolState.installable),
      ToolCheck('android-sdk', ToolState.present, path: '/sdk'),
    ]);
    expect(json, contains('"schema": 1'));
    expect(json, contains('"java"'));
    expect(json, contains('"/jbr"'));
    expect(json, isNot(contains('"frida"')));
  });
}
