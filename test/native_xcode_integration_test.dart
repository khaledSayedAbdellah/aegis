import 'dart:io';
import 'package:aegis/aegis.dart';
import 'package:aegis/src/probe/ios_simulator_build.dart';
import 'package:path/path.dart' as p;
import 'package:test/test.dart';
import 'ipa_test.dart' show fixture;

void main() {
  test('real Xcode builds Swift/Objective-C Simulator app without Flutter',
      () async {
    final root =
        Directory.systemTemp.createTempSync('aegis-native-xcode-smoke-');
    addTearDown(() => root.deleteSync(recursive: true));
    final source = Directory('test/fixtures/native_xcode');
    for (final entry in source
        .listSync(recursive: true, followLinks: false)
        .whereType<File>()) {
      final dest =
          File(p.join(root.path, p.relative(entry.path, from: source.path)));
      dest.parent.createSync(recursive: true);
      entry.copySync(dest.path);
    }
    // Synthetic IPA supplies the identity contract; Xcode produces the real app.
    final ipa = IpaContext.load(fixture(root).path);
    final app =
        await IosSimulatorBuilder().ensure(ipa, project: root.path, log: print);
    expect(matchingSimulatorApp(ipa, app), app);
    final verified =
        await Process.run('codesign', ['--verify', '--deep', '--strict', app]);
    expect(verified.exitCode, 0, reason: '${verified.stderr}');
    final reused = await IosSimulatorBuilder().ensure(ipa, project: root.path);
    expect(reused, app);
  },
      skip:
          !Platform.isMacOS || Platform.environment['AEGIS_TEST_XCODE'] != '1',
      timeout: const Timeout(Duration(minutes: 8)));
}
