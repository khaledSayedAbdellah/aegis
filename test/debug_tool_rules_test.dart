import 'dart:io';

import 'package:aegis/aegis.dart';
import 'package:archive/archive.dart';
import 'package:path/path.dart' as p;
import 'package:test/test.dart';

import 'rules_test.dart' show audit, result;
import 'support/dex_fixture.dart';

const pubspec = 'name: app\ndependencies:\n  flutter:\n    sdk: flutter\n';

List<String> lines(AuditReport r, String id) => result(r, id)
    .findings
    .map((f) => '${f.file}:${f.line} ${f.message}')
    .toList();

void main() {
  test('Dart debug tools used in release code', () async {
    final r = await audit({
      'pubspec.yaml': '$pubspec  alice: any\n  device_preview: any\n'
          '  chucker_flutter: any\n',
      'lib/main.dart': '''
import 'package:alice/alice.dart';
import 'package:device_preview/device_preview.dart';
import 'package:chucker_flutter/chucker_flutter.dart';
final alice = Alice();
void main() {
  ChuckerFlutter.showOnRelease = true;
  runApp(DevicePreview(enabled: true, builder: (c) => const App()));
}
''',
    });
    expect(lines(r, 'AEG-D13'), [
      'lib/main.dart:4 Alice is used outside a debug-only check, so it runs in release builds.',
      'lib/main.dart:7 DevicePreview is used outside a debug-only check, so it runs in release builds.',
      'lib/main.dart:6 Chucker is used outside a debug-only check, so it runs in release builds.',
    ]);
  });

  test('guarded, debug-only and dev-dependency uses pass', () async {
    final r = await audit({
      'pubspec.yaml': '$pubspec  alice: any\n  device_preview: any\n'
          '  chucker_flutter: any\ndev_dependencies:\n  flutter_stetho: any\n',
      'lib/main.dart': '''
import 'package:flutter/foundation.dart';
import 'package:alice/alice.dart';
import 'package:device_preview/device_preview.dart';
import 'package:chucker_flutter/chucker_flutter.dart';
import 'package:flutter_stetho/flutter_stetho.dart';
void main() {
  if (kDebugMode) {
    Alice().showInspector();
  }
  Stetho.initialize();
  final interceptor = ChuckerDioInterceptor();
  runApp(DevicePreview(enabled: !kReleaseMode, builder: (c) => const App()));
}
''',
      'lib/main_dev.dart': '''
import 'package:alice/alice.dart';
final alice = Alice();
''',
    });
    expect(result(r, 'AEG-D13').status, RuleStatus.passed);
  });

  test('Gradle adds debug tools to release builds', () async {
    final r = await audit({
      'android/app/build.gradle': '''
dependencies {
    debugImplementation "com.github.chuckerteam.chucker:library:4.0.0"
    releaseImplementation "com.github.chuckerteam.chucker:library-no-op:4.0.0"
    implementation 'com.facebook.stetho:stetho:1.6.0'
    implementation("com.squareup.leakcanary:leakcanary-android:2.14")
}
''',
    });
    expect(lines(r, 'AEG-D13'), [
      'android/app/build.gradle:4 Stetho is added with `implementation`, so it ships in release builds.',
      'android/app/build.gradle:5 LeakCanary is added with `implementation`, so it ships in release builds.',
    ]);
  });

  test('AEG-B13 finds debug tools in an APK, not their no-op twins', () async {
    final dir = Directory.systemTemp.createTempSync('aegis-debug-apk-');
    addTearDown(() => dir.deleteSync(recursive: true));
    Future<RuleResult> apk(List<String> classes) async {
      final source = ZipDecoder()
          .decodeBytes(File('test/fixtures/apk/secure.apk').readAsBytesSync());
      final archive = Archive();
      for (final f in source.files) {
        if (f.name == 'classes.dex') continue;
        archive.addFile(ArchiveFile.bytes(f.name, f.content as List<int>));
      }
      archive.addFile(ArchiveFile.bytes(
          'classes.dex',
          dexFile({
            for (final c in classes) c: ['x']
          })));
      final path = p.join(dir.path, 'app.apk');
      File(path).writeAsBytesSync(ZipEncoder().encode(archive));
      final r = await runAudit(dir.path,
          apkPath: path,
          config: AegisConfig(profile: ProfileSet.tryParse('l2')!),
          offline: true);
      return result(r, 'AEG-B13');
    }

    final shipped =
        await apk(['com.chuckerteam.chucker.internal.ui.MainActivity']);
    expect(shipped.findings.single.message,
        'Chucker is inside the APK (com.chuckerteam.chucker.internal.ui.MainActivity).');
    final noOp = await apk(['com.chuckerteam.chucker.api.ChuckerInterceptor']);
    expect(noOp.status, RuleStatus.passed);
  });
}
