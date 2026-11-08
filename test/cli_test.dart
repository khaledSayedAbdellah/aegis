import 'dart:io';

import 'package:aegis/aegis.dart';
import 'package:path/path.dart' as p;
import 'package:test/test.dart';

final aegisBin = p.absolute('bin/aegis.dart');

/// Runs the CLI in a fresh process, from the aegis package directory so that
/// its dependencies resolve.
Future<ProcessResult> aegis(List<String> args) =>
    Process.run(Platform.resolvedExecutable, [aegisBin, ...args],
        environment: {'LANG': 'en_US.UTF-8', 'LC_ALL': 'en_US.UTF-8'});

Directory project() {
  final dir = Directory.systemTemp.createTempSync('aegis_cli_');
  addTearDown(() => dir.deleteSync(recursive: true));
  File(p.join(dir.path, 'pubspec.yaml'))
      .writeAsStringSync('name: app\ndependencies:\n  flutter:\n    sdk: flutter\n');
  Directory(p.join(dir.path, 'lib')).createSync();
  File(p.join(dir.path, 'lib', 'main.dart')).writeAsStringSync('void main() {}\n');
  return dir;
}

File put(Directory root, String rel, {List<int>? bytes, DateTime? modified}) {
  final f = File(p.join(root.path, rel))..parent.createSync(recursive: true);
  f.writeAsBytesSync(bytes ?? [0]);
  if (modified != null) f.setLastModifiedSync(modified);
  return f;
}

void main() {
  group('Finding the built APK/AAB', () {
    test('newest release file wins, debug builds are ignored', () {
      final dir = project();
      final t0 = DateTime(2026, 1, 1);
      put(dir, '$flutterApkDir/app-staging-release.apk', modified: t0);
      put(dir, '$flutterApkDir/app-prod-release.apk', modified: t0.add(const Duration(hours: 1)));
      put(dir, '$flutterApkDir/app-debug.apk', modified: t0.add(const Duration(hours: 5)));
      put(dir, '$flutterBundleDir/prodRelease/app-prod-release.aab', modified: t0.add(const Duration(hours: 2)));
      put(dir, '$flutterBundleDir/devDebug/app-dev-debug.aab', modified: t0.add(const Duration(hours: 9)));

      expect(p.basename(findBuiltBinary(dir.path, 'apk')!.path), 'app-prod-release.apk');
      expect(p.basename(findBuiltBinary(dir.path, 'aab')!.path), 'app-prod-release.aab');
      expect(p.basename(findNewestBinary(dir.path)!.path), 'app-prod-release.aab');
    });

    test('nothing built', () {
      final dir = project();
      expect(findBuiltBinary(dir.path, 'apk'), isNull);
      expect(findNewestBinary(dir.path), isNull);
    });

    test('projectOf finds the project a build file came from', () {
      final dir = project();
      final apk = put(dir, '$flutterApkDir/app-prod-release.apk');
      expect(p.canonicalize(projectOf(apk.path)!), p.canonicalize(dir.path));
      // A file outside any Flutter project has none.
      final loose = Directory.systemTemp.createTempSync('aegis_loose_');
      addTearDown(() => loose.deleteSync(recursive: true));
      expect(projectOf(put(loose, 'app.apk').path), isNull);
    });
  });

  test('menu answers in Arabic and Persian digits', () {
    expect(parseMenuChoice('3', 4), 3);
    expect(parseMenuChoice(' 2 \r', 4), 2);
    expect(parseMenuChoice('٣', 4), 3);
    expect(parseMenuChoice('۴', 4), 4);
    expect(parseMenuChoice('5', 4), isNull);
    expect(parseMenuChoice('', 4), isNull);
    expect(parseMenuChoice('\uFFFD', 4), isNull);
    expect(parseMenuChoice(null, 4), isNull);
  });

  group('aegis init', () {
    test('writes aegis.yaml and refuses to overwrite it', () async {
      final dir = project();
      final r = await aegis(['init', dir.path, '--profile', 'l2', '--lang', 'ar']);
      expect(r.exitCode, 0, reason: '${r.stdout}${r.stderr}');
      final config = AegisConfig.load(dir.path);
      expect(config.profile.toString(), 'L2');
      expect(config.lang, 'ar');
      expect(config.failOn, Severity.high);

      final again = await aegis(['init', dir.path, '--profile', 'l1']);
      expect(again.exitCode, 2);
      expect(await aegis(['init', dir.path, '--profile', 'l1', '--force']).then((r) => r.exitCode), 0);
      expect(AegisConfig.load(dir.path).profile.toString(), 'L1');
    });

    test('rejects an unknown profile', () async {
      final r = await aegis(['init', project().path, '--profile', 'bank-ish']);
      expect(r.exitCode, 2);
    });
  });

  group('aegis run', () {
    test('code mode writes the HTML report into the project build folder', () async {
      final dir = project();
      final r = await aegis(['run', dir.path, '--mode', 'code', '--offline', '--no-color']);
      expect(r.exitCode, isNot(2), reason: '${r.stdout}${r.stderr}');
      expect(File(p.join(dir.path, 'build', 'aegis-report.html')).existsSync(), isTrue);
      expect(r.stdout, contains('aegis init'), reason: 'no aegis.yaml yet');
    });

    test('apk mode needs apk: in aegis.yaml, even when an APK is built', () async {
      final dir = project();
      put(dir, '$flutterApkDir/app-release.apk',
          bytes: File('test/fixtures/apk/secure.apk').readAsBytesSync());
      final r = await aegis(['run', dir.path, '--mode', 'apk', '--offline']);
      expect(r.exitCode, 2);
      expect(r.stderr, contains('apk: $flutterApkDir/app-release.apk'));
    });

    test('a path in aegis.yaml that does not exist says how to build it', () async {
      final dir = project();
      File(p.join(dir.path, 'aegis.yaml')).writeAsStringSync('profile: l1\napk: out/app.apk\n');
      final r = await aegis(['run', dir.path, '--mode', 'apk', '--offline']);
      expect(r.exitCode, 2);
      expect(r.stderr, contains('flutter build apk --release'));
      expect(r.stderr, contains('apk: out/app.apk'));
    });

    test('all mode audits the APK set in aegis.yaml, wherever it is', () async {
      final dir = project();
      put(dir, 'dist/my-app-1.2.3.apk', bytes: File('test/fixtures/apk/secure.apk').readAsBytesSync());
      File(p.join(dir.path, 'aegis.yaml'))
          .writeAsStringSync('profile: l2+r\nlang: en\napk: dist/my-app-1.2.3.apk\n');
      final r = await aegis(['run', dir.path, '--offline', '--no-color', '--no-probe', '-f', 'console,json']);
      expect(r.exitCode, isNot(2), reason: '${r.stdout}${r.stderr}');
      expect(r.stdout, contains('auditing the code and dist/my-app-1.2.3.apk'));
      expect(r.stdout, contains('APK: my-app-1.2.3.apk'));
      expect(r.stdout, contains('resilience probe skipped (turned off with --no-probe)'));
      expect(r.stdout, contains('Resilience probe'), reason: 'the report says the probe was skipped');
      expect(r.stdout, isNot(contains('aegis init')), reason: 'aegis.yaml exists');
      final json = File(p.join(dir.path, 'build', 'aegis-report.json')).readAsStringSync();
      expect(json, contains('"skipped"'));
    });

    test('all mode without apk:/aab: audits the code only, even when an APK is built', () async {
      final dir = project();
      put(dir, '$flutterApkDir/app-release.apk',
          bytes: File('test/fixtures/apk/secure.apk').readAsBytesSync());
      File(p.join(dir.path, 'aegis.yaml')).writeAsStringSync('profile: l1\nlang: en\n');
      final r = await aegis(['run', dir.path, '--offline', '--no-color']);
      expect(r.exitCode, isNot(2), reason: '${r.stdout}${r.stderr}');
      expect(r.stdout, contains('no apk:/aab: in aegis.yaml, auditing the code only'));
      expect(r.stdout, isNot(contains('Resilience probe')));
    });

    test('aegis probe needs apk:/aab: or a path', () async {
      final dir = project();
      final r = await aegis(['probe', '--project', dir.path]);
      expect(r.exitCode, 2);
      expect(r.stderr, contains('apk: $flutterApkDir/app-release.apk'));
    });

    test('plain aegis keeps its CI defaults', () async {
      final dir = project();
      final r = await aegis([dir.path, '--offline', '--no-color']);
      expect(r.exitCode, isNot(2), reason: '${r.stdout}${r.stderr}');
      expect(File(p.join(dir.path, 'build', 'aegis-report.html')).existsSync(), isFalse,
          reason: 'only the console report by default');
    });

    test('plain aegis never runs the probe, even with --apk', () async {
      final dir = project();
      final r = await aegis([dir.path, '--apk', 'test/fixtures/apk/secure.apk', '--offline', '--no-color']);
      expect(r.exitCode, isNot(2), reason: '${r.stdout}${r.stderr}');
      expect(r.stdout, isNot(contains('Resilience probe')));
      expect(r.stdout, isNot(contains('aegis-probe emulator')));
    });
  });
}
