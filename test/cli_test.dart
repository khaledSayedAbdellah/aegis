import 'dart:io';
import 'dart:convert';

import 'package:aegis/aegis.dart';
import 'package:archive/archive.dart';
import 'package:path/path.dart' as p;
import 'package:test/test.dart';
import 'package:yaml/yaml.dart';

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
  test('a corrupt APK manifest fails before scoring', () async {
    final dir = project();
    final manifest = 'broken'.codeUnits;
    final zip = ZipEncoder().encode(Archive()
      ..addFile(ArchiveFile('AndroidManifest.xml', manifest.length, manifest)));
    final apk = put(dir, 'invalid.apk', bytes: zip);
    final r = await aegis([dir.path, '--apk', apk.path, '--offline', '--min-score', '90']);
    expect(r.exitCode, 2);
    expect(r.stderr, contains('AndroidManifest.xml'));
    expect(r.stdout, isNot(contains('100/100')));
  });

  test('strict mode fails when freeRASP calls do not prove startup wiring', () async {
    final dir = project();
    File(p.join(dir.path, 'pubspec.yaml')).writeAsStringSync(
        'name: app\ndependencies:\n  flutter:\n    sdk: flutter\n  freerasp: any\n');
    File(p.join(dir.path, 'lib', 'main.dart')).writeAsStringSync(
        'void main() {}\n'
        'class Talsec { static final instance = Talsec(); '
        'void start(Object value) {} void attachListener(Object value) {} }\n'
        'void neverCalled() { Talsec.instance.attachListener(1); Talsec.instance.start(1); }');
    final report = p.join(dir.path, 'report');
    final r = await aegis([dir.path, '--offline', '--strict', '-f', 'json', '-o', report]);
    expect(r.exitCode, 2);
    expect(r.stderr, contains('AEG-P02'));
    final json = jsonDecode(File('$report.json').readAsStringSync()) as Map;
    final rule = (json['rules'] as List).cast<Map>().singleWhere((r) => r['id'] == 'AEG-P02');
    expect(rule['status'], 'incomplete');
  });

  test('AAB runtime probe requires a matching signed APK', () async {
    final bundle = p.absolute('test/fixtures/aab/vulnerable.aab');
    final missing = await aegis(['probe', bundle, '--lang', 'en']);
    expect(missing.exitCode, 2);
    expect(missing.stderr, contains('--probe-apk'));
    final mismatch = await aegis(['probe', bundle, '--lang', 'en',
      '--probe-apk', p.absolute('test/fixtures/apk/secure.apk')]);
    expect(mismatch.exitCode, 2);
    expect(mismatch.stderr, contains('same package name and version code'));
  });

  test('strict mode catches skipped AAB probes outside MAS-R', () async {
    final dir = project();
    put(dir, 'app.aab', bytes: File('test/fixtures/aab/secure.aab').readAsBytesSync());
    File(p.join(dir.path, 'aegis.yaml')).writeAsStringSync(
        'profile: l1\nlang: en\naab: app.aab\n'
        'probe_apk: dist/signed.apk\nprobe_cert_sha256: invalid\n');
    final report = p.join(dir.path, 'report');
    final args = ['run', dir.path, '--mode', 'aab', '--offline', '--strict',
      '--no-open', '-f', 'json', '-o', report];
    Map readReport() => jsonDecode(File('$report.json').readAsStringSync()) as Map;
    final result = await aegis(args);
    expect(result.exitCode, 2, reason: '${result.stdout}${result.stderr}');
    expect(result.stdout, contains('probe_cert_sha256 must be a SHA-256'));
    expect(result.stderr, contains('audit incomplete (--strict)'));
    expect(readReport()['complete'], isFalse);

    final optedOut = await aegis([...args, '--no-probe']);
    // Opting out of probes must not hide the new partial platform inspection.
    expect(optedOut.exitCode, 2, reason: '${optedOut.stdout}${optedOut.stderr}');
    expect(readReport()['complete'], isFalse);
    final rules = (readReport()['rules'] as List).cast<Map>();
    expect(rules.singleWhere((r) => r['id'] == 'AEG-N05')['status'], 'incomplete');
    expect(rules.singleWhere((r) => r['id'] == 'AEG-R09')['status'], 'notApplicable');
  });

  test('AAB probe resolves the YAML companion path and accepts CLI overrides', () async {
    final dir = project();
    put(dir, 'app.aab', bytes: File('test/fixtures/aab/vulnerable.aab').readAsBytesSync());
    final wrong = put(dir, 'dist/other.apk',
        bytes: File('test/fixtures/apk/secure.apk').readAsBytesSync());
    final config = File(p.join(dir.path, 'aegis.yaml'));
    final hex = List.filled(64, 'a').join();
    config.writeAsStringSync('aab: app.aab\nprobe_apk: dist/other.apk\nprobe_cert_sha256: "$hex"\n');
    final args = ['probe', '--project', dir.path, '--lang', 'en'];
    final configured = await aegis(args);
    expect(configured.exitCode, 2);
    expect(configured.stderr, contains('same package name and version code'));

    final pinOverride = await aegis([...args, '--probe-cert-sha256', 'invalid']);
    expect(pinOverride.stderr, contains('must be a SHA-256'));

    config.writeAsStringSync('aab: app.aab\nprobe_apk: absent.apk\nprobe_cert_sha256: "$hex"\n');
    final pathOverride = await aegis([...args, '--probe-apk', wrong.path]);
    expect(pathOverride.stderr, contains('same package name and version code'));
  });

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
      expect(r.stdout, contains('aegis setup'), reason: 'the next step after init');
      final config = AegisConfig.load(dir.path);
      expect(config.profile.toString(), 'L2');
      expect(config.lang, 'ar');
      expect(config.failOn, Severity.high);
      final yaml = File(p.join(dir.path, 'aegis.yaml')).readAsStringSync();
      final settings = loadYaml(yaml) as Map;
      expect(settings.keys, unorderedEquals([
        'profile', 'lang', 'fail_on', 'min_score', 'scan_packages', 'exclude',
        'rules', 'baseline', 'apk', 'aab', 'ipa', 'probe_apk', 'probe_cert_sha256',
        'ios_control_device', 'ios_jailbreak_device', 'ios_resigned_ipa',
        'ios_simulator', 'ios_simulator_app', 'ios_simulator_flavor',
        'ios_simulator_target', 'ios_xcode_project', 'ios_xcode_scheme',
        'ios_xcode_configuration', 'tracker_signatures', 'runtime_security',
      ]));
      for (final key in ['apk', 'aab', 'ipa', 'probe_apk', 'ios_resigned_ipa',
        'ios_simulator_app', 'ios_simulator_target', 'ios_xcode_project']) {
        expect(settings[key], '<path-to-file>', reason: key);
      }
      expect(config.runtimeSecurity['enabled'], isFalse);
      expect(config.runtimeSecurity['command'], isEmpty);
      expect(config.trackerSignatures, isNull);
      expect(config.scanPackages, isTrue);
      expect(config.minScore, isNull);
      expect(config.exclude, isEmpty);
      expect(config.disabledRules, isEmpty);
      expect(config.severityOverrides, isEmpty);
      expect(config.baseline, 'aegis-baseline.json');
      expect([
        config.apk, config.aab, config.ipa, config.probeApk, config.probeCertSha256,
        config.iosControlDevice, config.iosJailbreakDevice, config.iosResignedIpa,
        config.iosSimulator, config.iosSimulatorApp, config.iosSimulatorFlavor,
        config.iosSimulatorTarget, config.iosXcodeProject, config.iosXcodeScheme,
      ], everyElement(isNull));
      expect(config.iosXcodeConfiguration, 'Release');

      final again = await aegis(['init', dir.path, '--profile', 'l1']);
      expect(again.exitCode, 2);
      expect(await aegis(['init', dir.path, '--profile', 'l1', '--force']).then((r) => r.exitCode), 0);
      expect(AegisConfig.load(dir.path).profile.toString(), 'L1');
    });

    test('unfilled init placeholders allow source audits and request missing IPA paths', () async {
      final dir = project();
      expect((await aegis(['init', dir.path, '--profile', 'l1', '--lang', 'en'])).exitCode, 0);
      final run = await aegis(['run', dir.path, '--mode', 'code', '--offline', '-f', 'json', '-o', p.join(dir.path, 'report')]);
      expect(run.exitCode, 0, reason: '${run.stdout}${run.stderr}');
      expect(jsonDecode(File(p.join(dir.path, 'report.json')).readAsStringSync())['binary'], isNull);
      final ipa = await aegis(['run', dir.path, '--mode', 'ipa']);
      expect(ipa.exitCode, 2);
      expect(ipa.stderr, contains("needs the file's path in aegis.yaml"));
      expect(ipa.stderr, isNot(contains('File not found')));
    });

    test('rejects an unknown profile', () async {
      final r = await aegis(['init', project().path, '--profile', 'bank-ish']);
      expect(r.exitCode, 2);
    });
  });

  group('aegis run', () {
    test('run requires an explicit mode without a terminal, even with a file', () async {
      final dir = project();
      File(p.join(dir.path, 'aegis.yaml')).writeAsStringSync('apk: missing.apk\n');
      for (final extra in [<String>[], ['--apk', 'test/fixtures/apk/secure.apk']]) {
        final r = await aegis(['run', dir.path, ...extra, '--lang', 'en', '--offline']);
        expect(r.exitCode, 2);
        expect(r.stderr, contains('Select a mode explicitly'));
        expect(r.stderr, contains('--mode code'));
        expect(r.stderr, contains('--mode ipa'));
        expect(File(p.join(dir.path, 'build', 'aegis-report.html')).existsSync(), isFalse);
        expect(r.stdout, isNot(contains('Resilience probe')));
      }
    });

    test('all is rejected and run help lists only the four supported modes', () async {
      final r = await aegis(['run', project().path, '--mode', 'all']);
      expect(r.exitCode, 2);
      expect(r.stderr, contains('all'));
      final help = await aegis(['run', '--help']);
      expect(help.exitCode, 0);
      expect(help.stdout, contains('--mode code|apk|aab|ipa'));
      expect(help.stdout, isNot(contains('--mode all')));
      expect(help.stdout, contains('Without --mode'));
    });

    test('run rejects explicit artifact options conflicting with the chosen mode', () async {
      final dir = project();
      for (final options in [
        ['--mode', 'code', '--apk', 'test/fixtures/apk/secure.apk'],
        ['--mode', 'ipa', '--apk', 'test/fixtures/apk/secure.apk'],
        ['--mode', 'apk', '--ipa', 'missing.ipa'],
      ]) {
        final r = await aegis(['run', dir.path, ...options, '--lang', 'en', '--offline']);
        expect(r.exitCode, 2);
        expect(r.stderr, contains('does not match --mode'));
        expect(File(p.join(dir.path, 'build', 'aegis-report.html')).existsSync(), isFalse);
      }
    });

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

    test('apk mode audits the selected APK set in aegis.yaml, wherever it is', () async {
      final dir = project();
      put(dir, 'dist/my-app-1.2.3.apk', bytes: File('test/fixtures/apk/secure.apk').readAsBytesSync());
      File(p.join(dir.path, 'aegis.yaml'))
          .writeAsStringSync('profile: l2+r\nlang: en\napk: dist/my-app-1.2.3.apk\n');
      final r = await aegis(['run', dir.path, '--mode', 'apk', '--offline', '--no-color', '--no-probe', '-f', 'console,json']);
      expect(r.exitCode, isNot(2), reason: '${r.stdout}${r.stderr}');
      expect(r.stdout, contains('auditing the code and dist/my-app-1.2.3.apk'));
      expect(r.stdout, contains('APK: my-app-1.2.3.apk'));
      expect(r.stdout, contains('resilience probe skipped (turned off with --no-probe)'));
      expect(r.stdout, contains('Resilience probe'), reason: 'the report says the probe was skipped');
      expect(r.stdout, isNot(contains('aegis init')), reason: 'aegis.yaml exists');
      final json = File(p.join(dir.path, 'build', 'aegis-report.json')).readAsStringSync();
      expect(json, contains('"skipped"'));
    });

    test('explicit code mode ignores artifact configuration and built APKs', () async {
      final dir = project();
      put(dir, '$flutterApkDir/app-release.apk',
          bytes: File('test/fixtures/apk/secure.apk').readAsBytesSync());
      File(p.join(dir.path, 'aegis.yaml')).writeAsStringSync('profile: l1\nlang: en\napk: missing.apk\nipa: missing.ipa\n');
      final r = await aegis(['run', dir.path, '-m', 'code', '--offline', '--no-color']);
      expect(r.exitCode, isNot(2), reason: '${r.stdout}${r.stderr}');
      expect(r.stdout, isNot(contains('auditing the code and')));
      expect(r.stdout, isNot(contains('Resilience probe')));
    });

    test('aegis probe needs apk:/aab: or a path', () async {
      final dir = project();
      final r = await aegis(['probe', '--project', dir.path]);
      expect(r.exitCode, 2);
      expect(r.stderr, contains('apk: $flutterApkDir/app-release.apk'));
    });

    test('an iOS target selects the configured IPA even when apk: is present', () async {
      final dir = project();
      File(p.join(dir.path, 'aegis.yaml'))
          .writeAsStringSync('apk: dist/android.apk\nipa: dist/ios.ipa\n');
      final r = await aegis(['probe', '--project', dir.path,
        '--only', 'debugger', '--ios-control-device', '00001234-0001234A3C03401E']);
      expect(r.exitCode, 2);
      expect(r.stderr, contains('File not found: ${p.join(dir.path, 'dist', 'ios.ipa')}'));
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
