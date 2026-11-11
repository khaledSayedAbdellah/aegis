import 'dart:convert';
import 'dart:io';
import 'package:aegis/aegis.dart';
import 'package:aegis/src/project.dart';
import 'package:aegis/src/security/script_analysis.dart';
import 'package:test/test.dart';

void main() {
  late Directory root;
  void put(String path, String text) => File('${root.path}/$path')
    ..parent.createSync(recursive: true)
    ..writeAsStringSync(text);
  RuleResult result(AuditReport r, String id) =>
      r.results.singleWhere((r) => r.meta.id == id);
  Future<AuditReport> audit() => runAudit(root.path,
      offline: true,
      config: AegisConfig(profile: ProfileSet.tryParse('l2+r')!));
  setUp(() {
    root = Directory.systemTemp.createTempSync('aegis-cross-platform-');
    addTearDown(() => root.deleteSync(recursive: true));
  });

  test(
      'React Native TSX and JS: findings, offsets, redaction and native bridge',
      () async {
    put(
        'package.json',
        jsonEncode({
          'dependencies': {'react-native': '*', 'expo': '*'}
        }));
    final key = 'AKIA${'Z7QW3RT5YU8IO2PL'}';
    put('src/App.tsx', '''const apiKey = '$key';
console.log(accessToken);
const element = <WebView allowUniversalAccessFromFileURLs={true} mixedContentMode="always" />;
AsyncStorage.setItem('token', accessToken);
CryptoJS.DES.encrypt(value, key);
''');
    put('src/network.js',
        'const agent = new Agent({ rejectUnauthorized: false });');
    put('android/app/src/main/kotlin/Bridge.kt',
        'fun f() { Cipher.getInstance("DES") }');
    final r = await audit();
    for (final id in [
      'AEG-N01',
      'AEG-N02',
      'AEG-N03',
      'AEG-N04',
      'AEG-N08',
      'AEG-N09'
    ]) {
      expect(result(r, id).status, RuleStatus.failed, reason: id);
    }
    expect(result(r, 'AEG-N02').findings, hasLength(2));
    expect(result(r, 'AEG-N09').findings.single.line, 2);
    expect(result(r, 'AEG-N03').findings, hasLength(2));
    expect(renderJson(r), isNot(contains(key)));
    final inventory =
        r.securityEvidence.singleWhere((e) => e.ruleId == 'AEG-S01');
    expect(inventory.data['frameworks'], ['Expo', 'React Native']);
    expect(inventory.data['inspectedFilesByExtension'],
        {'.kt': 1, '.tsx': 1, '.js': 1});
    expect(result(r, 'AEG-S01').counts, isFalse);
    expect(r.results.any((r) => r.meta.id.startsWith('AEG-D')), isFalse);
  });

  test('strings, comments, regular expressions and JSX text are not executable',
      () async {
    put('App.tsx', r'''
// console.log(accessToken)
/* rejectUnauthorized: false */
const docs = "CryptoJS.DES.encrypt(value, key)";
const regex = /console.log(accessToken)/g;
const text = `console.log(accessToken)`;
const view = <Text>console.log(accessToken) <Text>rejectUnauthorized: false</Text></Text>;
console.log('accessToken');
AsyncStorage.setItem('theme', theme);
AsyncStorage.setItem('token', encrypt(accessToken));
const safe = <WebView mixedContentMode="never" allowUniversalAccessFromFileURLs={false} />;
const conditional = ready ? <Text>console.log(accessToken)</Text> : null;
const nested = <Text>{ready && <Text>console.log(password)</Text>}</Text>;
const list = [<Text>console.log(password)</Text>];
''');
    final r = await audit();
    for (final id in [
      'AEG-N01',
      'AEG-N02',
      'AEG-N03',
      'AEG-N04',
      'AEG-N08',
      'AEG-N09'
    ]) {
      expect(result(r, id).findings, isEmpty, reason: id);
    }
  });

  test(
      'template and JSX expressions remain inspected, nested literals stay hidden',
      () async {
    put('src/index.tsx', r'''
const element = <Text>{console.log(accessToken)}</Text>;
console.log(`token: ${accessToken}`);
const x = `value: ${console.log(password)}`;
const y = `${"console.log(password)"}`;
const z = `ignored ${`text ${console.log(apiKey)}`}`;
''');
    final r = await audit();
    expect(result(r, 'AEG-N09').findings.map((f) => f.line), [1, 2, 3, 5]);
  });

  test(
      'KMP common and target sources are scanned once without Android assumptions',
      () async {
    put('shared/src/commonMain/kotlin/Auth.kt',
        'fun save() { println(accessToken) }');
    put('shared/src/iosMain/kotlin/Secure.kt',
        'val access = mapOf(kSecAttrAccessible to kSecAttrAccessibleAlways)');
    put('shared/src/commonTest/kotlin/Fake.kt',
        'fun fake() { println(password) }');
    put('shared/src/iosTest/kotlin/Fake.kt',
        'fun fake() { println(password) }');
    put('shared/src/desktopMain/kotlin/Foo.kt', 'val safe = 1');
    final project = Project.load(root.path);
    expect(project.hasAndroid, isFalse);
    expect(project.sharedNativeSources, hasLength(3));
    expect(project.androidNativeSources, isEmpty);
    final r = await audit();
    expect(result(r, 'AEG-N09').findings.single.file, contains('commonMain'));
    expect(result(r, 'AEG-A01').counts, isFalse);
    expect(result(r, 'AEG-N04').findings.single.file, contains('iosMain'));
    expect(
        r.securityEvidence
            .singleWhere((e) => e.ruleId == 'AEG-S01')
            .data['frameworks'],
        ['Kotlin Multiplatform']);
  });

  test('KMP androidMain manifests and sources retain platform checks',
      () async {
    put('shared/src/androidMain/AndroidManifest.xml',
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android"><application android:debuggable="true"/></manifest>');
    put('shared/src/androidMain/kotlin/Unsafe.kt', 'Cipher.getInstance("DES")');
    final r = await audit();
    expect(result(r, 'AEG-A01').status, RuleStatus.failed);
    expect(result(r, 'AEG-N03').status, RuleStatus.failed);
  });

  test(
      'monorepo discovery ignores dependencies, tests, declarations and outputs',
      () {
    put('apps/mobile/package.json',
        '{"dependencies":{"@capacitor/core":"*","@ionic/angular":"*"}}');
    put('apps/mobile/src/main.ts', 'const safe = 1');
    put('packages/shared/src/shared.mjs', 'console.log(accessToken)');
    for (final path in [
      'node_modules/lib/a.js',
      'apps/mobile/dist/a.js',
      '.expo/a.js',
      'src/__tests__/a.js',
      'src/a.spec.ts',
      'src/a.test.tsx',
      'src/types.d.ts',
      'src/bundle.min.js',
      'excluded/a.js'
    ]) {
      put(path, 'console.log(password)');
    }
    final project =
        Project.load(root.path, config: AegisConfig(exclude: ['excluded/**']));
    expect(project.scriptSources, hasLength(2));
    expect(project.sourceFrameworks, containsAll(['Capacitor', 'Ionic']));
  });

  test('unsupported languages and components make the score provisional',
      () async {
    put('App.ts', 'console.log(accessToken)');
    put('src/Screen.vue', '<script>console.log(password)</script>');
    put('Maui/Store.cs', 'Console.WriteLine(password);');
    final r = await audit();
    expect(result(r, 'AEG-S01').status, RuleStatus.incomplete);
    expect(result(r, 'AEG-N09').status, RuleStatus.failed);
    expect(r.complete, isFalse);
    final inventory =
        r.securityEvidence.singleWhere((e) => e.ruleId == 'AEG-S01');
    expect(inventory.data['unsupportedFiles'],
        containsAll(['src/Screen.vue', 'Maui/Store.cs']));
    expect(renderHtml(r, lang: 'ar'), contains('نطاق تغطية فحص الكود'));
  });

  test('limited syntax retains verified failure but prevents complete pass',
      () async {
    put('main.ts', 'console.log(accessToken);\nconst unfinished = `text');
    final r = await audit();
    expect(result(r, 'AEG-N09').status, RuleStatus.failed);
    expect(result(r, 'AEG-N09').incomplete, isTrue);
    expect(result(r, 'AEG-N08').status, RuleStatus.incomplete);
    expect(r.complete, isFalse);
  });

  test('empty JS project does not get a successful source scan', () async {
    put('package.json', '{"dependencies":{"react-native":"*"}}');
    final r = await audit();
    expect(result(r, 'AEG-S01').status, RuleStatus.incomplete);
    expect(result(r, 'AEG-N08').counts, isFalse);
  });

  test('CLI discovers React Native and KMP and keeps terminal English',
      () async {
    for (final framework in ['react-native', 'kmp']) {
      final path = framework == 'kmp'
          ? '$framework/shared/src/commonMain/kotlin/Main.kt'
          : '$framework/src/Main.ts';
      put(
          path,
          framework == 'kmp'
              ? 'println(accessToken)'
              : 'console.log(accessToken)');
      final process = await Process.run(Platform.resolvedExecutable, [
        'run',
        'bin/aegis.dart',
        'run',
        '${root.path}/$framework',
        '--mode',
        'code',
        '--offline',
        '--no-open',
        '--no-color',
        '--lang',
        'ar',
        '--format',
        'console,json,html',
      ], environment: {
        'CI': 'true'
      });
      expect(process.exitCode, 0,
          reason: '${process.stdout}\n${process.stderr}');
      expect(RegExp(r'[\u0600-\u06ff]').hasMatch(process.stdout.toString()),
          isFalse);
      final reportRoot = '${root.path}/$framework/build/aegis-report';
      final report = jsonDecode(File('$reportRoot.json').readAsStringSync());
      expect(
          (report['rules'] as List)
              .singleWhere((r) => r['id'] == 'AEG-N09')['status'],
          'failed');
      expect(File('$reportRoot.html').readAsStringSync(),
          contains('نطاق تغطية فحص الكود'));
    }
  });

  test('hybrid Flutter plus shared Kotlin and JS uses the same source checks',
      () async {
    put('pubspec.yaml',
        'name: hybrid\ndependencies:\n  flutter:\n    sdk: flutter\n');
    put('lib/main.dart', 'void main() {}');
    put('shared/src/commonMain/kotlin/Auth.kt', 'println(accessToken)');
    put('web-src/Main.ts', 'console.log(password)');
    final r = await audit();
    expect(result(r, 'AEG-N09').findings, hasLength(2));
  });

  test(
      'ambiguous regex statement does not invent a log call or pass completely',
      () async {
    put('main.js', r'if (ok) /console.log(accessToken)/.test(text);');
    final r = await audit();
    expect(result(r, 'AEG-N09').findings, isEmpty);
    expect(result(r, 'AEG-N09').status, RuleStatus.incomplete);
  });

  test('division after a string does not swallow a sensitive logging call',
      () async {
    put('main.js', r"const value = '10' / console.log(accessToken) / 2;");
    final r = await audit();
    expect(result(r, 'AEG-N09').findings, hasLength(1));
  });

  test('artifact mode retains cross-platform findings and inline suppressions',
      () async {
    put('Main.ts',
        '// aegis:ignore AEG-N09\nconsole.log(password);\nconsole.log(accessToken);');
    final r = await runAudit(root.path,
        apkPath: 'test/fixtures/apk/secure.apk', offline: true);
    expect(r.binary, isNotNull);
    expect(result(r, 'AEG-N09').suppressed, 1);
    expect(result(r, 'AEG-N09').findings.single.line, 3);
  });

  test('lexical views keep exact offsets and reject runaway nesting', () {
    const source = 'const x = /a[b\\/]c/;\nconsole.log(accessToken);';
    final scan = scanScript(source);
    expect(scan.code.length, source.length);
    expect(scan.comments.length, source.length);
    expect(scan.code.indexOf('console'), source.indexOf('console'));
    expect(scan.limited, isFalse);
    expect(scanScript('{' * 100).limited, isTrue);
  });
}
