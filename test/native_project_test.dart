import 'dart:convert';
import 'dart:io';
import 'package:aegis/aegis.dart';
import 'package:aegis/src/project.dart';
import 'package:aegis/src/security/native_analysis.dart';
import 'package:test/test.dart';

void main() {
  late Directory root;
  void put(String path, String text) => File('${root.path}/$path')
    ..parent.createSync(recursive: true)
    ..writeAsStringSync(text);
  RuleResult result(AuditReport r, String id) =>
      r.results.singleWhere((r) => r.meta.id == id);
  Future<AuditReport> audit() => runAudit(root.path,
      config: AegisConfig(profile: ProfileSet.tryParse('l2+r')!),
      offline: true);
  const manifest =
      '<manifest xmlns:android="http://schemas.android.com/apk/res/android"><application android:debuggable="true"/></manifest>';
  setUp(() {
    root = Directory.systemTemp.createTempSync('aegis-native-source-');
    addTearDown(() => root.deleteSync(recursive: true));
  });
  test('native Android modules, Kotlin, Java and Gradle are inspected',
      () async {
    put('app/src/main/AndroidManifest.xml', manifest);
    put('feature/src/main/AndroidManifest.xml', manifest);
    put('app/build.gradle.kts', 'android { defaultConfig { minSdk = 21 } }');
    put('app/src/main/kotlin/Unsafe.kt',
        'fun f() { Cipher.getInstance("AES/ECB/PKCS5Padding") }');
    put('feature/src/main/java/Trust.java',
        'void checkServerTrusted(X509Certificate[] chain, String authType) {}');
    final r = await audit();
    expect(result(r, 'AEG-A01').findings, hasLength(2));
    expect(result(r, 'AEG-A10').status, RuleStatus.failed);
    expect(result(r, 'AEG-N01').findings.single.file, endsWith('Trust.java'));
    expect(result(r, 'AEG-N03').findings.single.file, endsWith('Unsafe.kt'));
    expect(r.results.any((r) => r.meta.id.startsWith('AEG-D')), isFalse);
    // Native apps get the runtime protection rule too: this one has none.
    expect(result(r, 'AEG-P01').findings.single.message,
        startsWith('Android: no RASP package or SDK'));
  });
  test('native Swift, Objective-C, Objective-C++ and plist need no pubspec',
      () async {
    put('Bank/Info.plist',
        '<plist><dict><key>NSAppTransportSecurity</key><dict><key>NSAllowsArbitraryLoads</key><true/></dict></dict></plist>');
    put('Bank/Screen.swift',
        'web.setValue(true, forKey: "allowUniversalAccessFromFileURLs")');
    put('Bank/Store.m',
        'id config = @{ kSecAttrAccessible: kSecAttrAccessibleAlways };');
    put('Bank/Network.mm', '[request setAllowsAnyHTTPSCertificate:YES];');
    final r = await audit();
    expect(result(r, 'AEG-I01').status, RuleStatus.failed);
    expect(result(r, 'AEG-N01').findings.single.file, 'Bank/Network.mm');
    expect(result(r, 'AEG-N02').findings.single.file, 'Bank/Screen.swift');
    expect(result(r, 'AEG-N04').findings.single.file, 'Bank/Store.m');
  });
  test(
      'all four languages find secrets and sensitive logging without leaking values',
      () async {
    final key = 'AKIA${'Z7QW3RT5YU8IO2PL'}';
    put('App.swift', 'let apiKey = "$key"\nprint(accessToken)');
    put('App.kt', 'val apiKey = "$key"\nLog.d("tag", accessToken)');
    put('App.java', 'String apiKey = "$key";\nLog.d("tag", accessToken);');
    put('App.m', 'NSString *apiKey = @"$key";\nNSLog(@"%@", accessToken);');
    final r = await audit();
    expect(result(r, 'AEG-N08').findings, hasLength(4));
    expect(result(r, 'AEG-N09').findings, hasLength(4));
    expect(renderJson(r), isNot(contains(key)));
    expect(result(r, 'AEG-N08').findings.every((f) => f.line == 1), isTrue);
    expect(result(r, 'AEG-N09').findings.every((f) => f.line == 2), isTrue);
  });
  test('vendor/generated/test/excluded and symlink files are not scanned', () {
    put('App.swift', 'let safe = 1');
    for (final path in [
      'Pods/Bad.swift',
      'build/Bad.swift',
      'AppTests/Bad.swift',
      'src/test/Bad.java',
      'skip/Bad.swift'
    ]) {
      put(path,
          'web.setValue(true, forKey: "allowUniversalAccessFromFileURLs")');
    }
    Link('${root.path}/link.swift').createSync('${root.path}/skip/Bad.swift');
    final project =
        Project.load(root.path, config: AegisConfig(exclude: ['skip/**']));
    expect(project.iosNativeSources.map((f) => f.path), ['App.swift']);
  });
  test('read limits preserve findings and mark coverage incomplete', () async {
    put('App.swift',
        'web.setValue(true, forKey: "allowUniversalAccessFromFileURLs")');
    put('Large.swift', ' ' * (4 * 1024 * 1024 + 1));
    final r = await audit();
    expect(result(r, 'AEG-N02').status, RuleStatus.failed);
    expect(result(r, 'AEG-N02').incomplete, isTrue);
    expect(r.complete, isFalse);
  });
  test('CLI code mode works with native source only', () async {
    put('App.kt', 'fun f() { Cipher.getInstance("DES") }');
    final process = await Process.run(Platform.resolvedExecutable, [
      '${Directory.current.path}/bin/aegis.dart',
      'run',
      root.path,
      '--mode',
      'code',
      '--offline',
      '--no-open',
      '--format',
      'json'
    ], environment: {
      'CI': 'true'
    });
    expect(process.exitCode, 0, reason: '${process.stdout}\n${process.stderr}');
    final json = jsonDecode(
        File('${root.path}/build/aegis-report.json').readAsStringSync());
    expect(
        (json['rules'] as List)
            .singleWhere((r) => r['id'] == 'AEG-N03')['status'],
        'failed');
  });
  test('artifact modes also retain native source findings and suppressions',
      () async {
    put('App.kt',
        '// aegis:ignore AEG-N03\nCipher.getInstance("DES")\nCipher.getInstance("AES/ECB/PKCS5Padding")');
    final r = await runAudit(root.path,
        apkPath: 'test/fixtures/apk/secure.apk', offline: true);
    expect(r.binary, isNotNull);
    expect(result(r, 'AEG-N03').findings, hasLength(1));
    expect(result(r, 'AEG-N03').suppressed, 1);
    expect(result(r, 'AEG-N03').findings.single.line, 3);
  });
  test('examples and comments do not masquerade as unsafe native operations',
      () async {
    put('App.swift',
        'let example = #"web.setValue(true, forKey: "allowUniversalAccessFromFileURLs")"#\n/* outer /* nested */ print(accessToken) */\nprint("accessToken")');
    put('App.kt',
        'val example = """Cipher.getInstance("DES")"""\nCipher.getInstance("AES/GCM/NoPadding")');
    final r = await audit();
    for (final id in ['AEG-N01', 'AEG-N02', 'AEG-N03', 'AEG-N09']) {
      expect(result(r, id).findings, isEmpty, reason: id);
    }
  });
  test('excluded Gradle input is not silently treated as inspected', () async {
    put('app/src/main/AndroidManifest.xml', manifest);
    put('app/build.gradle.kts', 'android { defaultConfig { minSdk = 21 } }');
    final r = await runAudit(root.path,
        config: AegisConfig(exclude: ['app/build.gradle.kts']), offline: true);
    expect(result(r, 'AEG-A10').status, RuleStatus.incomplete);
    expect(result(r, 'AEG-A10').findings, isEmpty);
  });
  test('nested comments, raw strings and text blocks preserve offsets', () {
    const input =
        '/* outer /* nested */ ignored */\nlet example = #"web.setValue(true, forKey: "unsafe")"#\nval doc = """\nCipher.getInstance("DES")\n"""\nCipher.getInstance("AES/ECB/PKCS5Padding")';
    final scan = scanNative(input);
    expect(scan.code.length, input.length);
    expect(scan.comments.length, input.length);
    expect(scan.code, isNot(contains('ignored')));
    expect(scan.code, isNot(contains('web.setValue')));
    expect(RegExp('Cipher.getInstance').allMatches(scan.code), hasLength(1));
    expect('\n'.allMatches(scan.code).length, '\n'.allMatches(input).length);
  });
}
