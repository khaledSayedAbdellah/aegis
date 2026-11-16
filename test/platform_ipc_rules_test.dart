import 'dart:io';

import 'package:aegis/aegis.dart';
import 'package:archive/archive.dart';
import 'package:path/path.dart' as p;
import 'package:test/test.dart';

import 'rules_test.dart' show audit, result;

const pubspec = 'name: app\ndependencies:\n  flutter:\n    sdk: flutter\n';

List<String> lines(AuditReport r, String id) => result(r, id)
    .findings
    .map((f) => '${f.file}:${f.line} ${f.message}')
    .toList();

void main() {
  test('AEG-P13 OAuth flows', () async {
    final r = await audit({
      'pubspec.yaml': '$pubspec  flutter_web_auth_2: any\n',
      'lib/auth.dart': r'''
const implicit = 'https://id.example.com/authorize?response_type=token&client_id=app';
const code = 'https://id.example.com/authorize?response_type=code&client_id=app';
final body = {'client_secret': secret, 'grant_type': 'authorization_code'};
''',
    });
    expect(lines(r, 'AEG-P13'), [
      startsWith('lib/auth.dart:1 Implicit OAuth flow'),
      startsWith('lib/auth.dart:2 Authorization code flow without PKCE'),
      startsWith('lib/auth.dart:3 A client_secret is sent from the app'),
    ]);

    final pkce = await audit({
      'pubspec.yaml': '$pubspec  flutter_web_auth_2: any\n',
      'lib/auth.dart': r'''
final url = 'https://id.example.com/authorize?response_type=code&code_challenge=$c&code_challenge_method=S256';
''',
    });
    expect(result(pkce, 'AEG-P13').status, RuleStatus.passed);
  });

  test('AEG-A15 PendingIntent', () async {
    final r = await audit({
      'android/app/build.gradle': 'android { defaultConfig { targetSdk 30 } }',
      'android/app/src/main/kotlin/Notify.kt': '''
fun notify(context: Context) {
  val implicit = Intent("com.acme.ACTION_OPEN")
  val a = PendingIntent.getActivity(context, 0, implicit, PendingIntent.FLAG_MUTABLE)
  val b = PendingIntent.getBroadcast(context, 1, implicit, 0)
  val explicit = Intent(context, MainActivity::class.java)
  val c = PendingIntent.getActivity(context, 2, explicit, PendingIntent.FLAG_MUTABLE)
  val d = PendingIntent.getActivity(context, 3, implicit, PendingIntent.FLAG_IMMUTABLE)
}
''',
    });
    expect(lines(r, 'AEG-A15'), [
      startsWith(
          'android/app/src/main/kotlin/Notify.kt:3 A FLAG_MUTABLE PendingIntent'),
      startsWith(
          'android/app/src/main/kotlin/Notify.kt:4 A PendingIntent without FLAG_IMMUTABLE'),
    ]);
  });

  test('AEG-A16 FileProvider paths', () async {
    final r = await audit({
      'android/app/src/main/res/xml/file_paths.xml': '''
<paths>
  <root-path name="root" path="" />
  <external-path name="ext" path="." />
  <cache-path name="shared" path="shared/" />
</paths>
''',
    });
    expect(lines(r, 'AEG-A16'), [
      startsWith(
          'android/app/src/main/res/xml/file_paths.xml:2 FileProvider shares <root-path'),
      startsWith(
          'android/app/src/main/res/xml/file_paths.xml:3 FileProvider shares <external-path path="."'),
    ]);
  });

  test('AEG-A17 task hijacking', () async {
    const manifest = '''
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application>
    <activity android:name=".MainActivity" android:exported="true"
        android:launchMode="singleTask" android:taskAffinity="com.acme.task" />
    <activity android:name=".Other" android:allowTaskReparenting="true" />
    <activity android:name=".Safe" android:launchMode="singleTask" />
  </application>
</manifest>''';
    final r = await audit({
      'android/app/src/main/AndroidManifest.xml': manifest,
    });
    expect(lines(r, 'AEG-A17'), [
      startsWith(
          'android/app/src/main/AndroidManifest.xml:3 .MainActivity uses a custom taskAffinity'),
      startsWith('android/app/src/main/AndroidManifest.xml:5 .Other uses'),
    ]);
    final modern = await audit({
      'android/app/src/main/AndroidManifest.xml': manifest,
      'android/app/build.gradle': 'android { defaultConfig { minSdk 30 } }',
    });
    expect(result(modern, 'AEG-A17').status, RuleStatus.passed);
  });

  test('AEG-I14 privacy manifest', () async {
    final r = await audit({
      'ios/Runner/AppDelegate.swift':
          'let seen = UserDefaults.standard.bool(forKey: "seen")',
      'ios/Runner/Info.plist': '<plist><dict/></plist>',
    });
    expect(lines(r, 'AEG-I14'), [
      'ios/Runner/AppDelegate.swift:1 The app\'s own code uses UserDefaults, a '
          'required-reason API, but has no PrivacyInfo.xcprivacy.'
    ]);
    final declared = await audit({
      'ios/Runner/AppDelegate.swift':
          'let seen = UserDefaults.standard.bool(forKey: "seen")',
      'ios/Runner/Info.plist': '<plist><dict/></plist>',
      'ios/Runner/PrivacyInfo.xcprivacy': '<plist><dict/></plist>',
    });
    expect(result(declared, 'AEG-I14').status, RuleStatus.passed);
  });

  test('AEG-C04 dynamic code loading', () async {
    final r = await audit({
      'android/app/src/main/kotlin/Loader.kt': '''
fun load(context: Context) {
  val dex = File(context.getExternalFilesDir(null), "plugin.dex")
  val loader = DexClassLoader(dex.path, context.codeCacheDir.path, null, classLoader)
  System.load(File(context.filesDir, "libextra.so").path)
  System.loadLibrary("native-lib")
}
''',
      'ios/Runner/Plugins.swift': '''
let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
let handle = dlopen(docs.appendingPathComponent("plugin.dylib").path, RTLD_NOW)
let own = dlopen(Bundle.main.path(forResource: "x", ofType: "dylib"), RTLD_NOW)
''',
      'ios/Runner/Info.plist': '<plist><dict/></plist>',
      'App.js': '''
const run = (code) => eval(code);
const fixed = eval("1 + 1");
''',
    });
    expect(lines(r, 'AEG-C04'), [
      startsWith(
          'android/app/src/main/kotlin/Loader.kt:3 DexClassLoader loads code'),
      startsWith(
          'android/app/src/main/kotlin/Loader.kt:4 System.load loads code'),
      startsWith('ios/Runner/Plugins.swift:2 dlopen loads code'),
      startsWith('App.js:1 eval loads code'),
    ]);
  });

  test('AEG-B15 v1-only APK for old Android, not AABs', () async {
    final dir = Directory.systemTemp.createTempSync('aegis-v1-');
    addTearDown(() => dir.deleteSync(recursive: true));
    Future<RuleResult> b15(String apk) async {
      final r = await runAudit(dir.path,
          apkPath: apk,
          config: AegisConfig(profile: ProfileSet.tryParse('l2')!),
          offline: true);
      return r.results.singleWhere((x) => x.meta.id == 'AEG-B15');
    }

    // Signed with v2 (minSdk 21).
    expect((await b15('test/fixtures/apk/vulnerable.apk')).status,
        RuleStatus.passed);
    // Re-zipping drops the APK Signing Block (v2/v3) and keeps the v1
    // signature in META-INF.
    final source = ZipDecoder().decodeBytes(
        File('test/fixtures/apk/vulnerable.apk').readAsBytesSync());
    final v1 = p.join(dir.path, 'v1.apk');
    final copy = Archive();
    for (final f in source.files) {
      copy.addFile(ArchiveFile.bytes(f.name, f.content as List<int>));
    }
    File(v1).writeAsBytesSync(ZipEncoder().encode(copy));
    expect(ApkContext.load(v1).certificates.map((c) => c.scheme), ['v1']);
    expect(
        (await b15(v1)).findings.single.message,
        startsWith(
            'The APK has only a v1 signature and supports Android before 7.0 (minSdk 21)'));
    // An app bundle is always signed with jarsigner: not this rule's business.
    expect((await b15('test/fixtures/aab/vulnerable.aab')).status,
        RuleStatus.notApplicable);
  });

  test('AEG-P01 lists emulator and virtualization checks as extras', () async {
    final r = await audit({
      'lib/guard.dart': '''
import 'dart:io';
const rootPaths = ['/system/xbin/su'];
bool traced() => File('/proc/self/status').readAsStringSync().contains('TracerPid');
bool frida() => File('/proc/self/maps').readAsStringSync().contains('frida');
bool emulator(info) => !info.isPhysicalDevice;
const clones = ['com.lody.virtual', 'com.lbe.parallel'];
''',
      'android/app/src/main/AndroidManifest.xml': '<manifest/>',
    });
    final evidence = r.securityEvidence
        .where((e) => e.ruleId == 'AEG-P01')
        .map((e) => e.detail.en)
        .join(' ');
    expect(
        evidence,
        contains(
            'root, debugger, hooking (Frida/Xposed), emulator, virtualization'));
  });
}
