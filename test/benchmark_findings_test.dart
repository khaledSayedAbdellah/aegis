/// Cases the benchmark apps (benchmark/apps.yaml) showed aegis missing or
/// getting wrong, written as small fixtures.
library;

import 'dart:convert';
import 'dart:io';

import 'package:aegis/aegis.dart';
import 'package:archive/archive.dart';
import 'package:aegis/src/binary/axml.dart' show decodeBinaryXml;
import 'package:aegis/src/dart_scanner.dart' show DartFile;
import 'package:aegis/src/rules/debug_guard.dart';
import 'package:path/path.dart' as p;
import 'package:test/test.dart';

import 'rules_test.dart' show audit, result;
import 'support/axml.dart';

Future<List<String>> found(String id, Map<String, String> files) async {
  final r = await audit(files);
  return result(r, id).findings.map((f) => '${f.file}:${f.line}').toList();
}

const _kt = 'android/app/src/main/kotlin/com/example/Main.kt';
const _manifest = '''
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application android:label="app"/>
</manifest>
''';

void main() {
  test('AEG-D08 follows a log line built from secrets', () async {
    expect(
        await found('AEG-D08', {
          'lib/main.dart': r'''
import 'dart:developer' as developer;
String format({required String password, required String token}) =>
    'login password=$password token=$token';
void login(String password, String token) {
  final line = format(password: password, token: token);
  developer.log(line, name: 'app');
  final note = 'saved';
  developer.log(note);
}
''',
        }),
        ['lib/main.dart:6']);
  });

  test('AEG-D08 ignores logs that only came near a secret', () async {
    expect(
        await found('AEG-D08', {
          'lib/main.dart': r'''
Future<void> login(auth, String email, String password) async {
  final result = await auth.signIn(email, password);
  debugPrint('signed in: $result');
  final ok = password.length > 8;
  print('valid: $ok');
  final note = 'user ' + email + ' pw ' + password;
  print(note);
}
''',
        }),
        ['lib/main.dart:7']);
  });

  test('AEG-D16 names the controller, not .text', () async {
    expect(
        await found('AEG-D16', {
          'lib/main.dart': '''
void copy(TextEditingController _secret, TextEditingController _title) {
  Clipboard.setData(ClipboardData(text: _secret.text));
  Clipboard.setData(ClipboardData(text: _title.text));
}
''',
        }),
        ['lib/main.dart:2']);
  });

  test('AEG-A15 follows flags returned by a helper', () async {
    expect(
        await found('AEG-A15', {
          _kt: '''
class Main {
  fun post() {
    val base = Intent("com.example.ACTION")
    val flags = mutableFlags()
    val pi = PendingIntent.getBroadcast(app, 0, base, flags)
  }
  private fun mutableFlags(): Int =
      PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
}
''',
        }),
        ['$_kt:5']);
  });

  test('AEG-A01 reads the release source set manifest', () async {
    expect(
        await found('AEG-A01', {
          'android/app/src/main/AndroidManifest.xml': _manifest,
          'android/app/src/release/AndroidManifest.xml': '''
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:tools="http://schemas.android.com/tools">
  <application
      android:debuggable="true"
      tools:replace="android:debuggable"/>
</manifest>
''',
        }),
        ['android/app/src/release/AndroidManifest.xml:4']);
  });

  test('AEG-D11 reads Kotlin and Java SQL', () async {
    expect(
        await found('AEG-D11', {
          _kt: r'''
class Provider {
  fun query(selection: String?, name: EditText) {
    val where = if (selection.isNullOrEmpty()) "1=1" else selection
    val sql = "SELECT id, name FROM users WHERE $where"
    db.rawQuery(sql, null)
    val qry = "SELECT * FROM users WHERE username='" +
        name.text + "'"
    db.rawQuery(qry, null)
    db.execSQL("INSERT INTO $TABLE ($USERNAME) VALUES ('root')")
    db.execSQL("DROP TABLE IF EXISTS " + TABLE_NAME)
    db.rawQuery("SELECT * FROM users WHERE id = ?", arrayOf(id))
  }
}
''',
        }),
        ['$_kt:5', '$_kt:8']);
  });

  test('AEG-D12: app escape helpers and nested strings', () async {
    expect(
        await found('AEG-D12', {
          'lib/main.dart': r'''
String _jsString(String s) =>
    '"${s.replaceAll(r'\', r'\\').replaceAll('"', r'\"')}"';
Future<void> f(web, String token, String value, String html) async {
  await web.runJavaScript('setToken(${_jsString(token)})');
  await web.loadHtmlString('<p>${htmlEscape(html)}</p>');
  await web.runJavaScript(value.substring('javascript:'.length));
  await web.runJavaScript('show($value)');
}
''',
        }),
        ['lib/main.dart:7']);
  });

  test('AEG-D06 finds keys and IVs in Kotlin and Java', () async {
    expect(
        await found('AEG-D06', {
          _kt: '''
class Crypto {
  private val KEY_ALIAS = "my_key_alias_name"
  private val apiKey = "sk-not-a-cipher-key-123456"
  fun encrypt(data: String): ByteArray {
    val key = "1234567890123456".toByteArray()
    val spec = SecretKeySpec(key, "AES")
    val iv = IvParameterSpec(ByteArray(16))
    return cipher.doFinal(apiKey.toByteArray())
  }
}
''',
          'android/app/src/main/java/com/example/Old.java': '''
class Old {
  String key = "This is the super secret key 123";
  byte[] ivBytes = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
  byte[] run() throws Exception {
    return encrypt(ivBytes, key.getBytes("UTF-8"), new IvParameterSpec(ivBytes));
  }
}
''',
        }),
        unorderedEquals([
          '$_kt:5',
          '$_kt:7',
          'android/app/src/main/java/com/example/Old.java:2',
          'android/app/src/main/java/com/example/Old.java:3',
        ]));
  });

  test('AEG-D07 in Kotlin and Java', () async {
    expect(
        await found('AEG-D07', {
          _kt: '''
fun token(): String {
    val random = Random()
    val token = StringBuilder()
    return token.toString()
}


fun dice() = Random().nextInt(6)



fun safe(): String {
    val password = SecureRandom().nextInt(10)
    return password.toString()
}
''',
        }),
        ['$_kt:2']);
  });

  test('AEG-D07: Flutter widget keys are not crypto', () async {
    expect(
        await found('AEG-D07', {
          'lib/demo.dart': '''
import 'dart:math' as math;
class Demo extends StatelessWidget {
  Demo({super.key, this.seed});
  final int? seed;
  Color pick() => colors[math.Random(seed).nextInt(colors.length)];
}



String otp() {
  final digits = math.Random().nextInt(999999);
  return '\$digits';
}
''',
        }),
        ['lib/demo.dart:11']);
  });

  test('AEG-N03 short RSA and symmetric keys', () async {
    expect(
        await found('AEG-N03', {
          _kt: '''
fun keys() {
    generator.initialize(1024, SecureRandom())
    keyGen.init(56)
    okGenerator.initialize(2048)
}
''',
        }),
        ['$_kt:2', '$_kt:3']);
  });

  test('AEG-D15 Compose fields and XML EditTexts for secrets', () async {
    expect(
        await found('AEG-D15', {
          _kt: '''
@Composable fun Login() {
    TextField(value = pin, onValueChange = {}, label = { Text("PIN") })
    TextField(value = pin, onValueChange = {}, label = { Text("PIN") },
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword))
    TextField(value = name, onValueChange = {}, label = { Text("Name") })
}
''',
          'android/app/src/main/res/layout/login.xml': '''
<LinearLayout>
    <EditText android:id="@+id/password" android:hint="Password"/>
    <EditText android:id="@+id/password2" android:inputType="textPassword"/>
    <EditText android:id="@+id/user" android:hint="User"/>
</LinearLayout>
''',
        }),
        [
          '$_kt:2',
          'android/app/src/main/res/layout/login.xml:2',
        ]);
  });

  test('AEG-D17 Android notifications with codes', () async {
    final r = await audit({
      _kt: '''
fun show(otp: String) {
    builder.setContentTitle("Sign in").setContentText("Your code: " + otp)
}
''',
    });
    final d17 = result(r, 'AEG-D17');
    expect(d17.status, RuleStatus.evidenceOnly);
    expect(d17.note, contains('$_kt:2'));
  });

  test('AEG-D11 in Swift', () async {
    expect(
        await found('AEG-D11', {
          'ios/Runner/Store.swift': r'''
func find(name: String, id: Int32) {
    let sql = "SELECT * FROM users WHERE name = '\(name)'"
    sqlite3_prepare_v2(db, sql, -1, &statement, nil)
    sqlite3_exec(db, "DELETE FROM t WHERE id = \(id)", nil, nil, nil)
    sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS \(table) (id TEXT)", nil, nil, nil)
    try queue.executeQuery("SELECT * FROM t WHERE a = ?", values: [name])
}
''',
        }),
        // `id: Int32` can only be a number.
        ['ios/Runner/Store.swift:3']);
  });

  test('AEG-D11: native numbers pass', () async {
    expect(
        await found('AEG-D11', {
          _kt: r'''
class Dao {
    fun byId(id: Int, limit: Long, name: String) {
        db.rawQuery("SELECT * FROM t WHERE id = $id LIMIT $limit", null)
        db.rawQuery("SELECT * FROM t WHERE n = '$name'", null)
        db.rawQuery("SELECT * FROM t LIMIT ${items.size}", null)
    }
}
''',
          'android/app/src/main/java/com/example/Dao.java': '''
class Dao {
    void byId(long id, String tag) {
        db.rawQuery("SELECT * FROM t WHERE id = " + id, null);
        db.rawQuery("SELECT * FROM t WHERE tag = '" + tag + "'", null);
    }
}
''',
          'ios/Runner/Store.swift': r'''
func find(id: Int32, name: String) {
    sqlite3_exec(db, "DELETE FROM t WHERE id = \(id)", nil, nil, nil)
    sqlite3_exec(db, "DELETE FROM t WHERE name = '\(name)'", nil, nil, nil)
}
''',
        }),
        unorderedEquals([
          '$_kt:4',
          'android/app/src/main/java/com/example/Dao.java:4',
          'ios/Runner/Store.swift:3',
        ]));
  });

  group('false positives found in well-kept apps', () {
    test('AEG-I14: model properties, the macOS target and Expo manifests',
        () async {
      expect(
          await found('AEG-I14', {
            'ios/Runner/AppView.swift': r'''
@Query(sort: \LocalTimeline.creationDate, order: .reverse) var timelines: [LocalTimeline]
''',
            'macos/Runner/AppDelegate.swift': 'let d = UserDefaults.standard\n',
          }),
          isEmpty);
      expect(
          await found('AEG-I14', {
            'ios/Runner/Files.swift':
                'let a = try FileManager.default.attributesOfItem(atPath: p)[.creationDate]\n'
                    'let d = a[FileAttributeKey.creationDate]\n',
          }),
          ['ios/Runner/Files.swift:2']);
      expect(
          await found('AEG-I14', {
            'package.json': '{"dependencies": {"expo": "52.0.0"}}',
            'app.config.js': '''
module.exports = {ios: {privacyManifests: {NSPrivacyAccessedAPITypes: [
  {NSPrivacyAccessedAPIType: 'NSPrivacyAccessedAPICategoryUserDefaults'}]}}}
''',
            'ios/Clip/ViewController.swift': 'let d = UserDefaults.standard\n',
          }),
          isEmpty);
    });

    test('AEG-A02: a library module that does not set backup', () async {
      final dir = Directory.systemTemp.createTempSync('aegis_lib_');
      addTearDown(() => dir.deleteSync(recursive: true));
      ({
        'settings.gradle.kts': 'include(":app", ":core")\n',
        'app/build.gradle.kts': 'plugins { id("com.android.application") }\n',
        'app/src/main/AndroidManifest.xml': '''
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application android:allowBackup="false"/>
</manifest>
''',
        'core/build.gradle.kts':
            'plugins { alias(libs.plugins.nowinandroid.android.library) }\n',
        'core/src/main/AndroidManifest.xml': '''
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application/>
</manifest>
''',
      }).forEach((path, text) {
        final f = File(p.join(dir.path, path));
        f.parent.createSync(recursive: true);
        f.writeAsStringSync(text);
      });
      final r = await runAudit(dir.path, offline: true);
      expect(result(r, 'AEG-A02').findings, isEmpty);
    });

    test('AEG-N09: a flag named like a secret is not logged data', () async {
      expect(
          await found('AEG-N09', {
            'package.json': '{"dependencies": {"react-native": "0.76.0"}}',
            'src/FeedCard.tsx': '''
export function update(pin: boolean, token: string) {
  const label = pin ? 'pin' : 'save'
  logger.error('failed to update feeds', {pin})
  console.log(`token: \${token}`)
}
''',
          }),
          ['src/FeedCard.tsx:4']);
    });
  });

  test('file searches skip node_modules, Pods, .git and build', () async {
    final key = ['AI', 'za', 'Sy', 'C' * 33].join();
    String manifest() =>
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android">'
        '<application><meta-data android:name="k" android:value="$key"/></application></manifest>\n';
    final r = await audit({
      'android/app/src/main/AndroidManifest.xml': manifest(),
      'node_modules/some-lib/android/src/main/AndroidManifest.xml': manifest(),
      'ios/Pods/Lib/Info.plist': '<plist><string>$key</string></plist>',
      '.git/info/AndroidManifest.xml': manifest(),
      'android/app/build/intermediates/AndroidManifest.xml': manifest(),
    });
    expect(result(r, 'AEG-N08').findings.map((f) => f.file),
        ['android/app/src/main/AndroidManifest.xml']);
  });

  group('reported by the owner', () {
    // Built at run time: no literal key shape in the repository.
    final key = ['AI', 'za', 'Sy', 'B' * 33].join();

    test('AEG-N08: Google API keys in the manifest, Info.plist and strings',
        () async {
      final r = await audit({
        'android/app/src/main/AndroidManifest.xml': '''
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application android:label="app">
    <!-- <meta-data android:name="old" android:value="$key"/> -->
    <meta-data android:name="com.google.android.geo.API_KEY" android:value="$key"/>
  </application>
</manifest>
''',
        'android/app/src/main/res/values/strings.xml':
            '<resources><string name="maps_key">$key</string></resources>\n',
        'android/app/src/debug/res/values/strings.xml':
            '<resources><string name="maps_key">$key</string></resources>\n',
        'ios/Runner/Info.plist':
            '<plist><dict>\n<key>GMSApiKey</key>\n<string>$key</string>\n</dict></plist>\n',
        'ios/Runner/GoogleService-Info.plist':
            '<plist><dict><key>API_KEY</key><string>$key</string></dict></plist>\n',
      });
      expect(
          result(r, 'AEG-N08').findings.map((f) => '${f.file}:${f.line}'),
          unorderedEquals([
            'android/app/src/main/AndroidManifest.xml:4',
            'android/app/src/main/res/values/strings.xml:1',
            'ios/Runner/Info.plist:3',
          ]));
      expect(result(r, 'AEG-N08').findings.map((f) => f.snippet).toSet(),
          {'[redacted]'});
    });

    test('AEG-B06: a Google API key in the APK manifest meta-data', () async {
      final dir = Directory.systemTemp.createTempSync('aegis_b06_');
      addTearDown(() => dir.deleteSync(recursive: true));
      final manifest = axml(AxmlElement('manifest', [
        (false, 'package', 'com.acme.bank')
      ], [
        AxmlElement('application', [], [
          AxmlElement('meta-data', [
            (true, 'name', 'com.google.android.geo.API_KEY'),
            (true, 'value', key),
          ]),
        ]),
      ]));
      expect(decodeBinaryXml(manifest),
          contains('com.google.android.geo.API_KEY'));
      final source = ZipDecoder()
          .decodeBytes(File('test/fixtures/apk/secure.apk').readAsBytesSync());
      final archive = Archive();
      for (final f in source.files) {
        if (f.name == 'AndroidManifest.xml') continue;
        archive.addFile(ArchiveFile.bytes(f.name, f.content as List<int>));
      }
      archive.addFile(ArchiveFile.bytes('AndroidManifest.xml', manifest));
      final apk = p.join(dir.path, 'app.apk');
      File(apk).writeAsBytesSync(ZipEncoder().encode(archive));
      final r = await runAudit(dir.path,
          apkPath: apk,
          config: AegisConfig(profile: ProfileSet.tryParse('l2')!),
          offline: true);
      expect(result(r, 'AEG-B06').findings.map((f) => f.message),
          ['Google API key found in a <meta-data> of the final manifest.']);
    });

    test('AEG-P03 reads signingCertHashes in every list form', () async {
      const hash = 'mVr/qQLO8DKTwqlL+B1qigl9NoBnbiUs8b4c2Ewcz0k=';
      for (final hashes in [
        "['$hash']",
        "[\n        '$hash',\n      ]",
        "<String>[\n        '$hash',\n      ]",
        "const [\n        '$hash',\n      ]",
        'kHashes',
      ]) {
        final r = await audit({
          'pubspec.yaml':
              'name: app\ndependencies:\n  flutter:\n    sdk: flutter\n'
                  '  freerasp: ^6.0.0\n',
          'lib/main.dart': '''
import 'package:freerasp/freerasp.dart';
Future<void> main() => Talsec.instance.start(TalsecConfig(
    androidConfig: AndroidConfig(
      packageName: 'com.example.app',
      signingCertHashes: $hashes,
    ),
    watcherMail: 'security@example.com'));
''',
          'lib/hashes.dart': "const kHashes = [\n  '$hash',\n];\n",
        });
        final messages = result(r, 'AEG-P03').findings.map((f) => f.message);
        expect(messages, isNot(contains(contains('no signingCertHashes'))),
            reason: hashes);
        expect(messages, isNot(contains(contains('empty'))), reason: hashes);
        expect(messages, contains(startsWith('Only one signing hash')),
            reason: hashes);
      }
    });
  });

  group('outside review (phase H)', () {
    test('H4: a new advisory on a baselined package is new', () {
      Finding f(String m) => Finding(
          ruleId: 'AEG-C01', message: m, file: 'android/app/build.gradle');
      final old = f('Maven com.squareup.okhttp3:okhttp 3.12.0: CVE-2021-0341 '
          '(https://osv.dev/vulnerability/CVE-2021-0341)');
      final other = f('Maven com.squareup.okhttp3:okhttp 4.9.9: CVE-2023-9999 '
          '(https://osv.dev/vulnerability/CVE-2023-9999)');
      final upgraded =
          f('Maven com.squareup.okhttp3:okhttp 3.14.9: CVE-2021-0341 '
              '(https://osv.dev/vulnerability/CVE-2021-0341)');
      expect(Baseline.fingerprint(old), isNot(Baseline.fingerprint(other)));
      expect(Baseline.fingerprint(old), Baseline.fingerprint(upgraded),
          reason: 'versions are still normalized');
      final ghsa1 = f('npm lodash 4.17.4: GHSA-jf85-cpcp-j695');
      final ghsa2 = f('npm lodash 4.17.4: GHSA-p6mc-m468-83gw');
      expect(Baseline.fingerprint(ghsa1), isNot(Baseline.fingerprint(ghsa2)));
      // Counts and line numbers still don't matter.
      expect(Baseline.fingerprint(f('3 exported components')),
          Baseline.fingerprint(f('5 exported components')));
    });

    test('H4: a baseline written with older fingerprints still matches',
        () async {
      final dir = Directory.systemTemp.createTempSync('aegis_oldbase_');
      addTearDown(() => dir.deleteSync(recursive: true));
      File(p.join(dir.path, 'pubspec.yaml')).writeAsStringSync('name: app\n');
      Directory(p.join(dir.path, 'lib')).createSync();
      File(p.join(dir.path, 'lib', 'a.dart'))
          .writeAsStringSync("const u = 'http://api.shop-backend.net/x';\n");
      final first = await runAudit(dir.path, offline: true);
      final message = first.results
          .firstWhere((x) => x.meta.id == 'AEG-D02')
          .findings
          .single
          .message;
      // As 0.17 wrote it: a fingerprint computed the old way.
      final file = p.join(dir.path, 'aegis-baseline.json');
      File(file).writeAsStringSync(jsonEncode({
        'findings': [
          {
            'fingerprint': '0123456789abcdef',
            'rule': 'AEG-D02',
            'file': 'lib/a.dart',
            'message': message,
            'count': 1,
          }
        ]
      }));
      final again = await runAudit(dir.path,
          offline: true, baseline: Baseline.load(file));
      expect(
          again.results
              .firstWhere((x) => x.meta.id == 'AEG-D02')
              .findings
              .single
              .baselined,
          isTrue);
    });

    test('H3: a secret finding carries its pattern\'s severity', () async {
      final aws = ['AKIA', 'IOSFODNN7', 'EXAMPLE'].join();
      final google = ['AI', 'za', 'Sy', 'D' * 33].join();
      final both = await audit({
        'lib/a.dart': "const k = '$aws';\nconst g = '$google';\n",
      });
      final d01 = result(both, 'AEG-D01');
      expect(d01.severity, Severity.critical);
      expect(d01.findings.map((f) => f.severity),
          [Severity.critical, Severity.medium]);
      // A critical problem caps the score in the critical band.
      expect(both.score.value, lessThan(40));
      final sarif = jsonDecode(renderSarif(both)) as Map;
      final levels = [
        for (final x in sarif['runs'][0]['results'] as List)
          if (x['ruleId'] == 'AEG-D01') x['level']
      ];
      expect(levels, ['error', 'warning']);

      final googleOnly = await audit({'lib/a.dart': "const g = '$google';\n"});
      expect(result(googleOnly, 'AEG-D01').severity, Severity.medium);

      // A severity set in aegis.yaml still wins.
      final dir = Directory.systemTemp.createTempSync('aegis_sev_');
      addTearDown(() => dir.deleteSync(recursive: true));
      File(p.join(dir.path, 'pubspec.yaml')).writeAsStringSync('name: app\n');
      Directory(p.join(dir.path, 'lib')).createSync();
      File(p.join(dir.path, 'lib', 'a.dart'))
          .writeAsStringSync("const k = '$aws';\n");
      final r = await runAudit(dir.path,
          config: AegisConfig.parse('rules:\n  AEG-D01: low\n'), offline: true);
      expect(result(r, 'AEG-D01').severity, Severity.low);
    });

    test('H5: AEG-D01 reads generated files such as envied output', () async {
      final aws = ['AKIA', 'IOSFODNN7', 'EXAMPLE'].join();
      final r = await audit({
        'lib/env.dart': "part 'env.g.dart';\n",
        'lib/env.g.dart':
            "part of 'env.dart';\nfinal class _Env { static const String awsKey = '$aws'; }\n",
        'lib/model.freezed.dart':
            "const url = 'http://api.shop-backend.net/x';\n",
      });
      expect(result(r, 'AEG-D01').findings.map((f) => '${f.file}:${f.line}'),
          ['lib/env.g.dart:2']);
      // Code-pattern rules still skip generated files.
      expect(result(r, 'AEG-D02').findings, isEmpty);
    });

    test('H2: AEG-D03 is not turned off by words in strings or comments',
        () async {
      final r = await audit({
        'lib/main.dart': r'''
import 'dart:io';
bool _accept(X509Certificate c, String h, int p) => true;
void f(HttpClient client) {
  HttpClient().badCertificateCallback = (a, b, d) { print('cert from provider ignored'); return true; };
  HttpClient().badCertificateCallback = (a, b, d) {
    // the header and builder are fine
    return true;
  };
  final cb = (c, h, p) => true;
  client.badCertificateCallback = cb;
  client.badCertificateCallback = _accept;
  HttpClient().badCertificateCallback = (cert, host, port) { return cert.sha1.toString() == pinned; };
  HttpClient().badCertificateCallback = (cert, host, port) { if (host == 'dev.local') return true; return false; };
  HttpClient().badCertificateCallback = (cert, host, port) { return isPinned(cert); };
}
''',
      });
      expect(result(r, 'AEG-D03').findings.map((f) => f.line), [4, 5, 10, 11]);
    });

    test('H1: a debug guard is read from the code, not nearby text', () async {
      final r = await audit({
        'lib/main.dart': r'''
import 'dart:io';
import 'package:flutter/foundation.dart';
void a() {
  if (!kDebugMode) {
    HttpClient().badCertificateCallback = (x, y, z) => true;
  }
}
void b() {
  if (kDebugMode) {
    print('debug');
  }
  HttpClient().badCertificateCallback = (x, y, z) => true;
}
void c() {
  assert(true);
  HttpClient().badCertificateCallback = (x, y, z) => true;
}
void d() {
  // only in kDebugMode
  HttpClient().badCertificateCallback = (x, y, z) => true;
}
void e() {
  if (isDebuggerAttached()) exit(1);
  HttpClient().badCertificateCallback = (x, y, z) => true;
}
void f() {
  if (kDebugMode || remoteFlag) {
    HttpClient().badCertificateCallback = (x, y, z) => true;
  }
}
void g() {
  if (kReleaseMode) {
    print('release');
  } else {
    HttpClient().badCertificateCallback = (x, y, z) => true;
  }
  if (kDebugMode) {
    HttpClient().badCertificateCallback = (x, y, z) => true;
  }
  if (!kReleaseMode) HttpClient().badCertificateCallback = (x, y, z) => true;
  assert(() {
    HttpClient().badCertificateCallback = (x, y, z) => true;
    return true;
  }());
}
void i() {
  if (!kDebugMode) return;
  HttpClient().badCertificateCallback = (x, y, z) => true;
}
void j(Config config) {
  if (config.enableLogging && Platform.isAndroid) {
    HttpClient().badCertificateCallback = (x, y, z) => true;
  }
}
''',
      });
      // a) negated guard, b) after a guarded block, c) assert(true) above,
      // d) a comment, e) isDebuggerAttached and f) `||` with a non-debug
      // part are all reported.
      expect(result(r, 'AEG-D03').findings.map((f) => f.line),
          [5, 12, 16, 20, 24, 28]);
    });

    test('H1: the true branch of a debug ternary is guarded', () {
      final f = DartFile('lib/a.dart', '''
final a = kDebugMode ? LogInterceptor() : null;
final b = kDebugMode ? null : LogInterceptor();
final c = isDebuggerAttached ? LogInterceptor() : null;
final d = !kReleaseMode ? LogInterceptor() : null;
''');
      final guarded = [
        for (var i = 0; i < f.tokens.length; i++)
          if (f.tokens[i].text == 'LogInterceptor') guardedByDebugBuild(f, i)
      ];
      expect(guarded, [true, false, false, true]);
    });

    test('H6: AEG-D02 allowlisted hosts end at the host', () async {
      final r = await audit({
        'lib/main.dart': '''
const a = 'http://localhost.acme-prod.com/api';
const b = 'http://example.com.acme.io/login';
const c = 'http://10.0.2.25/api';
const d = 'http://127.0.0.1.evil.io/x';
const ok1 = 'http://localhost:8080/ok';
const ok2 = 'http://10.0.2.2:8080/ok';
const ok3 = 'http://127.0.0.1/ok';
const ok4 = 'http://example.com';
const ok5 = 'http://schemas.android.com/apk/res/android';
const ok6 = 'http://www.w3.org/2000/svg';
const ok7 = 'http://[::1]:3000/';
''',
      });
      expect(result(r, 'AEG-D02').findings.map((f) => f.line), [1, 2, 3, 4]);
    });
  });

  group('second outside review (phase I)', () {
    test('I3: a nullable type is not a debug ternary', () async {
      final r = await audit({
        'lib/main.dart': r'''
import 'dart:io';
DevConfig? loadDevConfig() { HttpClient().badCertificateCallback = (a, b, d) => true; return null; }
class DevConfig {}
class Holder {
  DebugInfo? info = DebugInfo(HttpClient()..badCertificateCallback = (a, b, d) => true);
  Map<String, DevConfig?> configs() { HttpClient().badCertificateCallback = (a, b, d) => true; return {}; }
}
List<DebugInfo?> items() { HttpClient().badCertificateCallback = (a, b, d) => true; return []; }
void ok(HttpClient h) {
  h.badCertificateCallback = kDebugMode ? (a, b, d) => true : null;
}
''',
      });
      expect(result(r, 'AEG-D03').findings.map((f) => f.line), [2, 5, 6, 8]);
    });

    test('I4: reading the certificate is not checking it', () async {
      final r = await audit({
        'lib/main.dart': r'''
import 'dart:io';
void f() {
  HttpClient().badCertificateCallback = (c, h, p) { debugPrint(c.subject); return true; };
  HttpClient().badCertificateCallback = (c, h, p) { log('sha ${c.sha1}', c.pem); return true; };
  HttpClient().badCertificateCallback = (c, h, p) { final same = c.issuer; print(same); return true; };
  HttpClient().badCertificateCallback = (c, h, p) { if (c.subject.contains('acme')) return true; return false; };
  HttpClient().badCertificateCallback = (c, h, p) { if (h == 'api.acme.io') { return true; } return false; };
  HttpClient().badCertificateCallback = (c, h, p) { return c.sha1.toString() == pinned; };
  HttpClient().badCertificateCallback = (c, h, p) { for (final x in allowedHashes) { if (x == c.sha1) return true; } return false; };
}
''',
      });
      expect(result(r, 'AEG-D03').findings.map((f) => f.line), [3, 4, 5]);
    });

    test('I5: a callback variable is resolved in its own scope', () async {
      final r = await audit({
        'lib/main.dart': r'''
import 'dart:io';
final topLevel = (X509Certificate c, String h, int p) => true;
void a() { final cb = (X509Certificate c, String h, int p) => true; }
void main() {
  final cb = (X509Certificate c, String h, int p) => h == 'x';
  HttpClient().badCertificateCallback = cb;
}
void b() {
  final cb = (X509Certificate c, String h, int p) => true;
  HttpClient().badCertificateCallback = cb;
}
void c() {
  HttpClient().badCertificateCallback = topLevel;
}
void d(bool Function(X509Certificate, String, int) topLevel) {
  HttpClient().badCertificateCallback = topLevel;
}
class Api {
  final onBad = (X509Certificate c, String h, int p) => true;
  void e() {
    var onBad = (X509Certificate c, String h, int p) => h == 'x';
    HttpClient().badCertificateCallback = onBad;
  }
  void g() {
    HttpClient().badCertificateCallback = onBad;
  }
}
''',
      });
      expect(result(r, 'AEG-D03').findings.map((f) => f.line), [10, 13, 25]);
    });
    test('I1: --fail-on and Azure read only the new findings\' severity',
        () async {
      final dir = Directory.systemTemp.createTempSync('aegis_newsev_');
      addTearDown(() => dir.deleteSync(recursive: true));
      File(p.join(dir.path, 'pubspec.yaml')).writeAsStringSync('name: app\n');
      Directory(p.join(dir.path, 'lib')).createSync();
      final main = File(p.join(dir.path, 'lib', 'main.dart'));
      final aws = ['AKIA', 'IOSFODNN7', 'EXAMPLE'].join();
      main.writeAsStringSync("const k = '$aws';\nvoid main() {}\n");
      final first = await runAudit(dir.path, offline: true);
      final baseline = Baseline.fromResults(first.results);
      // A new high finding next to the baselined critical one.
      main.writeAsStringSync("const k = '$aws';\nvoid main() {}\n"
          "const apiSecret = 'q8Zr2LmX9vT4kP1wYb7N';\n");
      final r = await runAudit(dir.path, offline: true, baseline: baseline);
      final d01 = result(r, 'AEG-D01');
      expect(d01.severity, Severity.critical, reason: 'worst of all findings');
      expect(d01.newSeverity, Severity.high);
      expect(r.countAtLeast(Severity.critical), 0);
      expect(r.countAtLeast(Severity.high), 1);
      final azure = renderAzure(r, failOn: Severity.critical);
      expect(azure, contains('type=warning;code=AEG-D01'));
      expect(azure, contains('[high]'));
      expect(azure, isNot(contains('[critical]')));
      // The new-findings sections show the new finding's severity.
      final console = ConsoleReporter(color: false).render(r);
      expect(console, contains('[1] HIGH'));
      expect(console, isNot(contains('CRITICAL Hardcoded')));
      expect(renderMarkdown(r), contains('— HIGH'));
      expect(renderMarkdown(r), isNot(contains('— CRITICAL')));
    });

    test('I1: a severity set in aegis.yaml is every finding\'s', () async {
      final dir = Directory.systemTemp.createTempSync('aegis_oversev_');
      addTearDown(() => dir.deleteSync(recursive: true));
      File(p.join(dir.path, 'pubspec.yaml')).writeAsStringSync('name: app\n');
      Directory(p.join(dir.path, 'lib')).createSync();
      final aws = ['AKIA', 'IOSFODNN7', 'EXAMPLE'].join();
      File(p.join(dir.path, 'lib', 'a.dart'))
          .writeAsStringSync("const k = '$aws';\n");
      final r = await runAudit(dir.path,
          config: AegisConfig.parse('rules:\n  AEG-D01: low\n'), offline: true);
      final d01 = result(r, 'AEG-D01');
      expect(d01.findings.map(d01.severityOf), [Severity.low]);
      expect(r.countAtLeast(Severity.medium), 0);
      expect(renderAzure(r), contains('[low]'));
    });

    test('I2: a finding without an advisory id keeps its old fingerprint', () {
      // Pinned: changing it closes and reopens every code-scanning alert
      // and breaks existing baselines.
      expect(
          Baseline.fingerprint(Finding(
              ruleId: 'AEG-D01',
              message: 'AWS access key found.',
              file: 'lib/main.dart')),
          '9867b981083b1c05');
      expect(Baseline.fingerprintOf('AEG-D01', 'lib/main.dart', ''),
          Baseline.fingerprintOf('AEG-D01', 'lib/main.dart', ' '));
    });

    test('I2: a baseline entry without a message still matches', () async {
      final dir = Directory.systemTemp.createTempSync('aegis_nomsg_');
      addTearDown(() => dir.deleteSync(recursive: true));
      final f = Finding(ruleId: 'AEG-X01', message: '', file: 'lib/a.dart');
      final file = p.join(dir.path, 'aegis-baseline.json');
      File(file).writeAsStringSync(jsonEncode({
        'findings': [
          {
            // As 0.17 wrote it.
            'fingerprint': 'b405112eccf35ddb',
            'rule': 'AEG-X01',
            'file': 'lib/a.dart',
            'message': '',
          }
        ]
      }));
      expect(Baseline.load(file).entries.keys, [Baseline.fingerprint(f)]);
    });
  });
}
