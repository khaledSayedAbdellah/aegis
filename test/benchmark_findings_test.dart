/// Cases the benchmark apps (benchmark/apps.yaml) showed aegis missing or
/// getting wrong, written as small fixtures.
library;

import 'package:aegis/aegis.dart';
import 'package:test/test.dart';

import 'rules_test.dart' show audit, result;

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
        ['ios/Runner/Store.swift:3', 'ios/Runner/Store.swift:4']);
  });
}
