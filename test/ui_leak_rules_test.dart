import 'package:aegis/aegis.dart';
import 'package:test/test.dart';

import 'rules_test.dart' show audit, result;

const pubspec = 'name: app\ndependencies:\n  flutter:\n    sdk: flutter\n';

List<String> lines(AuditReport r, String id) =>
    result(r, id).findings.map((f) => '${f.line}: ${f.message}').toList();

void main() {
  test('AEG-D15 keyboard cache', () async {
    final r = await audit({
      'lib/main.dart': '''
final a = TextField(decoration: InputDecoration(labelText: 'Card number'));
final b = TextFormField(controller: passwordController);
final c = TextField(obscureText: true, decoration: InputDecoration(labelText: 'Password'));
final d = TextField(enableSuggestions: false, autocorrect: false,
    decoration: InputDecoration(hintText: 'CVV'));
final e = TextField(obscureText: _hidden, controller: pinController);
final f = TextField(decoration: InputDecoration(labelText: 'Name'));
final g = TextField(controller: otpController);
''',
    });
    expect(lines(r, 'AEG-D15'), [
      '1: TextField for sensitive input keeps keyboard suggestions and autocorrect on.',
      '2: TextFormField for sensitive input keeps keyboard suggestions and autocorrect on.',
    ]);
  });

  test('AEG-D16 clipboard', () async {
    final r = await audit({
      'lib/main.dart': '''
void copy() {
  Clipboard.setData(ClipboardData(text: session.accessToken));
  Clipboard.setData(ClipboardData(text: orderId));
}
''',
    });
    expect(lines(r, 'AEG-D16'),
        ['2: `session.accessToken` is copied to the clipboard.']);
  });

  test('AEG-D17 notifications are listed for review', () async {
    final r = await audit({
      'pubspec.yaml': '$pubspec  flutter_local_notifications: any\n',
      'lib/notify.dart': '''
import 'package:flutter_local_notifications/flutter_local_notifications.dart';
void notify(plugin, String otp) {
  plugin.show(0, 'Your code', 'Use \$otp to sign in', details);
  plugin.show(1, 'Order shipped', 'On its way', details);
}
''',
    });
    expect(result(r, 'AEG-D17').status, RuleStatus.evidenceOnly);
    expect(result(r, 'AEG-D17').note, contains('lib/notify.dart:3'));
    expect(result(r, 'AEG-D17').note, isNot(contains('notify.dart:4')));
  });

  test('AEG-D18 Keychain options', () async {
    final r = await audit({
      'pubspec.yaml': '$pubspec  flutter_secure_storage: any\n',
      'lib/main.dart': '''
const a = IOSOptions(accessibility: KeychainAccessibility.first_unlock);
const b = IOSOptions(accessibility: KeychainAccessibility.first_unlock_this_device);
const c = IOSOptions(synchronizable: true);
''',
    });
    expect(lines(r, 'AEG-D18'), [
      '1: Secure storage uses `KeychainAccessibility.first_unlock`, so items can move to other devices.',
      '3: Secure storage uses `synchronizable: true`, so items can move to other devices.',
    ]);
  });

  test('AEG-D20 generated keys and key material in plain storage', () async {
    final r = await audit({
      'lib/main.dart': '''
Future<void> f(SharedPreferences prefs, Box box) async {
  final k = Key.fromSecureRandom(32);
  await prefs.setString('k', k.base64);
  await box.put('dbKey', bytes);
  await prefs.setString('theme', 'dark');
  await secureStorage.write(key: 'k', value: k.base64);
}
''',
    });
    expect(lines(r, 'AEG-D20'), [
      '3: Key `k` is written to plain storage with setString().',
      '4: Key `dbKey` is written to plain storage with put().',
    ]);
  });

  test('AEG-D04 now covers Hive boxes and SQLite tables', () async {
    final r = await audit({
      'pubspec.yaml': '$pubspec  sqflite: any\n',
      'lib/main.dart': '''
Future<void> f() async {
  await Hive.openBox('tokens');
  await Hive.openBox('vault', encryptionCipher: HiveAesCipher(key));
  await Hive.openBox('settings');
  await db.execute('CREATE TABLE users (id INTEGER, email TEXT, password TEXT)');
  await db.execute('CREATE TABLE notes (id INTEGER, body TEXT)');
}
''',
    });
    expect(lines(r, 'AEG-D04'), [
      '2: Hive box "tokens" is opened without encryptionCipher, so its data is stored unencrypted.',
      '5: Table users stores password in an unencrypted SQLite database.',
    ]);

    final cipher = await audit({
      'pubspec.yaml': '$pubspec  sqflite_sqlcipher: any\n',
      'lib/main.dart':
          "void f() => db.execute('CREATE TABLE users (password TEXT)');",
    });
    expect(result(cipher, 'AEG-D04').status, RuleStatus.passed);
  });

  test('AEG-P14 card and identity fields are listed for review', () async {
    final r = await audit({
      'lib/pay.dart': '''
final card = TextField(decoration: InputDecoration(labelText: 'Card number'));
''',
      'android/app/src/main/res/layout/pay.xml': '''
<LinearLayout>
  <EditText android:id="@+id/card_number" android:inputType="number" />
  <EditText android:id="@+id/iban" android:accessibilityDataSensitive="yes" />
</LinearLayout>
''',
    });
    expect(result(r, 'AEG-P14').status, RuleStatus.evidenceOnly);
    expect(result(r, 'AEG-P14').note, contains('lib/pay.dart:1'));
    expect(result(r, 'AEG-P14').note,
        contains('android/app/src/main/res/layout/pay.xml:2'));
    expect(result(r, 'AEG-P14').note, isNot(contains('pay.xml:3')));
  });
}
