import 'package:aegis/aegis.dart';
import 'package:aegis/src/rules/package_hygiene_rules.dart';
import 'package:test/test.dart';

import 'rules_test.dart' show audit, result;

void main() {
  test('look-alike names', () {
    expect(lookAlike('shared_preference'), 'shared_preferences');
    expect(lookAlike('flutter_secure_storge'), 'flutter_secure_storage');
    expect(lookAlike('dioo'), isNull,
        reason: 'names under 5 letters are skipped');
    expect(lookAlike('shared_preferences'), isNull);
    expect(lookAlike('my_company_utils'), isNull);
  });

  test('AEG-C03 offline reports look-alikes only', () async {
    final r = await audit({
      'pubspec.yaml': 'name: app\ndependencies:\n  flutter:\n    sdk: flutter\n'
          '  shared_preference: any\n  url_launcher: any\n'
          '  firebase_cor: any\n  firebase_core: any\n',
    });
    expect(
        result(r, 'AEG-C03').findings.map((f) => f.message),
        [
          'shared_preference is one letter away from the popular package '
              'shared_preferences. Check that it is the package you meant.',
        ],
        reason:
            'firebase_cor is next to firebase_core, which is also a dependency');
    expect(result(r, 'AEG-C03').severity, Severity.low);
  });
}
