import 'package:aegis/aegis.dart';
import 'package:path/path.dart' as p;
import 'package:test/test.dart';

void main() {
  group('apk: / aab: in aegis.yaml', () {
    test('are read as written', () {
      final c = AegisConfig.parse('''
profile: l2+r
apk: build/app/outputs/apk/prod/release/app-prod-release.apk
aab: /abs/app.aab
''');
      expect(c.apk, 'build/app/outputs/apk/prod/release/app-prod-release.apk');
      expect(c.aab, '/abs/app.aab');
    });

    test('missing or empty → null', () {
      expect(AegisConfig.parse('profile: l1\n').apk, isNull);
      expect(AegisConfig.parse('apk: ""\n').apk, isNull);
    });

    test('resolve makes a relative path absolute against the project', () {
      expect(AegisConfig.resolve('/proj', 'build/a.apk'), p.normalize('/proj/build/a.apk'));
      expect(AegisConfig.resolve('/proj', '/abs/a.apk'), '/abs/a.apk');
      expect(AegisConfig.resolve('/proj', null), isNull);
    });

    test('survive copyWith (e.g. a --profile override)', () {
      final c = AegisConfig.parse('apk: a.apk\naab: b.aab\n')
          .copyWith(profile: ProfileSet.tryParse('l2+r'));
      expect(c.apk, 'a.apk');
      expect(c.aab, 'b.aab');
    });
  });
}
