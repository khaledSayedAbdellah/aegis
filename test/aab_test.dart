import 'dart:convert';
import 'dart:io';

import 'package:aegis/aegis.dart';
import 'package:path/path.dart' as p;
import 'package:test/test.dart';
import 'package:xml/xml.dart';

/// Fixtures are built by tool/make_aab_fixtures.py with Google's protobuf
/// library and aapt2's Resources.proto.
const fixtures = 'test/fixtures/aab';
final expected = jsonDecode(File('$fixtures/expected.json').readAsStringSync())
    as Map<String, dynamic>;

final l2r = AegisConfig(profile: ProfileSet.tryParse('l2+r')!);

Future<AuditReport> bundleOnly(String aab) =>
    runAudit(fixtures, apkPath: '$fixtures/$aab', config: l2r, offline: true);

RuleResult result(AuditReport r, String id) =>
    r.results.firstWhere((x) => x.meta.id == id);
Set<String> failedIds(AuditReport r) => r.failed.map((x) => x.meta.id).toSet();
String messages(AuditReport r, String id) =>
    result(r, id).findings.map((f) => '${f.file} ${f.message}').join('\n');

String? androidAttr(XmlElement e, String name) {
  for (final a in e.attributes) {
    if (a.name.prefix == 'android' && a.name.local == name) return a.value;
  }
  return null;
}

void main() {
  group('AAB reader', () {
    test('protobuf manifest, resources and modules', () {
      final aab = ApkContext.load('$fixtures/vulnerable.aab');
      expect(aab.isBundle, isTrue);
      expect(aab.kind, 'AAB');
      expect(aab.packageName, 'com.myshop.app');
      expect(aab.versionName, '1.2.0');
      expect(aab.versionCode, '7');
      expect(aab.minSdk, 21, reason: 'only a compiled int, no raw value');
      expect(aab.targetSdk, 33);
      expect(aab.manifest!.rootElement.descendantElements.length + 1,
          expected['vulnerable']['manifestElements'],
          reason: 'every element of the protobuf tree is decoded');

      final app = aab.application!;
      expect(androidAttr(app, 'debuggable'), 'true',
          reason: 'compiled boolean');
      expect(androidAttr(app, 'networkSecurityConfig'), '@xml/nsc',
          reason: 'compiled reference');
      expect(androidAttr(app, 'allowBackup'), 'true', reason: 'raw value');

      final nsc = aab.networkSecurityConfig;
      expect(nsc, isNotNull);
      expect(nsc!.$1, 'res/a.xml');
      expect(
          nsc.$2
              .findAllElements('certificates')
              .map((e) => e.getAttribute('src'))
              .toList(),
          ['system', 'user']);

      expect(aab.isFlutter, isTrue);
      expect(aab.abis, ['arm64-v8a']);
      expect(aab.libappEntry, 'lib/arm64-v8a/libapp.so');
      expect(aab.libappStrings, contains('_MaterialAppState'));

      // Entries are seen with their APK names.
      expect(aab.zip.contains('classes.dex'), isTrue);
      expect(aab.zip.contains('resources.pb'), isTrue);
      expect(
          aab.zip.contains('META-INF/kotlinx_coroutines_core.version'), isTrue,
          reason: 'base/root/');
      expect(aab.zip.contains('feature_pay/classes.dex'), isTrue,
          reason: 'feature module code');
      expect(aab.zip.entries.keys.where((n) => n.contains('proguard')), isEmpty,
          reason: 'BUNDLE-METADATA is not installed on devices');

      // The bundle is signed with the upload key (v1, jarsigner).
      expect(aab.certificates, hasLength(1));
      expect(aab.certificates.single.sha256Base64,
          expected['vulnerable']['sha256Base64']);
      expect(aab.certificates.single.scheme, 'v1');
      expect(aab.sizeBytes, File('$fixtures/vulnerable.aab').lengthSync());
    });

    test('bundle view keeps base files and skips metadata', () {
      final view = ApkContext.bundleView([
        'BundleConfig.pb',
        'META-INF/UPLOAD.RSA',
        'BUNDLE-METADATA/x/y',
        'base/manifest/AndroidManifest.xml',
        'base/dex/classes.dex',
        'base/dex/classes2.dex',
        'base/assets/a.txt',
        'base/assets.pb',
        'feature/manifest/AndroidManifest.xml',
        'feature/dex/classes.dex',
        'feature/assets/a.txt',
        'feature/assets/b.txt',
      ]);
      expect(view, {
        'base/manifest/AndroidManifest.xml': 'AndroidManifest.xml',
        'base/dex/classes.dex': 'classes.dex',
        'base/dex/classes2.dex': 'classes2.dex',
        'base/assets/a.txt': 'assets/a.txt',
        'feature/dex/classes.dex': 'feature/classes.dex',
        'feature/assets/b.txt': 'assets/b.txt',
      });
    });

    test('rejects files that are not bundles', () {
      final dir = Directory.systemTemp.createTempSync('aegis_aab_');
      addTearDown(() => dir.deleteSync(recursive: true));
      final notZip = File(p.join(dir.path, 'a.aab'))
        ..writeAsStringSync('hello');
      expect(() => ApkContext.load(notZip.path), throwsFormatException);
      final apkNamedAab = File('test/fixtures/apk/vulnerable.apk')
          .copySync(p.join(dir.path, 'b.aab'));
      expect(() => ApkContext.load(apkNamedAab.path), throwsFormatException);
    });

    test('an APK is still read as an APK', () {
      final apk = ApkContext.load('test/fixtures/apk/vulnerable.apk');
      expect(apk.isBundle, isFalse);
      expect(apk.kind, 'APK');
    });
  });

  group('AAB audit', () {
    test('vulnerable bundle', () async {
      final r = await bundleOnly('vulnerable.aab');
      expect(r.binary!.kind, 'AAB');
      expect(
          failedIds(r),
          containsAll([
            'AEG-B02', 'AEG-B03', 'AEG-B04', 'AEG-B05', 'AEG-B06', //
            'AEG-B07', 'AEG-B08', 'AEG-B09', 'AEG-B11',
          ]));
      expect(
          messages(r, 'AEG-B03'),
          allOf(contains('allowBackup'), contains('usesCleartextTraffic'),
              contains('user-installed')));
      expect(messages(r, 'AEG-B04'), contains('SmsReceiver'));
      expect(messages(r, 'AEG-B05'), contains('READ_SMS'));
      expect(messages(r, 'AEG-B08'), contains('.env'));
      expect(messages(r, 'AEG-B11'),
          allOf(contains('targetSdk is 33'), contains('minSdk is 21')));

      final secrets = result(r, 'AEG-B06').findings;
      expect(secrets.map((f) => f.file).toSet(), {
        'vulnerable.aab!/lib/arm64-v8a/libapp.so',
        'vulnerable.aab!/resources.pb',
        'vulnerable.aab!/feature_pay/classes.dex',
      });
      expect(secrets, hasLength(3),
          reason: 'the key in proguard.map is not scanned');

      // Binary rules say AAB, not APK.
      expect(result(r, 'AEG-B08').meta.title.en,
          'Secret file shipped inside the AAB');
      expect(result(r, 'AEG-B08').findings.single.message,
          '.env is inside the AAB.');
      expect(result(r, 'AEG-B08').findings.single.messageOf('ar'),
          '.env موجود جوه الـ AAB.');
    });

    test('hardened bundle passes', () async {
      final r = await bundleOnly('secure.aab');
      for (final res in r.results.where(
          (r) => RegExp(r'^AEG-B(?:0[1-9]|1[01])$').hasMatch(r.meta.id))) {
        if (res.meta.id == 'AEG-B10') {
          expect(res.status, RuleStatus.notApplicable);
        } else {
          expect(res.status, RuleStatus.passed,
              reason: '${res.meta.id}: ${res.findings.map((f) => f.message)}');
        }
      }
      expect(r.score.value, 100);
      final b09 = result(r, 'AEG-B09').meta;
      expect(b09.passTitle.en, 'The AAB is signed with a release certificate');
      expect(b09.passTitle.ar, 'الـ AAB متوقع بشهادة release');
      expect(b09.description.en, isNot(contains('APK')));
      expect(result(r, 'AEG-B10').meta.title.ar, contains('الـ AAB'));
    });

    test('APK reports keep saying APK', () async {
      final r = await runAudit(fixtures,
          apkPath: 'test/fixtures/apk/secure.apk', config: l2r, offline: true);
      expect(result(r, 'AEG-B09').meta.passTitle.en,
          'The APK is signed with a release certificate');
    });

    group('freeRASP hashes and Play re-signing', () {
      final upload = expected['secure']['sha256Base64'] as String;
      const playKey = 'mVr/qQLO8DKTwqlL+B1qigl9NoBnbiUs8b4c2Ewcz0k=';

      Future<RuleResult> b10(String hashes) async {
        final dir = Directory.systemTemp.createTempSync('aegis_aab_');
        addTearDown(() => dir.deleteSync(recursive: true));
        File(p.join(dir.path, 'pubspec.yaml')).writeAsStringSync(
            'name: app\ndependencies:\n  flutter:\n    sdk: flutter\n  freerasp: ^7.0.0\n');
        Directory(p.join(dir.path, 'lib')).createSync();
        File(p.join(dir.path, 'lib', 'main.dart')).writeAsStringSync('''
final config = TalsecConfig(
  androidConfig: AndroidConfig(
    packageName: 'com.acme.bank',
    signingCertHashes: [$hashes],
  ),
);
''');
        final r = await runAudit(dir.path,
            apkPath: '$fixtures/secure.aab', config: l2r, offline: true);
        return result(r, 'AEG-B10');
      }

      test('only the upload key: installs from Play would fail', () async {
        final r = await b10("'$upload'");
        expect(r.status, RuleStatus.failed);
        expect(r.findings.single.message,
            allOf(contains('upload key'), contains('app signing key')));
      });

      test('upload key and another key: assumed to be the Play key', () async {
        expect((await b10("'$upload', '$playKey'")).status, RuleStatus.passed);
      });

      test('no upload key: cannot be checked from the bundle', () async {
        final r = await b10("'$playKey'");
        expect(r.status, RuleStatus.notApplicable);
        expect(r.note, contains('Play Console'));
      });
    });
  });

  group('Reports and baselines', () {
    test('reports say it is a bundle signed with the upload key', () async {
      final r = await bundleOnly('secure.aab');
      final console = ConsoleReporter(color: false).render(r);
      expect(
          console, allOf(contains('App bundle (AAB)'), contains('upload key')));
      expect(renderHtml(r), contains('App bundle (AAB)'));
      expect(renderMarkdown(r), contains('upload key'));
      final json = jsonDecode(renderJson(r)) as Map<String, dynamic>;
      expect(json['binary']['kind'], 'AAB');
    });

    test('an AAB finding matches the same APK finding in a baseline', () {
      Finding f(String file, String message) =>
          Finding(ruleId: 'AEG-B08', message: message, file: file);
      expect(
          Baseline.fingerprint(f('app-release.aab!/assets/flutter_assets/.env',
              '.env is inside the AAB.')),
          Baseline.fingerprint(f(
              'app-prod-release.apk!/assets/flutter_assets/.env',
              '.env is inside the APK.')));
    });
  });
}
