import 'dart:io';
import 'dart:typed_data';
import 'package:aegis/aegis.dart';
import 'package:aegis/src/binary/elf_security.dart';
import 'package:aegis/src/binary/zip.dart';
import 'package:aegis/src/l10n/messages.g.dart';
import 'package:aegis/src/rules/platform_security_rules.dart';
import 'package:aegis/src/rules/runtime_security_rules.dart';
import 'package:aegis/src/security/public_json.dart';
import 'package:archive/archive.dart';
import 'package:test/test.dart';
import 'rules_test.dart' show audit, result, manifestHeader;

String manifest(String body, {String permission = '', String app = ''}) =>
    '$manifestHeader $permission <uses-sdk android:targetSdkVersion="35"/><application $app>$body</application></manifest>';
const manifestPath = 'android/app/src/main/AndroidManifest.xml';
const nativePath = 'android/app/src/main/java/app/Test.java';

Uint8List elf(
    {bool wide = true,
    Endian endian = Endian.little,
    bool stack = false,
    bool wx = false,
    bool relro = true,
    bool now = true,
    int type = 3}) {
  final b = Uint8List(512), d = ByteData(512);
  b.setRange(0, 7,
      [127, 69, 76, 70, wide ? 2 : 1, endian == Endian.little ? 1 : 2, 1]);
  void u16(int o, int v) => d.setUint16(o, v, endian);
  void u32(int o, int v) => d.setUint32(o, v, endian);
  void word(int o, int v) {
    if (wide) {
      d.setUint64(o, v, endian);
    } else {
      u32(o, v);
    }
  }

  u16(16, type);
  word(wide ? 32 : 28, wide ? 64 : 52);
  u16(wide ? 54 : 42, wide ? 56 : 32);
  u16(wide ? 56 : 44, relro ? 4 : 3);
  void ph(int i, int type, int flags, int off, int size) {
    final o = (wide ? 64 : 52) + i * (wide ? 56 : 32);
    u32(o, type);
    u32(o + (wide ? 4 : 24), flags);
    word(o + (wide ? 8 : 4), off);
    word(o + (wide ? 16 : 8), off);
    word(o + (wide ? 32 : 16), size);
  }

  ph(0, 1, wx ? 7 : 5, 0, 512);
  ph(1, 0x6474e551, stack ? 7 : 6, 0, 0);
  ph(2, 2, 6, 400, wide ? 32 : 16);
  if (relro) ph(3, 0x6474e552, 4, 0, 0);
  if (now) {
    word(400, 24);
    word(400 + (wide ? 8 : 4), 0);
  }
  final bytes = d.buffer.asUint8List();
  bytes.setRange(0, 7, b.sublist(0, 7));
  return bytes;
}

void main() {
  group('manifest semantics', () {
    test('links need verification and constrained hosts', () async {
      final r = await audit({
        manifestPath: manifest(
            '''<activity android:name=".Link" android:exported="true"><intent-filter><action android:name="android.intent.action.VIEW"/><category android:name="android.intent.category.BROWSABLE"/><data android:scheme="https" android:host="*.example.com"/></intent-filter></activity>''')
      });
      expect(result(r, 'AEG-A11').findings, hasLength(2));
      expect(result(r, 'AEG-A13').status, RuleStatus.incomplete);
    });
    test(
        'verified exact host passes configuration but offline association stays incomplete',
        () async {
      final r = await audit({
        manifestPath: manifest(
            '''<activity android:name=".Link" android:exported="true"><intent-filter android:autoVerify="true"><action android:name="android.intent.action.VIEW"/><category android:name="android.intent.category.BROWSABLE"/><data android:scheme="https" android:host="example.com"/></intent-filter></activity>''')
      });
      expect(result(r, 'AEG-A11').status, RuleStatus.passed);
      expect(result(r, 'AEG-A13').status, RuleStatus.incomplete);
    });
    test('non-browsable VIEW is not exempted from exported component checks',
        () async {
      final r = await audit({
        manifestPath: manifest(
            '<activity android:name=".Private" android:exported="true"><intent-filter><action android:name="android.intent.action.VIEW"/></intent-filter></activity>')
      });
      expect(result(r, 'AEG-A06').status, RuleStatus.failed);
    });
    test('normal permission does not make an exported service secure',
        () async {
      final r = await audit({
        manifestPath: manifest(
            '<service android:name=".S" android:exported="true" android:permission="app.ACCESS"/>',
            permission:
                '<permission android:name="app.ACCESS" android:protectionLevel="normal"/>')
      });
      expect(
          result(r, 'AEG-A12').findings.single.message, contains('app.ACCESS'));
    });
    test('inherited signature permission protects both provider operations',
        () async {
      final r = await audit({
        manifestPath: manifest(
            '<provider android:name=".P" android:exported="true"/>',
            permission:
                '<permission android:name="app.ACCESS" android:protectionLevel="signature|privileged"/>',
            app: 'android:permission="app.ACCESS"')
      });
      expect(result(r, 'AEG-A12').status, RuleStatus.passed);
    });
    test('read-only permission does not protect provider writes', () async {
      final r = await audit({
        manifestPath: manifest(
            '<provider android:name=".P" android:exported="true" android:readPermission="app.ACCESS"/>',
            permission:
                '<permission android:name="app.ACCESS" android:protectionLevel="signature"/>')
      });
      expect(result(r, 'AEG-A12').findings.single.message, contains('write'));
    });
    test('unknown external permission strength is incomplete', () async {
      final r = await audit({
        manifestPath: manifest(
            '<service android:name=".S" android:exported="true" android:permission="another.app.ACCESS"/>')
      });
      expect(result(r, 'AEG-A12').status, RuleStatus.incomplete);
      expect(
          r.securityEvidence
              .any((e) => e.ruleId == 'AEG-A12' && e.status == 'unavailable'),
          isTrue);
    });
    test('assetlinks requires package, relation and every signer', () {
      final value = [
        {
          'relation': ['delegate_permission/common.handle_all_urls'],
          'target': {
            'namespace': 'android_app',
            'package_name': 'app.test',
            'sha256_cert_fingerprints': ['AA:BB']
          }
        }
      ];
      expect(authorizesAndroidAssociation(value, 'app.test', {'aabb'}), isTrue);
      expect(
          authorizesAndroidAssociation(value, 'other.app', {'aabb'}), isFalse);
      expect(authorizesAndroidAssociation(value, 'app.test', {'aabb', 'ccdd'}),
          isFalse);
      expect(authorizesAndroidAssociation(value, 'app.test', {}), isFalse);
    });
    test('association fetcher blocks private/metadata/rebinding destinations',
        () {
      for (final address in [
        '127.0.0.1',
        '10.0.0.1',
        '169.254.169.254',
        '192.168.1.1',
        '172.31.0.1',
        '100.64.0.1',
        '::1',
        '::ffff:127.0.0.1'
      ]) {
        expect(publicAddress(InternetAddress(address)), isFalse,
            reason: address);
      }
      expect(publicAddress(InternetAddress('8.8.8.8')), isTrue);
    });
  });
  group('native configuration versus indicators', () {
    test('explicit insecure settings fail; comments do not', () async {
      final r = await audit({
        nativePath: '''class Test {
     // setAllowUniversalAccessFromFileURLs(true);
     void checkServerTrusted(X509Certificate[] chain, String type) { }
     void web() { settings.setMixedContentMode(WebSettings.MIXED_CONTENT_ALWAYS_ALLOW); }
     void crypto() { Cipher.getInstance("AES/ECB/PKCS5Padding"); }
     void storage() { openFileOutput("data", MODE_WORLD_READABLE); }
   }'''
      });
      for (final id in ['AEG-N01', 'AEG-N02', 'AEG-N03', 'AEG-N04']) {
        expect(result(r, id).findings, hasLength(1), reason: id);
      }
    });
    test('MD5, SQLite and malloc references are not definite vulnerabilities',
        () async {
      final r = await audit({
        'ios/Runner/Test.m':
            'void test() { CC_MD5(data); sqlite3_exec(db); malloc(10); }'
      });
      expect(result(r, 'AEG-N03').findings, isEmpty);
      expect(result(r, 'AEG-N04').findings, isEmpty);
      expect(
          r.securityEvidence
              .where((e) => ['AEG-N03', 'AEG-N04'].contains(e.ruleId)),
          hasLength(2));
    });
    test(
        'weak Keychain accessibility and file protection detected in native source',
        () async {
      final r = await audit({
        'ios/Runner/Test.swift':
            'let attributes = [kSecAttrAccessible: kSecAttrAccessibleAlways]\nlet file = [FileAttributeKey.protectionKey: FileProtectionType.none]'
      });
      expect(result(r, 'AEG-N04').findings, hasLength(2));
    });
    test('native safe configuration and commented examples do not fail',
        () async {
      final r = await audit({
        nativePath:
            '// Cipher.getInstance("DES");\nclass Test { void f(){ Cipher.getInstance("AES/GCM/NoPadding"); settings.setAllowFileAccessFromFileURLs(false); } }'
      });
      expect(result(r, 'AEG-N03').findings, isEmpty);
      expect(result(r, 'AEG-N02').findings, isEmpty);
    });
    test('source-looking string literals do not become configuration findings',
        () async {
      final r = await audit({
        nativePath:
            r'''String docs = "settings.setAllowFileAccessFromFileURLs(true);";'''
      });
      expect(result(r, 'AEG-N02').findings, isEmpty);
    });
    test('iOS entitlements distinguish broad access from macOS-only flags',
        () async {
      final r = await audit({
        'ios/Runner/Runner.entitlements':
            '''<?xml version="1.0"?><plist version="1.0"><dict><key>keychain-access-groups</key><array><string>TEAM.*</string></array><key>com.apple.security.cs.allow-jit</key><true/></dict></plist>'''
      });
      expect(result(r, 'AEG-I10').findings, hasLength(1));
      expect(r.securityEvidence.any((e) => e.ruleId == 'AEG-I10'), isTrue);
    });
    test('trackers are inventory only and render bilingual escaped evidence',
        () async {
      final r = await audit({
        'pubspec.yaml': 'name: app\ndependencies:\n  firebase_analytics: any\n'
      });
      expect(result(r, 'AEG-T01').status, RuleStatus.notApplicable);
      expect(r.securityEvidence.any((e) => e.ruleId == 'AEG-T01'), isTrue);
      expect(renderHtml(r, lang: 'ar'), contains(Ar.extEvidenceScope));
      expect(renderHtml(r, lang: 'ar'), isNot(contains(En.extEvidenceScope)));
      expect(
          (reportToJson(r)['securityEvidence'] as List)
              .first['countsTowardScore'],
          isFalse);
    });
  });
  group('bounded ELF parsing', () {
    for (final wide in [false, true]) {
      for (final endian in [Endian.little, Endian.big]) {
        test('${wide ? 64 : 32} bit $endian program flags and RELRO', () {
          final good = inspectElf(elf(wide: wide, endian: endian));
          expect(good.type, 3);
          expect(good.relro && good.bindNow, isTrue);
          expect(good.executableStack, isFalse);
          expect(good.canary, isNull);
          final bad = inspectElf(elf(
              wide: wide, endian: endian, stack: true, wx: true, now: false));
          expect(bad.wx, isTrue);
          expect(bad.executableStack, isTrue);
          expect(bad.toJson()['relro'], 'partial');
        });
      }
    }
    test('missing RELRO and truncation cannot pass', () {
      expect(inspectElf(elf(relro: false)).toJson()['relro'], 'none');
      final bytes = elf();
      for (final size in [0, 4, 51, 80, 180]) {
        expect(() => inspectElf(Uint8List.sublistView(bytes, 0, size)),
            throwsFormatException);
      }
    });
    test('ZIP entry limit is enforced on expanded bytes and size lies', () {
      final archive = Archive()
        ..addFile(ArchiveFile.bytes('test', List.filled(10000, 65)));
      final bytes = Uint8List.fromList(ZipEncoder().encode(archive));
      final zip = ZipReader(bytes);
      expect(() => zip.readEntry(zip.entries['test']!, maxBytes: 100),
          throwsFormatException);
      ByteData.sublistView(bytes)
          .setUint32(zip.centralDirectoryOffset + 24, 1, Endian.little);
      final lying = ZipReader(bytes);
      expect(() => lying.read('test'), throwsFormatException);
    });
  });
  group('runtime result contract', () {
    Future<AuditReport> runtime(RuntimeSecurityResult data) async {
      final dir = Directory.systemTemp.createTempSync('aegis-runtime-unit-');
      addTearDown(() => dir.deleteSync(recursive: true));
      File('${dir.path}/pubspec.yaml').writeAsStringSync('name: app\n');
      return runAudit(dir.path,
          rules: runtimeSecurityRules, runtimeSecurity: data, offline: true);
    }

    test('unconfigured and failed baseline are incomplete, never passes',
        () async {
      for (final data in [
        const RuntimeSecurityResult({}, configured: false),
        const RuntimeSecurityResult({
          'baseline': false,
          'network': [
            {'phase': 'untrusted', 'host': 'api.test'}
          ]
        })
      ]) {
        final r = await runtime(data);
        expect(r.complete, isFalse);
        expect(r.failed, isEmpty);
        expect(r.incomplete, hasLength(2));
      }
    });
    test('intercepted requests fail; silence does not prove pinning', () async {
      final r = await runtime(const RuntimeSecurityResult({
        'baseline': true,
        'cleanup': true,
        'network': [
          {'phase': 'trusted', 'host': 'api.test'},
          {'phase': 'trusted', 'host': 'control.test'}
        ]
      }, pinnedHosts: [
        'api.test'
      ]));
      expect(result(r, 'AEG-R09').findings, hasLength(1));
      expect(result(r, 'AEG-R09').incomplete, isTrue);
      final silent = await runtime(const RuntimeSecurityResult(
          {'baseline': true, 'cleanup': true, 'network': []}));
      expect(result(silent, 'AEG-R09').status, RuleStatus.incomplete);
    });
    test('leaks survive incomplete collection and contain labels only',
        () async {
      final r = await runtime(const RuntimeSecurityResult({
        'baseline': true,
        'storage': {
          'hits': [
            {'marker': 'password', 'channel': 'files'}
          ],
          'channels': {'files': true, 'logs': false, 'clipboard': false},
          'limited': false
        }
      }, markers: [
        'password'
      ]));
      expect(result(r, 'AEG-R10').status, RuleStatus.failed);
      expect(result(r, 'AEG-R10').incomplete, isTrue);
      expect(result(r, 'AEG-R10').findings.single.message,
          contains('value redacted'));
    });
    test('storage success requires all channels, markers and cleanup',
        () async {
      final r = await runtime(const RuntimeSecurityResult({
        'baseline': true,
        'cleanup': true,
        'storage': {
          'hits': [],
          'channels': {'files': true, 'logs': true, 'clipboard': true},
          'limited': false
        }
      }, markers: [
        'password'
      ]));
      expect(result(r, 'AEG-R10').status, RuleStatus.passed);
    });
    test('config and overrides preserve runtime settings', () {
      final c = AegisConfig.parse(
              'tracker_signatures: custom.json\nruntime_security:\n  enabled: true\n  command: [python3, scenario.py]\n')
          .copyWith(lang: 'ar');
      expect(c.trackerSignatures, 'custom.json');
      expect(c.runtimeSecurity['enabled'], isTrue);
      expect(() => AegisConfig.parse('runtime_security: invalid'),
          throwsFormatException);
    });
  });
}
