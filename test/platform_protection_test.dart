import 'dart:io';
import 'dart:convert';
import 'package:archive/archive.dart';
import 'package:aegis/aegis.dart';
import 'package:aegis/src/project.dart';
import 'package:aegis/src/rules/platform_protection_rules.dart';
import 'package:aegis/src/security/platform_checks.dart';
import 'package:aegis/src/security/android_platform.dart';
import 'package:aegis/src/reporters/security_view.dart';
import 'package:aegis/src/probe/ios_platform_observer.dart';
import 'package:test/test.dart';
import 'package:xml/xml.dart';
import 'rules_test.dart' show audit, result, manifestHeader;
import 'ios_static_test.dart' show ipaBytes;
import 'support/macho_security_fixture.dart';

final profiles = ProfileSet.tryParse('l2+r')!;
const manifestPath = 'android/app/src/main/AndroidManifest.xml';
Future<Project> iosProject() async {
  final dir = Directory.systemTemp.createTempSync('aegis-platform-');
  addTearDown(() => dir.deleteSync(recursive: true));
  final file = File('${dir.path}/test.ipa')
    ..writeAsBytesSync(ipaBytes(securityMachO()));
  final ipa = IpaContext.load(file.path);
  return Project.ipaOnly(dir.path, ipa)..ipa = ipa;
}

void main() {
  test('Simulator observation requires this launch identity and a regular file',
      () {
    final dir = Directory.systemTemp.createTempSync('aegis-observer-test-');
    addTearDown(() => dir.deleteSync(recursive: true));
    final file = File('${dir.path}/facts.json');
    final observer = IosPlatformObserver('unused', file, 'expected');
    expect(observer.read('org.example.app', 42), isEmpty);
    void write(String nonce, String bundle, int pid) =>
        file.writeAsStringSync(jsonEncode({
          'nonce': nonce,
          'bundle': bundle,
          'pid': pid,
          'screen': {'windows': 1},
          'phase': 'background'
        }));
    write('wrong', 'org.example.app', 42);
    expect(observer.read('org.example.app', 42), isEmpty);
    write('expected', 'org.other.app', 42);
    expect(observer.read('org.example.app', 42), isEmpty);
    write('expected', 'org.example.app', 43);
    expect(observer.read('org.example.app', 42), isEmpty);
    write('expected', 'org.example.app', 42);
    final observed = observer.read('org.example.app', 42);
    expect(observed['verified'], isTrue);
    expect(observed['phase'], 'background');
    expect(observed, isNot(contains('nonce')));
    file.renameSync('${dir.path}/target.json');
    Link(file.path).createSync('${dir.path}/target.json');
    expect(observer.read('org.example.app', 42), isEmpty);
  });
  test('layout flags are review evidence, never a global tapjacking verdict',
      () async {
    final r = await audit({
      manifestPath: '$manifestHeader<application/></manifest>',
      'android/app/src/main/res/layout/main.xml':
          '<Button xmlns:android="http://schemas.android.com/apk/res/android" android:filterTouchesWhenObscured="true"/>',
      'android/app/src/main/res/layout-land/main.xml':
          '<Button xmlns:android="http://schemas.android.com/apk/res/android" android:filterTouchesWhenObscured="false"/>'
    });
    expect(result(r, 'AEG-A14').findings, isEmpty);
    expect(result(r, 'AEG-A14').status, RuleStatus.incomplete);
    expect(
        r.securityEvidence
            .where((e) =>
                e.ruleId == 'AEG-A14' &&
                e.data['source'] == 'layout-configuration')
            .map((e) => e.data['value']),
        unorderedEquals(['true', 'false']));
  });
  test(
      'all six rules retain explicit limits; evidence never grants full coverage',
      () async {
    final p = await iosProject();
    for (final kind in platformKinds.where((k) => k != 'tapjacking')) {
      final check = await PlatformProtectionRule(kind).check(p, profiles);
      expect(check.isIncomplete, isTrue);
    }
    expect(
        (await const PlatformProtectionRule('tapjacking').check(p, profiles))
            .applicable,
        isFalse);
    final ar = SecurityView(p.securityEvidence, 'ar').html();
    expect(ar, contains('الفحص'));
    expect(ar, isNot(contains('No verified runtime')));
  });
  test('backup policies preserve cloud/device and include/exclude distinctions',
      () {
    final p = inspectBackupPolicy(XmlDocument.parse(
        '''<data-extraction-rules><cloud-backup disableIfNoEncryptionCapabilities="true"><exclude domain="sharedpref" path="auth.xml"/></cloud-backup><device-transfer><include domain="file" path="public/"/></device-transfer></data-extraction-rules>'''));
    expect(p.issues, isEmpty);
    expect(p.flows['cloud-backup']!.single['action'], 'exclude');
    expect(p.flows['device-transfer']!.single['path'], 'public/');
    for (final path in ['../secret', '/secret', '*.db']) {
      expect(
          inspectBackupPolicy(XmlDocument.parse(
                  '<full-backup-content><exclude domain="file" path="$path"/></full-backup-content>'))
              .issues,
          isNotEmpty);
    }
    expect(inspectBackupPolicy(XmlDocument.parse('<unexpected/>')).issues,
        isNotEmpty);
  });
  test('backup source variants are read instead of accepting the resource name',
      () async {
    final r = await audit({
      manifestPath:
          '$manifestHeader<application android:fullBackupContent="@xml/backup" android:dataExtractionRules="@xml/extract"/></manifest>',
      'android/app/src/main/res/xml/backup.xml':
          '<full-backup-content><exclude domain="sharedpref" path="auth.xml"/></full-backup-content>',
      'android/app/src/main/res/xml-v28/backup.xml': '<full-backup-content/>',
      'android/app/src/main/res/xml/extract.xml':
          '<data-extraction-rules><cloud-backup><exclude domain="file" path="private/"/></cloud-backup></data-extraction-rules>'
    });
    expect(result(r, 'AEG-A02').status, RuleStatus.incomplete);
    expect(result(r, 'AEG-N05').status, RuleStatus.incomplete);
    final rows = r.securityEvidence
        .where((e) => e.ruleId == 'AEG-N05' && e.data.containsKey('rules'))
        .toList();
    expect(rows, hasLength(3));
    expect(rows.any((e) => (e.data['rules'] as List).isEmpty), isTrue);
  });
  test('compiled APK XML resource variants use the final packaged manifest',
      () {
    final dir = Directory.systemTemp.createTempSync('aegis-backup-');
    addTearDown(() => dir.deleteSync(recursive: true));
    final archive = ZipDecoder().decodeBytes(
        File('test/fixtures/apk/vulnerable.apk').readAsBytesSync());
    final bytes = archive.findFile('res/a.xml')!.content;
    archive.addFile(ArchiveFile.bytes('res/xml/backup.xml', bytes));
    archive.addFile(ArchiveFile.bytes('res/xml-v31/backup.xml', bytes));
    final file = File('${dir.path}/test.apk')
      ..writeAsBytesSync(ZipEncoder().encode(archive));
    final apk = ApkContext.load(file.path);
    expect(apk.xmlResourcePaths('@xml/backup'), hasLength(2));
    expect(apk.readXmlResource('res/xml-v31/backup.xml').rootElement.name.local,
        'network-security-config');
    expect(() => apk.xmlResourcePaths('@xml/missing'), throwsFormatException);
  });
  test('AASA legacy/current identity schemas, exclusions and malformed data',
      () {
    const id = 'TEAM.org.example.test';
    expect(
        iosAssociationMatches({
          'applinks': {
            'details': [
              {
                'appID': id,
                'paths': ['/*']
              }
            ]
          }
        }, id),
        isTrue);
    expect(
        iosAssociationMatches({
          'applinks': {
            'details': [
              {
                'appIDs': [id],
                'components': [
                  {'/': '/public/*'}
                ]
              }
            ]
          }
        }, id),
        isTrue);
    expect(
        iosAssociationMatches({
          'applinks': {
            'details': [
              {
                'appID': 'OTHER.app',
                'paths': ['*']
              }
            ]
          }
        }, id),
        isFalse);
    expect(
        iosAssociationMatches({
          'applinks': {
            'details': [
              {
                'appID': id,
                'paths': ['NOT /*']
              }
            ]
          }
        }, id),
        isNull);
    expect(
        iosAssociationMatches({
          'applinks': {'details': 'broken'}
        }, id),
        isNull);
    for (final entry in [
      {
        'appIDs': [123],
        'components': [
          {'/': '/*'}
        ]
      },
      {
        'appIDs': [],
        'components': [
          {'/': '/*'}
        ]
      },
      {
        'appID': id,
        'components': [
          {'/': 123}
        ]
      },
      {
        'appID': id,
        'components': [
          {'/': '/*', 'exclude': 'false'}
        ]
      },
      {
        'appID': id,
        'paths': [123, '*']
      }
    ]) {
      expect(
          iosAssociationMatches({
            'applinks': {
              'details': [entry]
            }
          }, id),
          isNull);
    }
    expect(
        iosAssociationMatches({
          'applinks': {
            'details': [
              {
                'appID': id,
                'paths': ['NOT /*']
              },
              {
                'appID': id,
                'paths': ['/public/*']
              }
            ]
          }
        }, id),
        isTrue);
  });
  test(
      'AASA mismatch is a finding, unavailable fetch and offline are incomplete',
      () async {
    final p = await iosProject();
    p.entitlements['signed'] = {
      'application-identifier': 'TEAM.${p.ipa!.bundleId}',
      'com.apple.developer.associated-domains': ['applinks:example.com']
    };
    var calls = 0;
    final rule = PlatformProtectionRule('links', fetcher: (uri) async {
      calls++;
      return {
        'applinks': {'details': []}
      };
    });
    final result = await rule.check(p, profiles);
    expect(result.findings, hasLength(1));
    expect(result.isIncomplete, isTrue);
    p.offline = true;
    expect((await rule.check(p, profiles)).findings, isEmpty);
    expect(calls, 1);
    p.offline = false;
    expect(
        (await PlatformProtectionRule('links',
                    fetcher: (uri) async =>
                        throw const FormatException('unavailable'))
                .check(p, profiles))
            .findings,
        isEmpty);
  });
  test('Android parser ignores other apps and never returns UI text', () {
    final v = inspectAndroidPlatform(
        'org.example.app',
        '''Window #0 Window{a u0 org.example.app/Main}:
      mAttrs={fl=0x2000}
Window #1 Window{b u0 org.other.app/Main}:
      mAttrs={fl=0x0}''',
        '''<hierarchy><node package="org.example.app" password="true" text="PRIVATE_PASSWORD" clickable="true"/><node package="org.other.app" password="true"/></hierarchy>''');
    expect((v['screen'] as Map)['secureWindows'], 1);
    expect((v['screen'] as Map)['passwordFields'], 1);
    expect(v.toString(), isNot(contains('PRIVATE_PASSWORD')));
    expect((v['tapjacking'] as Map)['clickableViews'], 1);
  });
  test(
      'API presence and explicit weakening configuration remain review evidence',
      () async {
    final r = await audit({
      manifestPath:
          '$manifestHeader<application android:allowBackup="false"/></manifest>',
      'android/app/src/main/java/test/App.java': '''class App { void setup() {
        key.setUserAuthenticationRequired(false);
        view.setFilterTouchesWhenObscured(false);
        web.setWebContentsDebuggingEnabled(true);
        String example="view.setHideOverlayWindows(false)";
        // view.setHideOverlayWindows(false);
      }}'''
    });
    for (final id in ['AEG-N06', 'AEG-N07', 'AEG-A14']) {
      expect(result(r, id).findings, isEmpty);
      expect(result(r, id).status, RuleStatus.incomplete);
      expect(
          r.securityEvidence.any((e) =>
              e.ruleId == id && e.data['source'] == 'source-configuration'),
          isTrue);
    }
    expect(
        r.securityEvidence
            .where((e) => e.data['source'] == 'source-configuration'),
        hasLength(3));
  });
  test(
      'verified runtime facts are scoped, count-only and cannot pass by silence',
      () async {
    final p = await iosProject();
    p.probe = ProbeOutcome.ran(ProbeReport(
        app: 'test',
        baselineAlive: true,
        results: [],
        platform: 'ios-simulator',
        platformObservations: {
          'verified': true,
          'viewLimitReached': 'DO_NOT_REPORT',
          'screen': {'windows': 1, 'secret': 'DO_NOT_REPORT'},
          'webview': {'webviews': 1, 'webviewInsecureContent': 1}
        }));
    final screen =
        await const PlatformProtectionRule('screen').check(p, profiles);
    expect(screen.isIncomplete, isTrue);
    expect(screen.findings, isEmpty);
    final web =
        await const PlatformProtectionRule('webview').check(p, profiles);
    expect(web.isIncomplete, isTrue);
    expect(web.findings, hasLength(1));
    expect(p.securityEvidence.toString(), isNot(contains('DO_NOT_REPORT')));
    expect(
        p.securityEvidence
            .where((e) => e.data['source'] == 'automatic-runtime-observer'),
        hasLength(2));
  });
  test('unverified runtime input never becomes a finding', () async {
    final p = await iosProject();
    p.probe = ProbeOutcome.ran(ProbeReport(
        app: 'test',
        baselineAlive: true,
        results: [],
        platformObservations: {
          'webview': {'webviewInsecureContent': 2}
        }));
    expect(
        (await const PlatformProtectionRule('webview').check(p, profiles))
            .findings,
        isEmpty);
  });
}
