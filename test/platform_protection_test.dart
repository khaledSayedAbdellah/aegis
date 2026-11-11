import 'dart:io';
import 'dart:convert';
import 'package:archive/archive.dart';
import 'package:aegis/aegis.dart';
import 'package:aegis/src/l10n/messages.g.dart';
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
    expect(result(r, 'AEG-A14').status, RuleStatus.evidenceOnly);
    expect(
        r.securityEvidence
            .where((e) =>
                e.ruleId == 'AEG-A14' &&
                e.data['source'] == 'layout-configuration')
            .map((e) => e.data['value']),
        unorderedEquals(['true', 'false']));
  });
  test(
      'static evidence is never a pass and never makes the audit incomplete',
      () async {
    final p = await iosProject();
    for (final kind in platformKinds.where((k) => k != 'tapjacking')) {
      final check = await PlatformProtectionRule(kind).check(p, profiles);
      expect(check.applicable, isFalse, reason: kind);
      expect(check.isIncomplete, isFalse, reason: kind);
      expect(check.findings, isEmpty, reason: kind);
      expect(check.isEvidenceOnly, isTrue, reason: kind);
      expect(check.note, En.platformEvidenceOnly);
      expect(check.noteAr, Ar.platformEvidenceOnly);
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
    expect(result(r, 'AEG-N05').status, RuleStatus.evidenceOnly);
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
      'AASA mismatch is a counted failure; unavailable fetch and offline are evidence',
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
    // No runtime observation was requested: a plain, fully counted failure.
    expect(result.applicable, isTrue);
    expect(result.isIncomplete, isFalse);
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
      expect(result(r, id).status, RuleStatus.evidenceOnly);
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
    // A finished launch observation without a finding is evidence, not a pass.
    expect(screen.applicable, isFalse);
    expect(screen.isIncomplete, isFalse);
    expect(screen.findings, isEmpty);
    final web =
        await const PlatformProtectionRule('webview').check(p, profiles);
    expect(web.applicable, isTrue);
    expect(web.isIncomplete, isFalse);
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
    final web =
        await const PlatformProtectionRule('webview').check(p, profiles);
    expect(web.findings, isEmpty);
    // The Android probe was requested and collects this control: still unfinished.
    expect(web.isIncomplete, isTrue);
  });
  group('requested runtime observation', () {
    ProbeOutcome ran(String platform, Map<String, Object?> observations,
            {Set<String> attempts = const {'control'}}) =>
        ProbeOutcome.ran(ProbeReport(
            app: 'test',
            baselineAlive: true,
            results: [],
            platform: platform,
            platformObservations: observations,
            platformObserverAttempts: attempts));
    Future<RuleCheck> check(Project p, String kind) =>
        PlatformProtectionRule(kind).check(p, profiles);

    test('a collector that returned nothing leaves its controls incomplete',
        () async {
      final p = await iosProject();
      p.probe = ran('ios-simulator', {});
      for (final kind in platformObserverKinds['ios-simulator']!['control']!) {
        final result = await check(p, kind);
        expect(result.isIncomplete, isTrue, reason: kind);
        expect(result.note, En.platformIncomplete);
      }
      p.probe = ProbeOutcome.skipped('no simulator');
      expect((await check(p, 'screen')).isIncomplete, isTrue);
    });
    test('a probe that was not requested leaves evidence only', () async {
      final p = await iosProject();
      p.probe = ProbeOutcome.skipped('--no-probe', requested: false);
      for (final kind in platformObserverKinds['ios-simulator']!['control']!) {
        final result = await check(p, kind);
        expect(result.isIncomplete, isFalse, reason: kind);
        expect(result.applicable, isFalse, reason: kind);
      }
    });
    test('a target without a collector for a control requests nothing',
        () async {
      final p = await iosProject();
      // No observer is injected into a physical iPhone.
      p.probe = ran('ios', {});
      for (final kind in platformKinds.where((k) => k != 'tapjacking')) {
        expect((await check(p, kind)).isIncomplete, isFalse, reason: kind);
      }
    });
    test('Android collects screen/WebView/tapjacking only', () async {
      final dir = Directory.systemTemp.createTempSync('aegis-platform-');
      addTearDown(() => dir.deleteSync(recursive: true));
      File('${dir.path}/pubspec.yaml').writeAsStringSync('name: app\n');
      File('${dir.path}/$manifestPath')
        ..parent.createSync(recursive: true)
        ..writeAsStringSync('$manifestHeader<application/></manifest>');
      final r = await runAudit(dir.path,
          rules: platformProtectionRules,
          offline: true,
          probe: ran('android', {
            'verified': true,
            'screen': {'windows': 1, 'secureWindows': 0},
            'webview': <String, int>{},
            'tapjacking': {'clickableViews': 3}
          }));
      expect(result(r, 'AEG-P11').status, RuleStatus.evidenceOnly);
      expect(result(r, 'AEG-A14').status, RuleStatus.evidenceOnly);
      expect(result(r, 'AEG-N07').status, RuleStatus.incomplete);
      expect(result(r, 'AEG-N05').status, RuleStatus.evidenceOnly);
      expect(result(r, 'AEG-N06').status, RuleStatus.evidenceOnly);
      expect(r.incomplete.map((x) => x.meta.id), ['AEG-N07']);
    });
    test('the Android instrumented observer is requested only once it started',
        () async {
      final dir = Directory.systemTemp.createTempSync('aegis-platform-');
      addTearDown(() => dir.deleteSync(recursive: true));
      File('${dir.path}/pubspec.yaml').writeAsStringSync('name: app\n');
      File('${dir.path}/$manifestPath')
        ..parent.createSync(recursive: true)
        ..writeAsStringSync('$manifestHeader<application/></manifest>');
      const control = {
        'verified': true,
        'screen': {'windows': 1, 'secureWindows': 0},
        'webview': {'webviews': 0},
        'tapjacking': {'clickableViews': 3}
      };
      Future<AuditReport> audit(ProbeOutcome probe) => runAudit(dir.path,
          rules: platformProtectionRules, offline: true, probe: probe);
      // Started and returned nothing: the key-access test was requested.
      final failed = await audit(
          ran('android', control, attempts: {'control', 'instrumented'}));
      expect(result(failed, 'AEG-N06').status, RuleStatus.incomplete);
      expect(failed.incomplete.map((x) => x.meta.id), ['AEG-N06']);
      expect(
          failed.securityEvidence
              .where((e) => e.ruleId == 'AEG-N06')
              .map((e) => e.data['observerStarted']),
          contains(true));
      // Never started (no Frida check in this run): evidence only.
      final skipped = await audit(ran('android', control));
      expect(result(skipped, 'AEG-N06').status, RuleStatus.evidenceOnly);
      expect(skipped.incomplete, isEmpty);
      // Started and verified: its facts complete the control.
      final verified = await audit(ran('android', {
        'verified': true,
        'instrumented': true,
        'keyQueriesComplete': true,
        'key_access': {'keystoreAliases': 2, 'authRequiredKeys': 1},
        'control': control,
      }, attempts: {
        'control',
        'instrumented'
      }));
      expect(result(verified, 'AEG-N06').status, RuleStatus.evidenceOnly);
      expect(verified.incomplete, isEmpty);
    });
    test('a launch observer that never started is still an unfinished request',
        () async {
      final p = await iosProject();
      p.probe = ran('ios-simulator', {}, attempts: {});
      expect((await check(p, 'screen')).isIncomplete, isTrue);
      expect(
          p.securityEvidence
              .where((e) => e.status == 'unavailable')
              .map((e) => e.data['observerStarted']),
          everyElement(isFalse));
    });
    test('a collector bound affects only its own control', () async {
      final p = await iosProject();
      p.probe = ran('ios-simulator', {
        'verified': true,
        'keyQueriesComplete': false,
        'viewLimitReached': false,
        'fileLimitReached': false,
        'screen': {'windows': 1},
        'backup': {'files': 2},
        'key_access': {'keychainItems': 1},
      });
      expect((await check(p, 'key_access')).isIncomplete, isTrue);
      expect((await check(p, 'screen')).isIncomplete, isFalse);
      expect((await check(p, 'backup')).isIncomplete, isFalse);
    });
    test('a proven finding stays counted when coverage is partial', () async {
      final dir = Directory.systemTemp.createTempSync('aegis-platform-');
      addTearDown(() => dir.deleteSync(recursive: true));
      File('${dir.path}/pubspec.yaml').writeAsStringSync('name: app\n');
      File('${dir.path}/$manifestPath')
        ..parent.createSync(recursive: true)
        ..writeAsStringSync('$manifestHeader<application/></manifest>');
      final r = await runAudit(dir.path,
          rules: platformProtectionRules,
          offline: true,
          probe: ran('android', {
            'verified': true,
            'viewLimitReached': true,
            'webview': {'webviews': 1, 'webviewInsecureContent': 1},
          }));
      final web = result(r, 'AEG-N07');
      // RuleStatus.failed keeps the score; the flag records partial coverage.
      expect(web.status, RuleStatus.failed);
      expect(web.counts, isTrue);
      expect(web.incomplete, isTrue);
      expect(web.findings, hasLength(1));
      expect(r.complete, isFalse);
    });
  });
  test('a static audit of Android and iOS sources is complete', () async {
    final r = await audit({
      manifestPath: '$manifestHeader<application/></manifest>',
      'ios/Runner/Info.plist':
          '<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict/></plist>',
    });
    expect(
        r.incomplete.map((x) => x.meta.id).toSet()
          ..retainAll(platformRuleIds.values.toSet()),
        isEmpty);
    for (final id in platformRuleIds.values) {
      expect(result(r, id).status, RuleStatus.evidenceOnly, reason: id);
      expect(result(r, id).counts, isFalse, reason: id);
    }
  });
}
