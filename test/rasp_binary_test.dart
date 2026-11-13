import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:aegis/aegis.dart';
import 'package:aegis/src/binary/dex.dart';
import 'package:aegis/src/security/rasp_detection.dart';
import 'package:archive/archive.dart';
import 'package:path/path.dart' as p;
import 'package:test/test.dart';

import 'support/dex_fixture.dart';
import 'support/macho_security_fixture.dart';

const rootPaths = ['/system/xbin/su', 'com.topjohnwu.magisk'];
const sentryRootChecker = 'io.sentry.android.core.internal.util.RootChecker';
const jailbreakPaths = ['/Applications/Cydia.app', '/var/jb'];

void main() {
  late Directory dir;
  setUp(() {
    dir = Directory.systemTemp.createTempSync('aegis-rasp-binary-');
    addTearDown(() => dir.deleteSync(recursive: true));
  });

  Future<AuditReport> audit({String? apk, String? ipa}) => runAudit(dir.path,
      apkPath: apk,
      ipaPath: ipa,
      config: AegisConfig(profile: ProfileSet.tryParse('l2+r')!),
      offline: true);

  /// The secure fixture APK with its DEX replaced and [files] added.
  Future<AuditReport> apk(Map<String, List<String>> classes,
      {List<String> referenced = const [],
      Map<String, List<int>> files = const {}}) {
    final source = ZipDecoder()
        .decodeBytes(File('test/fixtures/apk/secure.apk').readAsBytesSync());
    final archive = Archive();
    for (final f in source.files) {
      if (f.name == 'classes.dex' || files.containsKey(f.name)) continue;
      archive.addFile(ArchiveFile.bytes(f.name, f.content as List<int>));
    }
    archive.addFile(ArchiveFile.bytes(
        'classes.dex', dexFile(classes, referenced: referenced)));
    files.forEach(
        (name, bytes) => archive.addFile(ArchiveFile.bytes(name, bytes)));
    final path = p.join(dir.path, 'app.apk');
    File(path).writeAsBytesSync(ZipEncoder().encode(archive));
    return audit(apk: path);
  }

  Future<AuditReport> ipa(Uint8List main,
      [Map<String, List<int>> extras = const {}]) {
    const app = 'Payload/Test.app';
    final archive = Archive()
      ..addFile(ArchiveFile.bytes(
          '$app/Info.plist',
          utf8.encode('<plist><dict><key>CFBundleIdentifier</key>'
              '<string>org.aegis.test</string><key>CFBundleExecutable</key>'
              '<string>Test</string></dict></plist>')))
      ..addFile(ArchiveFile.bytes('$app/Test', main));
    extras.forEach((name, bytes) =>
        archive.addFile(ArchiveFile.bytes('$app/$name', bytes)));
    final path = p.join(dir.path, 'app.ipa');
    File(path).writeAsBytesSync(ZipEncoder().encode(archive));
    return audit(ipa: path);
  }

  RuleResult p01(AuditReport r) =>
      r.results.singleWhere((x) => x.meta.id == 'AEG-P01');
  List<String> messages(AuditReport r) =>
      p01(r).findings.map((f) => f.message).toList();
  List<String> evidence(AuditReport r) => r.securityEvidence
      .where((e) => e.ruleId == 'AEG-P01')
      .map((e) => e.detail.en)
      .toList();

  group('DEX reader', () {
    test('finds the class that loads a string or calls a method', () {
      final usage = readDexUsage(
          dexFile({
            'com.acme.Guard': [...rootPaths, 'call:isDebuggerConnected'],
            'com.acme.Other': ['hello', 'call:toString'],
          }, referenced: [
            'io.sentry.android.core.SentryInitProvider'
          ]),
          (text) => raspChecksIn(text, platform: raspAndroid));
      expect(usage.complete, isTrue);
      expect(usage.classes, {
        'com.acme.Guard',
        'com.acme.Other',
        'io.sentry.android.core.SentryInitProvider'
      });
      expect(usage.users, {
        'com.acme.Guard': {raspRoot, raspDebugger}
      });
    });

    test('reads a file compiled by d8', () {
      // Java compiled with javac and d8 --release: com.acme.Guard has root
      // paths, Debug.isDebuggerConnected() and "frida-server" among packed
      // and sparse switches and an array literal; a class named like
      // Sentry's RootChecker tests "test-keys".
      final usage = readDexUsage(
          File('test/fixtures/dex/d8.dex').readAsBytesSync(),
          (text) => raspChecksIn(text, platform: raspAndroid));
      expect(usage.complete, isTrue);
      expect(usage.users, {
        'com.acme.Guard': {raspRoot, raspDebugger, raspHooking},
        sentryRootChecker: {raspRoot},
      });
    });

    test('a truncated file is reported as incomplete, not as empty', () {
      final bytes = dexFile({
        'com.acme.Guard': rootPaths,
      });
      final cut = Uint8List.sublistView(bytes, 0, bytes.length - 24);
      expect(readDexUsage(cut, raspChecksIn).complete, isFalse);
      expect(readDexUsage(Uint8List(8), raspChecksIn).complete, isFalse);
    });
  });

  group('APK', () {
    test('no protection at all', () async {
      final r = await apk({
        'com.acme.Main': ['hello']
      });
      expect(messages(r),
          ['Android: no RASP SDK and no root detection was found in the APK.']);
    });

    test("a crash reporter's root check is not protection", () async {
      final r = await apk({
        sentryRootChecker: rootPaths,
        'com.acme.Main': ['hello'],
      });
      expect(p01(r).status, RuleStatus.failed);
      expect(messages(r).single,
          startsWith('Android: the only root detection belongs to Sentry.'));
      expect(evidence(r), [
        'Sentry checks for root on Android ($sentryRootChecker). It does '
            'this for its own reports, so it is not counted as protection.'
      ]);
    });

    test('a RASP SDK in the APK passes, whatever else is there', () async {
      final r = await apk({
        sentryRootChecker: rootPaths,
        'com.scottyab.rootbeer.RootBeer': ['/sbin/su'],
      });
      expect(p01(r).status, RuleStatus.passed);
      expect(
          evidence(r),
          contains('Runtime protection on Android: RootBeer, found in '
              'com.scottyab.rootbeer.RootBeer.'));
    });

    test("the app's own checks count when its classes can be identified",
        () async {
      final partial = await apk({
        'com.acme.shop.Guard': rootPaths,
        sentryRootChecker: rootPaths,
      });
      expect(messages(partial).single,
          startsWith("Android: the app's own checks detect root but not"));

      final full = await apk({
        'com.acme.shop.Guard': [
          ...rootPaths,
          'call:isDebuggerConnected',
          'de.robv.android.xposed.XposedBridge'
        ],
      });
      expect(p01(full).status, RuleStatus.passed);
    });

    test('checks in the compiled Dart code are the app\'s own', () async {
      final r = await apk({
        'com.acme.Main': ['hello']
      }, files: {
        'lib/arm64-v8a/libapp.so':
            utf8.encode('\x00/system/xbin/su\x00TracerPid\x00frida-server\x00'),
      });
      expect(p01(r).status, RuleStatus.passed);
      expect(evidence(r).single, contains('lib/arm64-v8a/libapp.so'));
    });

    test('renamed classes next to a crash reporter cannot be attributed',
        () async {
      // R8 renamed the class that holds the check; Sentry's entry point kept
      // its name, so the check may be Sentry's.
      final unknown = await apk({
        'a.b': [...rootPaths, 'call:isDebuggerConnected', 'frida-server'],
      }, referenced: [
        'io.sentry.android.core.SentryInitProvider'
      ]);
      expect(p01(unknown).status, RuleStatus.evidenceOnly);
      expect(p01(unknown).note, contains('Sentry is in the same APK'));
      expect(evidence(unknown).single, contains('are not counted'));

      // Without such a library the renamed code can only be the app's.
      final own = await apk({
        'a.b': [...rootPaths, 'call:isDebuggerConnected', 'frida-server'],
      });
      expect(p01(own).status, RuleStatus.passed);
    });
  });

  group('IPA', () {
    test('no protection at all', () async {
      final r = await ipa(securityMachO(strings: ['hello']));
      expect(messages(r), [
        'iOS: no RASP SDK and no jailbreak detection was found in the IPA.'
      ]);
    });

    test("a crash reporter's jailbreak check is not protection", () async {
      final r = await ipa(securityMachO(strings: ['hello']), {
        'Frameworks/Sentry.framework/Sentry':
            securityMachO(fileType: 6, strings: jailbreakPaths),
      });
      expect(messages(r).single,
          startsWith('iOS: the only jailbreak detection belongs to Sentry.'));
    });

    test('a RASP framework passes', () async {
      final r = await ipa(securityMachO(strings: ['hello']), {
        'Frameworks/IOSSecuritySuite.framework/IOSSecuritySuite':
            securityMachO(fileType: 6, strings: ['x']),
      });
      expect(p01(r).status, RuleStatus.passed);
      expect(
          evidence(r).single,
          'Runtime protection on iOS: IOSSecuritySuite, found in '
          'Frameworks/IOSSecuritySuite.framework/IOSSecuritySuite.');
    });

    test("the app's own checks in the executable", () async {
      final partial = await ipa(securityMachO(strings: jailbreakPaths));
      expect(messages(partial).single,
          startsWith("iOS: the app's own checks detect jailbreak but not"));

      final full = await ipa(
          securityMachO(strings: [...jailbreakPaths, 'ptrace', 'FridaGadget']));
      expect(p01(full).status, RuleStatus.passed);
    });

    test('checks next to a statically linked crash reporter are uncertain',
        () async {
      final r = await ipa(securityMachO(
          strings: [...jailbreakPaths, 'ptrace', 'FridaGadget'],
          symbols: [(r'_OBJC_CLASS_$_SentryCrashMonitor', 0x0f)]));
      expect(p01(r).status, RuleStatus.evidenceOnly);
      expect(p01(r).note, contains('Sentry is in the same IPA'));
    });

    test('an encrypted IPA cannot be judged', () async {
      final r = await ipa(securityMachO(encrypted: true));
      expect(p01(r).status, RuleStatus.incomplete);
      expect(p01(r).note, contains('encrypted'));
    });
  });
}
