/// Finds runtime protection (RASP) wherever an app can have it: a Dart
/// package that the code imports, a native SDK declared in Gradle, CocoaPods,
/// Swift Package Manager or package.json and referenced by the code, or the
/// app's own root/jailbreak, debugger and hooking checks in Dart or native
/// source.
library;

import 'dart:io';

import 'package:path/path.dart' as p;

import '../project.dart';
import '../project/native_files.dart' show nativeIgnoredDirectories;
import 'native_analysis.dart' show withoutComments;

const raspAndroid = 'android';
const raspIos = 'ios';

/// Check categories. `root` applies to Android, `jailbreak` to iOS.
const raspRoot = 'root';
const raspJailbreak = 'jailbreak';
const raspDebugger = 'debugger';
const raspHooking = 'hooking';

/// The check that makes a platform's protection count at all.
String raspIntegrityCheck(String platform) =>
    platform == raspAndroid ? raspRoot : raspJailbreak;

/// Dart packages known to provide runtime protection or device-integrity
/// checks. Others are recognized by [raspPackageName] or by scanning their
/// native code.
const raspPackages = [
  'freerasp',
  'safe_device',
  'flutter_jailbreak_detection',
  'jailbreak_root_detection',
  'flutter_neo_shield',
  'flutter_app_security',
  'trust_fall',
  'root_checker_plus',
  'flutter_root_jailbreak_checker',
  'device_safety_info',
  'flutter_security_checker',
  'approov_service_flutter_httpclient',
];

/// Package names that say what they do: `root_checker`, `anti_debug`,
/// `jailbreak_detection`, `app_integrity`...
final raspPackageName = RegExp(
    r'(?:^|_)(?:rasp|root|rooted|jailbreak|jailbroken|tamper|antitamper|'
    r'anti_tamper|antidebug|anti_debug|antifrida|anti_frida|frida|integrity|'
    r'safe_device|security_checker|device_safety)(?:_|$)');

/// Literal indicators of each check in source code. Names alone (`isRooted`)
/// are not indicators: a stub that returns false has the same name.
final raspIndicators = <String, RegExp>{
  raspRoot:
      RegExp(r'/system/(?:x?bin|sbin|sd/xbin|bin/\.ext|usr/we-need-root)/su\b|'
          r'/sbin/su\b|/su/bin/su\b|/data/local(?:/x?bin)?/su\b|Superuser\.apk|'
          r'com\.topjohnwu\.magisk|eu\.chainfire\.supersu|'
          r'com\.koushikdutta\.superuser|com\.noshufou\.android\.su|'
          r'com\.thirdparty\.superuser|com\.yellowes\.su|\btest-keys\b|'
          r'\bRootBeer\b'),
  raspJailbreak:
      RegExp(r'/Applications/(?:Cydia|Sileo|Zebra|blackra1n|FakeCarrier|Icy|'
          r'IntelliScreen|SBSettings|WinterBoard|RockApp|MxTube)\.app|'
          r'/Library/MobileSubstrate|/var/jb\b|/usr/sbin/sshd|/etc/apt\b|'
          r'cydia://|sileo://|zbra://|/private/var/lib/(?:apt|cydia)|'
          r'/private/var/stash|/private/jailbreak\.txt|/var/lib/undecimus|'
          r'/\.bootstrapped_electra|/\.installed_unc0ver|/usr/libexec/cydia|'
          r'amIJailbroken'),
  raspDebugger:
      RegExp(r'isDebuggerConnected|waitingForDebugger|TracerPid|PT_DENY_ATTACH|'
          r'\bP_TRACED\b|amIDebugged|amIBeingDebugged|denyDebugger'),
  raspHooking: RegExp(
      r'\b[Ff]rida\b|FRIDA|frida-server|frida-gadget|FridaGadget|gum-js-loop|'
      r'\b27042\b|de\.robv\.android\.xposed|XposedBridge|LSPosed|EdXposed|'
      r'com\.saurik\.substrate|\bMobileSubstrate\b|MSHookFunction|'
      r'MSHookMessageEx|SubstrateLoader|libcycript|cynject|SSLKillSwitch|'
      r'amIReverseEngineered|amIRuntimeHooked'),
};

/// A native SDK that provides runtime protection. [usage] is null for
/// build-time protectors (DexGuard, DexProtector), which the code never calls.
class NativeRaspSdk {
  const NativeRaspSdk(this.name, this.platform, this.declared, this.usage);
  final String name;

  /// [raspAndroid], [raspIos], or `react-native` for package.json.
  final String platform;
  final RegExp declared;
  final RegExp? usage;
}

final nativeRaspSdks = [
  NativeRaspSdk('freeRASP (Talsec)', raspAndroid,
      RegExp(r'com\.aheaditec\.talsec'), RegExp(r'com\.aheaditec\.talsec')),
  NativeRaspSdk('freeRASP (Talsec)', raspIos, RegExp(r'TalsecRuntime'),
      RegExp(r'\bTalsecRuntime\b|SecurityThreatCenter')),
  NativeRaspSdk('RootBeer', raspAndroid, RegExp(r'com\.scottyab:rootbeer'),
      RegExp(r'\bRootBeer\b')),
  NativeRaspSdk('IOSSecuritySuite', raspIos, RegExp(r'IOSSecuritySuite'),
      RegExp(r'\bIOSSecuritySuite\b')),
  NativeRaspSdk('DTTJailbreakDetection', raspIos,
      RegExp(r'DTTJailbreakDetection'), RegExp(r'DTTJailbreakDetection')),
  NativeRaspSdk('DexGuard', raspAndroid,
      RegExp(r'com\.guardsquare|\bdexguard\b', caseSensitive: false), null),
  NativeRaspSdk('DexProtector', raspAndroid,
      RegExp(r'com\.licel|\bdexprotector\b', caseSensitive: false), null),
  NativeRaspSdk('Approov', raspAndroid, RegExp(r'io\.approov'),
      RegExp(r'io\.approov|\bApproov\w*\b')),
  NativeRaspSdk(
      'Approov', raspIos, RegExp(r'\bApproov\w*'), RegExp(r'\bApproov\w*\b')),
  NativeRaspSdk('Zimperium zDefend', raspAndroid, RegExp(r'com\.zimperium'),
      RegExp(r'com\.zimperium')),
  NativeRaspSdk('freeRASP (Talsec)', 'react-native',
      RegExp(r'"freerasp-react-native"'), RegExp(r'freerasp-react-native')),
  NativeRaspSdk('jail-monkey', 'react-native', RegExp(r'"jail-monkey"'),
      RegExp(r'jail-monkey')),
];

/// A crash, analytics or attribution SDK that checks for root or jailbreak to
/// label its own reports. Its checks never react to a threat, so they are not
/// protection for the app.
class DeviceCheckingLibrary {
  const DeviceCheckingLibrary(this.name,
      {required this.dart,
      required this.android,
      required this.apple,
      this.nativeLibrary,
      this.checksDevice = true});
  final String name;

  /// False for libraries that are only listed so their code is not taken for
  /// the app's own.
  final bool checksDevice;

  /// Dart package names.
  final String dart;

  /// Android class names (`io.sentry.`), as a prefix pattern.
  final String android;

  /// iOS framework and class names, as a prefix pattern.
  final String apple;

  /// Android `.so` file names, as a prefix pattern.
  final String? nativeLibrary;

  bool isDartPackage(String package) => _prefix(dart).hasMatch(package);
  bool ownsAndroidClass(String name) => _prefix(android).hasMatch(name);
  bool ownsAppleName(String name) => _prefix(apple).hasMatch(name);
  bool ownsNativeLibrary(String file) =>
      nativeLibrary != null && _prefix(nativeLibrary!).hasMatch(file);
}

final _prefixes = <String, RegExp>{};
RegExp _prefix(String pattern) =>
    _prefixes[pattern] ??= RegExp('^(?:$pattern)');

/// More specific entries first (Crashlytics before Firebase).
const deviceCheckingLibraries = [
  DeviceCheckingLibrary('Sentry',
      dart: r'sentry(?:_|$)',
      android: r'io\.sentry\.',
      apple: r'Sentry',
      nativeLibrary: r'libsentry'),
  DeviceCheckingLibrary('Firebase Crashlytics',
      dart: r'firebase_crashlytics$',
      android: r'com\.google\.firebase\.crashlytics\.',
      apple: r'FirebaseCrashlytics|FIRCLS',
      nativeLibrary: r'libcrashlytics'),
  DeviceCheckingLibrary('Bugsnag',
      dart: r'bugsnag_',
      android: r'com\.bugsnag\.',
      apple: r'Bugsnag|BSG[A-Z]',
      nativeLibrary: r'libbugsnag'),
  DeviceCheckingLibrary('Instabug',
      dart: r'instabug_',
      android: r'com\.instabug\.',
      apple: r'Instabug|IBG[A-Z]',
      nativeLibrary: r'libibg|libinstabug'),
  DeviceCheckingLibrary('Datadog',
      dart: r'datadog_',
      android: r'com\.datadog\.',
      apple: r'Datadog',
      nativeLibrary: r'libdatadog'),
  DeviceCheckingLibrary('AppsFlyer',
      dart: r'appsflyer_', android: r'com\.appsflyer\.', apple: r'AppsFlyer'),
  DeviceCheckingLibrary('Adjust',
      dart: r'adjust_sdk$',
      android: r'com\.adjust\.sdk\.',
      apple: r'Adjust(?:Sdk)?$|ADJ[A-Z]'),
  DeviceCheckingLibrary('New Relic',
      dart: r'newrelic_',
      android: r'com\.newrelic\.',
      apple: r'NewRelic|NRMA',
      nativeLibrary: r'libnewrelic'),
  DeviceCheckingLibrary('App Center',
      dart: r'appcenter',
      android: r'com\.microsoft\.appcenter\.',
      apple: r'AppCenter|MSAC[A-Z]'),
  DeviceCheckingLibrary('Embrace',
      dart: r'embrace',
      android: r'io\.embrace\.',
      apple: r'Embrace|EMB[A-Z]',
      nativeLibrary: r'libembrace'),
  DeviceCheckingLibrary('Firebase / Google Play services',
      dart: r'firebase_',
      android: r'com\.google\.(?:firebase|android\.gms)\.',
      apple: r'Firebase|GoogleUtilities|GoogleAppMeasurement|FIR[A-Z]|GUL[A-Z]',
      checksDevice: false),
  DeviceCheckingLibrary('Facebook SDK',
      dart: r'flutter_facebook|facebook_',
      android: r'com\.facebook\.',
      apple: r'FBSDK|FBAEMKit',
      checksDevice: false),
];

/// One way the app gets runtime protection.
class RaspSource {
  RaspSource(this.name, this.kind, this.file, this.platforms,
      {this.checks = const {}});

  /// Package, SDK or `custom`.
  final String name;

  /// `package` (known name), `package-name` (recognized by its name),
  /// `package-code` (its native code has integrity checks), `sdk`, `custom`,
  /// `binary` (an SDK found in an APK or IPA) or `library` (a
  /// [DeviceCheckingLibrary]: found, but not protection).
  final String kind;

  /// Where it is used or declared.
  final String file;
  final Set<String> platforms;

  /// For `package-code` and `custom`: the checks found.
  final Set<String> checks;
}

class RaspInventory {
  /// Packages and SDKs: each protects its platforms completely.
  final List<RaspSource> sdks = [];

  /// The app's own checks: platform -> check -> files.
  final Map<String, Map<String, Set<String>>> custom = {};

  /// Checks that belong to a crash or analytics library, not to the app.
  final List<RaspSource> libraries = [];

  /// Binary audits: platform -> libraries that are in the binary while the
  /// checks in [custom] are in code whose owner cannot be identified, so
  /// they may be the library's.
  final Map<String, Set<String>> uncertain = {};

  /// Binary audits: true when the code could not be read (encrypted IPA).
  bool unreadable = false;

  /// Protection that is declared but never used by the code.
  final List<(String name, String file)> unused = [];

  bool coversWithSdk(String platform) =>
      sdks.any((s) => s.platforms.contains(platform));

  /// Libraries with a root or jailbreak check on [platform].
  List<String> librariesChecking(String platform) => {
        for (final l in libraries)
          if (l.platforms.contains(platform) &&
              l.checks.contains(raspIntegrityCheck(platform)))
            l.name
      }.toList();
}

/// [roots] maps package names to their folders (see `resolvePackageRoots`);
/// packages without one are only recognized by name.
RaspInventory detectRasp(Project project, Set<String> platforms,
    {Map<String, String> roots = const {}}) {
  final inventory = RaspInventory();
  _dartPackages(project, platforms, inventory, roots);
  _nativeSdks(project, platforms, inventory);
  _customChecks(project, platforms, inventory);
  return inventory;
}

Iterable<String> _candidatePackages(Project project) =>
    ({...project.locked.keys, ...project.dependencies.keys}
          ..remove(project.name)
          ..remove('flutter'))
        .toList()
      ..sort();

/// Imported packages that are not recognized by name: their code has to be
/// read to know whether they check the device.
Set<String> raspPackagesToScan(Project project) => {
      for (final package in _candidatePackages(project))
        if (!raspPackages.contains(package) &&
            !raspPackageName.hasMatch(package) &&
            project.dartFiles.any((f) => f.importsPackage(package)))
          package
    };

void _dartPackages(Project project, Set<String> platforms,
    RaspInventory inventory, Map<String, String> roots) {
  for (final package in _candidatePackages(project)) {
    final importing =
        project.dartFiles.where((f) => f.importsPackage(package)).firstOrNull;
    final known = raspPackages.contains(package);
    final named = !known && raspPackageName.hasMatch(package);
    if (importing == null) {
      if ((known || named) && project.dependsOn(package)) {
        inventory.unused.add((package, 'pubspec.yaml'));
      }
      continue;
    }
    if (known || named) {
      inventory.sdks.add(RaspSource(package, known ? 'package' : 'package-name',
          importing.path, platforms));
      continue;
    }
    final root = roots[package];
    if (root == null) continue;
    final found = _scanPackage(root, platforms);
    final covered = platforms
        .where((pl) => found[pl]?.contains(raspIntegrityCheck(pl)) ?? false)
        .toSet();
    if (covered.isEmpty) continue;
    final source = RaspSource(package, 'package-code', importing.path, covered,
        checks: {for (final pl in covered) ...found[pl]!});
    final library = deviceCheckingLibraries
        .where((l) => l.isDartPackage(package))
        .firstOrNull;
    if (library == null) {
      inventory.sdks.add(source);
    } else {
      inventory.libraries.add(RaspSource(
          package, 'library', importing.path, covered,
          checks: source.checks));
    }
  }
}

const _sourceExtensions = {'.kt', '.java', '.swift', '.m', '.mm', '.dart'};

/// Checks found in a package's Dart and native code, per platform.
Map<String, Set<String>> _scanPackage(String root, Set<String> platforms) {
  final found = <String, Set<String>>{};
  var files = 0;
  for (final (sub, platform) in [
    ('android', raspAndroid),
    ('ios', raspIos),
    ('darwin', raspIos),
    ('lib', null),
  ]) {
    final dir = Directory(p.join(root, sub));
    if (!dir.existsSync()) continue;
    for (final file in _walk(dir)) {
      if (++files > 400) return found;
      final String text;
      try {
        if (file.lengthSync() > 512 * 1024) continue;
        text = file.readAsStringSync();
      } catch (_) {
        continue;
      }
      final targets = platform == null ? platforms : {platform};
      _record(withoutComments(text), targets.intersection(platforms),
          (pl, check) => (found[pl] ??= {}).add(check));
    }
  }
  return found;
}

Iterable<File> _walk(Directory dir) sync* {
  final List<FileSystemEntity> entries;
  try {
    entries = dir.listSync(followLinks: false);
  } on FileSystemException {
    return;
  }
  for (final e in entries) {
    final name = p.basename(e.path);
    if (e is Directory) {
      if (nativeIgnoredDirectories.contains(name) ||
          {'example', 'test', 'androidTest', 'Tests'}.contains(name)) {
        continue;
      }
      yield* _walk(e);
    } else if (e is File && _sourceExtensions.contains(p.extension(name))) {
      yield e;
    }
  }
}

/// The checks whose indicators are in [code]. With [platform], only the
/// checks that protect it are looked for.
Set<String> raspChecksIn(String code, {String? platform}) => {
      for (final entry in raspIndicators.entries)
        if ((platform == null || raspCheckApplies(entry.key, platform)) &&
            entry.value.hasMatch(code))
          entry.key
    };

/// True when [check] protects [platform]: root checks only protect Android,
/// jailbreak checks iOS.
bool raspCheckApplies(String check, String platform) =>
    !(check == raspRoot && platform != raspAndroid) &&
    !(check == raspJailbreak && platform != raspIos);

/// Calls [add] for each check whose indicator is in [code], on the platforms
/// it applies to.
void _record(String code, Set<String> platforms,
    void Function(String platform, String check) add) {
  for (final check in raspChecksIn(code)) {
    for (final platform in platforms) {
      if (raspCheckApplies(check, platform)) add(platform, check);
    }
  }
}

void _nativeSdks(
    Project project, Set<String> platforms, RaspInventory inventory) {
  final manifests = _dependencyFiles(project);
  if (manifests.isEmpty) return;
  final sources = <String, List<ProjectFile>>{
    raspAndroid: [
      ...project.androidNativeSources,
      ...project.sharedNativeSources
    ],
    raspIos: project.iosNativeSources,
    'react-native': project.scriptSources,
  };
  for (final sdk in nativeRaspSdks) {
    final targets = sdk.platform == 'react-native' ? platforms : {sdk.platform};
    if (targets.intersection(platforms).isEmpty) continue;
    for (final (file, text, platform) in manifests) {
      if (platform != sdk.platform) continue;
      if (!sdk.declared.hasMatch(withoutComments(text))) continue;
      final usage = sdk.usage;
      final user = usage == null
          ? file
          : sources[sdk.platform]!
              .where((f) => usage.hasMatch(withoutComments(f.text)))
              .map((f) => f.path)
              .firstOrNull;
      if (user == null) {
        inventory.unused.add((sdk.name, file));
      } else if (!inventory.sdks
          .any((s) => s.name == sdk.name && s.platforms.containsAll(targets))) {
        inventory.sdks.add(
            RaspSource(sdk.name, 'sdk', user, targets.intersection(platforms)));
      }
      break;
    }
  }
}

/// Gradle, CocoaPods, Swift Package Manager and npm files that declare the
/// app's own dependencies (lock files also list the plugins' dependencies).
List<(String file, String text, String platform)> _dependencyFiles(
    Project project) {
  final out = <(String, String, String)>[];
  var visited = 0;
  void visit(Directory dir, int depth) {
    if (depth > 8) return;
    final List<FileSystemEntity> entries;
    try {
      entries = dir.listSync(followLinks: false)
        ..sort((a, b) => a.path.compareTo(b.path));
    } on FileSystemException {
      return;
    }
    for (final e in entries) {
      if (++visited > 20000) return;
      final name = p.basename(e.path);
      final rel = project.rel(e.path);
      if (project.config.isExcluded(rel)) continue;
      if (e is Directory) {
        if (nativeIgnoredDirectories.contains(name)) continue;
        if (name.endsWith('.xcodeproj')) {
          final pbx = File(p.join(e.path, 'project.pbxproj'));
          if (pbx.existsSync()) _add(out, project, pbx, raspIos);
          continue;
        }
        if (name.endsWith('.xcworkspace') || name.endsWith('.app')) continue;
        visit(e, depth + 1);
      } else if (e is File) {
        final platform = switch (name) {
          'build.gradle' ||
          'build.gradle.kts' ||
          'settings.gradle' ||
          'settings.gradle.kts' ||
          'libs.versions.toml' =>
            raspAndroid,
          'Podfile' || 'Package.swift' => raspIos,
          'package.json' => 'react-native',
          _ => null,
        };
        if (platform != null) _add(out, project, e, platform);
      }
    }
  }

  visit(Directory(project.root), 0);
  return out;
}

void _add(List<(String, String, String)> out, Project project, File file,
    String platform) {
  try {
    if (file.lengthSync() > 2 * 1024 * 1024) return;
    out.add((project.rel(file.path), file.readAsStringSync(), platform));
  } catch (_) {}
}

void _customChecks(
    Project project, Set<String> platforms, RaspInventory inventory) {
  void scan(String path, String text, Set<String> targets) {
    _record(withoutComments(text), targets.intersection(platforms),
        (platform, check) {
      ((inventory.custom[platform] ??= {})[check] ??= {}).add(path);
    });
  }

  for (final f in project.dartFiles) {
    scan(f.path, f.source, platforms);
  }
  for (final f in project.androidNativeSources) {
    scan(f.path, f.text, {raspAndroid});
  }
  for (final f in project.iosNativeSources) {
    scan(f.path, f.text, {raspIos});
  }
  for (final f in project.sharedNativeSources) {
    final targets = f.path.contains('/iosMain/')
        ? {raspIos}
        : f.path.contains('/androidMain/')
            ? {raspAndroid}
            : platforms;
    scan(f.path, f.text, targets);
  }
}
