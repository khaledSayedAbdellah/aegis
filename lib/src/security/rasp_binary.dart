/// Runtime protection as it can be read from a compiled APK, AAB or IPA.
///
/// A compiled app also carries the root and jailbreak checks of its crash and
/// analytics libraries, so every check is attributed to the code that holds
/// it: a RASP SDK, a [DeviceCheckingLibrary], or the app.
library;

import 'dart:convert';

import '../binary/apk.dart';
import '../binary/dex.dart';
import '../binary/ipa.dart';
import 'rasp_detection.dart';

/// RASP SDKs and plugins by their Android class names.
final _androidSdks = <(String, RegExp)>[
  ('freeRASP (Talsec)', RegExp(r'^com\.aheaditec\.(?:talsec|freerasp)')),
  ('RootBeer', RegExp(r'^com\.scottyab\.rootbeer\.')),
  ('Approov', RegExp(r'^(?:io\.approov|com\.criticalblue\.approov)')),
  ('Zimperium zDefend', RegExp(r'^com\.zimperium\.')),
  ('DexProtector', RegExp(r'^com\.licel\.')),
  ('DexGuard', RegExp(r'^com\.guardsquare\.dexguard\.')),
  ('safe_device', RegExp(r'^com\.xamdesign\.safe_device\.')),
  (
    'flutter_jailbreak_detection',
    RegExp(r'^appmire\.be\.flutterjailbreakdetection\.')
  ),
];

/// RASP SDKs by a name that stays in an iOS binary: the framework, or the
/// module and class names of statically linked code.
final _appleSdks = <(String, RegExp)>[
  ('freeRASP (Talsec)', RegExp(r'TalsecRuntime|^freerasp$')),
  ('IOSSecuritySuite', RegExp(r'IOSSecuritySuite')),
  ('DTTJailbreakDetection', RegExp(r'DTTJailbreakDetection')),
  ('Approov', RegExp(r'^Approov')),
  ('Zimperium zDefend', RegExp(r'^ZDefend')),
];

/// Names R8 gives to classes it renames: `a.b`, `o.c3`, `b4.x`.
final _obfuscatedClass =
    RegExp(r'^(?:[A-Za-z0-9_$]{1,3}\.)*[A-Za-z0-9_$]{1,3}$');

const _dexLimit = 96 * 1024 * 1024;
const _nativeLimit = 96 * 1024 * 1024;

RaspInventory detectApkRasp(ApkContext apk) {
  final inventory = RaspInventory();
  final classes = <String>{};
  final users = <String, Set<String>>{};
  // Checks found in code whose owner cannot be told.
  final unidentified = <String>{};
  final libraries = <String, (Set<String> checks, Set<String> places)>{};
  final present = <String>{};

  void own(String place, Set<String> checks, {bool identified = true}) {
    for (final check in checks) {
      ((inventory.custom[raspAndroid] ??= {})[check] ??= {}).add(place);
    }
    if (!identified) unidentified.add(place);
  }

  void library(String name, String place, Set<String> checks) {
    final entry = libraries[name] ??= (<String>{}, <String>{});
    entry.$1.addAll(checks);
    entry.$2.add(place);
  }

  final dexFiles = apk.zip.entries.values
      .where((e) => RegExp(r'(^|/)classes\d*\.dex$').hasMatch(e.name))
      .toList()
    ..sort((a, b) => a.name.compareTo(b.name));
  for (final entry in dexFiles) {
    if (entry.size > _dexLimit) continue;
    final bytes = apk.zip.readEntry(entry);
    final usage = readDexUsage(
        bytes, (text) => raspChecksIn(text, platform: raspAndroid));
    classes.addAll(usage.classes);
    usage.users.forEach((name, checks) {
      (users[name] ??= {}).addAll(checks);
    });
    if (!usage.complete) {
      // Unreadable code: its strings still say which checks exist.
      final checks = raspChecksIn(printableStrings(bytes, min: 4).join('\n'),
          platform: raspAndroid);
      if (checks.isNotEmpty) own(entry.name, checks, identified: false);
    }
  }

  DeviceCheckingLibrary? libraryOf(String className) => deviceCheckingLibraries
      .where((l) => l.ownsAndroidClass(className))
      .firstOrNull;
  String? sdkOf(String className) => _androidSdks
      .where((sdk) => sdk.$2.hasMatch(className))
      .map((sdk) => sdk.$1)
      .firstOrNull;

  final sdkClasses = <String, String>{};
  for (final name in classes) {
    final sdk = sdkOf(name);
    if (sdk != null) {
      final first = sdkClasses[sdk];
      if (first == null || name.compareTo(first) < 0) sdkClasses[sdk] = name;
      continue;
    }
    final lib = libraryOf(name);
    if (lib != null && lib.checksDevice) present.add(lib.name);
  }
  for (final e in sdkClasses.entries) {
    inventory.sdks.add(RaspSource(e.key, 'binary', e.value, {raspAndroid}));
  }
  for (final e in users.entries) {
    if (sdkOf(e.key) != null) continue;
    final lib = libraryOf(e.key);
    if (lib != null) {
      library(lib.name, e.key, e.value);
    } else {
      own(e.key, e.value, identified: !_obfuscatedClass.hasMatch(e.key));
    }
  }

  // Native libraries of one ABI: the others hold the same code.
  final abi = apk.abis.isEmpty
      ? null
      : const ['arm64-v8a', 'armeabi-v7a', 'x86_64', 'x86']
              .where(apk.abis.contains)
              .firstOrNull ??
          apk.abis.first;
  if (abi != null) {
    for (final entry in apk.zip.entries.values) {
      final name = entry.name;
      if (!name.startsWith('lib/$abi/') || !name.endsWith('.so')) continue;
      final file = name.split('/').last;
      if (file == 'libflutter.so' || entry.size > _nativeLimit) continue;
      final lib = deviceCheckingLibraries
          .where((l) => l.ownsNativeLibrary(file))
          .firstOrNull;
      if (lib != null && lib.checksDevice) present.add(lib.name);
      final checks = raspChecksIn(
          latin1.decode(apk.zip.readEntry(entry), allowInvalid: true),
          platform: raspAndroid);
      if (checks.isEmpty) continue;
      if (lib != null) {
        library(lib.name, name, checks);
      } else {
        own(name, checks);
      }
    }
  }

  _finish(inventory, raspAndroid, libraries, present, unidentified);
  return inventory;
}

RaspInventory detectIpaRasp(IpaContext ipa) {
  final inventory = RaspInventory();
  final unidentified = <String>{};
  final libraries = <String, (Set<String> checks, Set<String> places)>{};
  final present = <String>{};
  final sdks = <String, String>{};
  var encrypted = false;

  void own(String place, Set<String> checks, {bool identified = true}) {
    for (final check in checks) {
      ((inventory.custom[raspIos] ??= {})[check] ??= {}).add(place);
    }
    if (!identified) unidentified.add(place);
  }

  void library(String name, String place, Set<String> checks) {
    final entry = libraries[name] ??= (<String>{}, <String>{});
    entry.$1.addAll(checks);
    entry.$2.add(place);
  }

  DeviceCheckingLibrary? libraryOf(String name) =>
      deviceCheckingLibraries.where((l) => l.ownsAppleName(name)).firstOrNull;
  String? sdkOf(String name) => _appleSdks
      .where((sdk) => sdk.$2.hasMatch(name))
      .map((sdk) => sdk.$1)
      .firstOrNull;

  for (final binary in ipa.staticAnalysis.binaries) {
    final place = binary.path.startsWith('${ipa.appPath}/')
        ? binary.path.substring(ipa.appPath.length + 1)
        : binary.path;
    final framework =
        RegExp(r'(?:^|/)([^/]+)\.framework/').firstMatch(place)?[1];
    if (framework == 'Flutter') continue;
    if (binary.slices.any((s) => s.encrypted)) encrypted = true;

    // The framework's name survives encryption and symbol stripping.
    if (framework != null) {
      final sdk = sdkOf(framework) ??
          (raspPackages.contains(framework) ||
                  raspPackageName.hasMatch(framework.toLowerCase())
              ? framework
              : null);
      if (sdk != null) {
        sdks.putIfAbsent(sdk, () => place);
        continue;
      }
    }
    final frameworkLibrary = framework == null ? null : libraryOf(framework);
    if (frameworkLibrary != null && frameworkLibrary.checksDevice) {
      present.add(frameworkLibrary.name);
    }

    // Statically linked code keeps its class names in the metadata.
    final linked = <String>{};
    final owned = <String, Set<String>>{};
    final loose = <String>{};
    for (final slice in binary.slices) {
      for (final entry in slice.metadata.entries) {
        final owner = entry.owner;
        final name = owner ?? entry.name;
        final sdk = sdkOf(name);
        if (sdk != null) sdks.putIfAbsent(sdk, () => place);
        final lib = libraryOf(name);
        if (lib != null && lib.checksDevice) linked.add(lib.name);
        final checks = raspChecksIn(entry.qualifiedName, platform: raspIos);
        if (checks.isEmpty) continue;
        if (owner == null) {
          loose.addAll(checks);
        } else {
          (owned[owner] ??= {}).addAll(checks);
        }
      }
      for (final symbol in slice.symbols) {
        final match = RegExp(r'OBJC_CLASS_\$_(\w+)').firstMatch(symbol);
        if (match == null) continue;
        final sdk = sdkOf(match[1]!);
        if (sdk != null) sdks.putIfAbsent(sdk, () => place);
        final lib = libraryOf(match[1]!);
        if (lib != null && lib.checksDevice) linked.add(lib.name);
      }
      loose.addAll(raspChecksIn([...slice.strings, ...slice.symbols].join('\n'),
          platform: raspIos));
      // ptrace is not a public iOS API: an app only names it to deny
      // debuggers.
      if (slice.symbols.contains('_ptrace') ||
          slice.strings.contains('ptrace')) {
        loose.add(raspDebugger);
      }
    }
    present.addAll(linked);

    for (final e in owned.entries) {
      if (sdkOf(e.key) != null) continue;
      final lib = frameworkLibrary ?? libraryOf(e.key);
      if (lib != null) {
        library(lib.name, '$place (${e.key})', e.value);
      } else {
        own('$place (${e.key})', e.value);
      }
    }
    if (loose.isEmpty) continue;
    if (frameworkLibrary != null) {
      library(frameworkLibrary.name, place, loose);
    } else {
      // In the main executable, strings without a class may belong to a
      // library that is linked into it.
      own(place, loose, identified: framework != null || linked.isEmpty);
    }
  }

  for (final e in sdks.entries) {
    inventory.sdks.add(RaspSource(e.key, 'binary', e.value, {raspIos}));
  }
  _finish(inventory, raspIos, libraries, present, unidentified);
  inventory.unreadable = encrypted && inventory.sdks.isEmpty;
  return inventory;
}

void _finish(
    RaspInventory inventory,
    String platform,
    Map<String, (Set<String>, Set<String>)> libraries,
    Set<String> present,
    Set<String> unidentified) {
  for (final e in libraries.entries) {
    final places = e.value.$2.toList()..sort();
    inventory.libraries.add(RaspSource(
        e.key, 'library', places.take(3).join(', '), {platform},
        checks: e.value.$1));
  }
  // The integrity check counts as the app's own only when the code it is in
  // can be identified, or when no library that has the same check is there.
  final integrity = inventory.custom[platform]?[raspIntegrityCheck(platform)];
  if (integrity != null &&
      integrity.every(unidentified.contains) &&
      present.isNotEmpty) {
    inventory.uncertain[platform] = present;
  }
}
