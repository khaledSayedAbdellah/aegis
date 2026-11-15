/// Network inspectors and debug tools that ship in release builds.
library;

import 'dart:io';

import 'package:path/path.dart' as p;

import '../binary/dex.dart';
import '../dart_scanner.dart';
import '../l10n/messages.g.dart';
import '../model.dart';
import '../project.dart';
import '../project/native_files.dart' show nativeIgnoredDirectories;
import 'dart_rules.dart' show guardedByDebug;
import 'rule.dart';

const _all = {MasProfile.l1, MasProfile.l2, MasProfile.r};

const _description =
    Bilingual(En.debugToolDescription, Ar.debugToolDescription);
const _fix = Bilingual(En.debugToolFix, Ar.debugToolFix);

/// Dart packages and the names that use them.
const _dartTools = <String, (String, Set<String>)>{
  'alice': ('Alice', {'Alice', 'AliceDioAdapter', 'AliceHttpAdapter'}),
  'alice_lightweight': ('Alice', {'Alice'}),
  'flutter_stetho': ('Stetho', {'Stetho', 'StethoHttpOverrides'}),
  'flutter_flipperkit': (
    'Flipper',
    {'FlipperClient', 'FlipperNetworkPlugin', 'FlipperReduxInspectorPlugin'}
  ),
  'device_preview': ('DevicePreview', {'DevicePreview'}),
  // chucker_flutter records nothing in release unless showOnRelease is set.
  'chucker_flutter': ('Chucker', {'showOnRelease'}),
};

/// Android libraries: the Gradle coordinates, and class names that only the
/// working implementation has (Chucker's library-no-op has neither).
const _androidTools = <(String, String, String)>[
  (
    'Chucker',
    'com.github.chuckerteam.chucker:library:',
    'com.chuckerteam.chucker.internal.'
  ),
  ('Stetho', 'com.facebook.stetho:stetho', 'com.facebook.stetho.inspector.'),
  ('Flipper', 'com.facebook.flipper:flipper', 'com.facebook.flipper.android.'),
  (
    'LeakCanary',
    'com.squareup.leakcanary:leakcanary-android',
    'leakcanary.internal.'
  ),
];

class DebugToolRule extends Rule {
  const DebugToolRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-D13',
        title: Bilingual(En.debugToolTitle, Ar.debugToolTitle),
        passTitleText: Bilingual(En.debugToolPass, Ar.debugToolPass),
        description: _description,
        fix: _fix,
        severity: Severity.medium,
        masvs: ['MASVS-RESILIENCE-4'],
        maswe: ['MASWE-0061', 'MASWE-0063'],
        cwe: 'CWE-489',
        profiles: _all,
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final out = <Finding>[];
    for (final e in _dartTools.entries) {
      if (!project.dependsOn(e.key)) continue;
      final (tool, names) = e.value;
      for (final f in project.dartFiles) {
        if (!f.importsPackage(e.key) || _debugOnlyFile(f.path)) continue;
        var used = false;
        for (var i = 0; i < f.tokens.length; i++) {
          final t = f.tokens[i];
          if (!t.isIdent || !names.contains(t.text)) continue;
          used = true;
          if (t.text == 'showOnRelease') {
            final next = f.tokens.skip(i + 1).take(2).map((t) => t.text).join();
            if (next != '=true') continue;
          } else if (guardedByDebug(f, i) || _previewDisabled(f, i)) {
            continue;
          }
          out.add(at(f, i, En.debugToolDart(tool: tool),
              messageAr: Ar.debugToolDart(tool: tool)));
          break;
        }
        if (!used && e.key != 'chucker_flutter') {
          final i = f.tokens.indexWhere((t) =>
              t.isString && (t.value ?? '').startsWith('package:${e.key}/'));
          out.add(at(f, i < 0 ? 0 : i, En.debugToolImport(tool: tool),
              messageAr: Ar.debugToolImport(tool: tool)));
        }
      }
    }
    for (final (file, text) in _gradleFiles(project)) {
      final lines = text.split('\n');
      for (var l = 0; l < lines.length; l++) {
        final m = RegExp(
                r'''^\s*(implementation|api|releaseImplementation|compile)\b[\s(]*["']([^"']+)["']''')
            .firstMatch(lines[l]);
        if (m == null) continue;
        for (final (tool, coordinates, _) in _androidTools) {
          if (!m[2]!.startsWith(coordinates)) continue;
          out.add(inFile(
              file, l + 1, En.debugToolGradle(tool: tool, configuration: m[1]!),
              messageAr: Ar.debugToolGradle(tool: tool, configuration: m[1]!)));
        }
      }
    }
    return RuleCheck(out);
  }

  /// Entry points and helpers only built for development flavors.
  static bool _debugOnlyFile(String path) {
    final folders = path.split('/')..removeLast();
    return RegExp(r'(?:^|_)(?:dev|debug|development|staging|mock|fake)(?:_|$)',
                caseSensitive: false)
            .hasMatch(p.basenameWithoutExtension(path)) ||
        folders.any((d) => const {
              'dev',
              'debug',
              'mock',
              'mocks',
              'fake',
              'fakes'
            }.contains(d));
  }

  /// `DevicePreview(enabled: !kReleaseMode, ...)`.
  static bool _previewDisabled(DartFile f, int i) {
    if (f.tokens[i].text != 'DevicePreview') return false;
    final open = i + 1;
    if (open >= f.tokens.length || !f.tokens[open].isPunct('(')) return false;
    final enabled = f.namedArg(f.args(open), 'enabled');
    if (enabled == null) return false;
    final text = f.text(enabled.start, enabled.end);
    return RegExp(r'kDebugMode|!\s*kReleaseMode|kProfileMode').hasMatch(text);
  }

  /// `build.gradle` / `build.gradle.kts` of the Android app.
  static List<(String, String)> _gradleFiles(Project project) {
    final out = <(String, String)>[];
    void visit(Directory dir, int depth) {
      final List<FileSystemEntity> entries;
      try {
        entries = dir.listSync(followLinks: false)
          ..sort((a, b) => a.path.compareTo(b.path));
      } on FileSystemException {
        return;
      }
      for (final e in entries) {
        final name = p.basename(e.path);
        if (e is File &&
            (name == 'build.gradle' || name == 'build.gradle.kts')) {
          try {
            out.add((project.rel(e.path), e.readAsStringSync()));
          } catch (_) {}
        } else if (e is Directory &&
            depth < 3 &&
            !nativeIgnoredDirectories.contains(name) &&
            !const {'node_modules', 'Pods', 'build', 'ios', 'lib'}
                .contains(name)) {
          visit(e, depth + 1);
        }
      }
    }

    visit(Directory(project.root), 0);
    return out;
  }
}

class DebugToolApkRule extends Rule {
  const DebugToolApkRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-B13',
        title: Bilingual(En.debugToolApkTitle, Ar.debugToolApkTitle),
        passTitleText: Bilingual(En.debugToolApkPass, Ar.debugToolApkPass),
        description: _description,
        fix: _fix,
        severity: Severity.medium,
        masvs: ['MASVS-RESILIENCE-4'],
        maswe: ['MASWE-0061', 'MASWE-0063'],
        cwe: 'CWE-489',
        profiles: _all,
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final apk = project.apk;
    if (apk == null) return RuleCheck.notApplicable();
    final manifest = apk.manifestText ?? '';
    final classes = <String>{};
    for (final e in apk.zip.entries.values) {
      if (!RegExp(r'(^|/)classes\d*\.dex$').hasMatch(e.name)) continue;
      if (e.size > 96 * 1024 * 1024) continue;
      classes
          .addAll(readDexUsage(apk.zip.readEntry(e), (_) => const {}).classes);
    }
    final out = <Finding>[];
    for (final (tool, _, prefix) in _androidTools) {
      final inManifest = manifest.contains(prefix);
      final cls = classes.where((c) => c.startsWith(prefix)).firstOrNull;
      if (!inManifest && cls == null) continue;
      final evidence = inManifest ? 'AndroidManifest.xml' : cls!;
      out.add(inFile(
          '${apk.fileName}!/${inManifest ? 'AndroidManifest.xml' : 'classes.dex'}',
          null,
          En.debugToolApk(tool: tool, evidence: evidence),
          messageAr: Ar.debugToolApk(tool: tool, evidence: evidence)));
    }
    return RuleCheck(out);
  }
}

const debugToolRules = <Rule>[DebugToolRule()];
