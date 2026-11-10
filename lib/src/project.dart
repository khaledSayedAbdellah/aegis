/// Loads everything the rules need from a Flutter project on disk.
library;

import 'dart:convert';
import 'dart:io';

import 'package:path/path.dart' as p;
import 'package:xml/xml.dart';
import 'package:yaml/yaml.dart';

import 'binary/apk.dart';
import 'binary/ipa.dart';
import 'binary/ios_signature.dart';
import 'config.dart';
import 'security/evidence.dart';
import 'security/android_references.dart';
import 'security/runtime_security.dart';
import 'l10n/messages.g.dart';
import 'dart_scanner.dart';
import 'plist.dart';
import 'probe/probe_model.dart';
import 'util.dart';

const androidNs = 'http://schemas.android.com/apk/res/android';

/// A text file of the project, relative path + content.
class ProjectFile {
  ProjectFile(this.path, this.text);
  final String path;
  final String text;
}

class LockedPackage {
  LockedPackage(this.name, this.version, this.source);
  final String name;
  final String version;

  /// `hosted`, `git`, `path` or `sdk`.
  final String source;
}

class Project {
  Project._(this.root, this.config);

  /// Absolute project root.
  final String root;
  final AegisConfig config;

  /// When true, rules must not use the network (OSV lookups are skipped).
  bool offline = false;
  final List<SecurityEvidence> securityEvidence = [];

  /// False when only a compiled binary is audited (no pubspec.yaml).
  bool hasSource = true;

  /// The release APK to audit alongside the source, if any.
  ApkContext? apk;
  late final AndroidReferences? nativeAndroidReferences = apk == null ? null : AndroidReferences(apk!);
  IpaContext? ipa;
  IosSignature? iosSignature;

  /// The resilience probe's outcome when this run tried it (rules AEG-R01..R04).
  ProbeOutcome? probe;
  RuntimeSecurityResult? runtimeSecurity;

  late final String name;
  Map<dynamic, dynamic> pubspec = {};

  /// Direct dependency name -> raw yaml spec.
  final Map<String, Object?> dependencies = {};
  final Map<String, Object?> devDependencies = {};
  final Map<String, Object?> dependencyOverrides = {};
  final Map<String, LockedPackage> locked = {};
  String? lockIssue;
  String? lockIssueAr;
  final List<String> assets = [];

  final List<DartFile> dartFiles = [];

  /// First-party packages (git and path dependencies) whose Dart code was
  /// scanned together with the app. Their files are named `package:<name>/...`.
  final List<String> scannedPackages = [];

  // Android
  ProjectFile? androidManifest;
  XmlDocument? androidManifestXml;
  ProjectFile? appGradle;
  String? networkSecurityConfigReference;
  ProjectFile? networkSecurityConfig;
  XmlDocument? networkSecurityConfigXml;
  final List<ProjectFile> androidNativeSources = [];

  // iOS
  ProjectFile? infoPlist;
  Map<String, Object?>? infoPlistData;
  final Map<String, Map<String, Object?>> entitlements = {};
  final List<ProjectFile> iosNativeSources = [];

  /// CI / build scripts that may contain `flutter build` commands.
  final List<ProjectFile> buildScripts = [];

  /// Lines of `.gitignore` files (root, android/, ios/).
  final List<String> gitignore = [];

  bool get hasAndroid => Directory(p.join(root, 'android')).existsSync();
  bool get hasIos => Directory(p.join(root, 'ios')).existsSync();
  bool get isFlutterApp =>
      dependencies.containsKey('flutter') ||
      hasAndroid ||
      hasIos;

  /// Whether [package] is a direct dependency (not dev-only).
  bool dependsOn(String package) => dependencies.containsKey(package);

  /// Whether [package] is anywhere in the resolved graph (pubspec.lock), or
  /// a direct dependency when no lock file exists.
  bool usesPackage(String package) =>
      locked.containsKey(package) || dependencies.containsKey(package);

  /// Absolute path for a project-relative path.
  String abs(String relative) => p.join(root, relative);

  String rel(String absolute) => slash(p.relative(absolute, from: root));

  /// Loads the project at [path]. Throws [FileSystemException] when there is
  /// no `pubspec.yaml`.
  static Project load(String path, {AegisConfig? config}) {
    final root = p.normalize(p.absolute(path));
    final pubspecFile = File(p.join(root, 'pubspec.yaml'));
    if (!pubspecFile.existsSync()) {
      throw FileSystemException('No pubspec.yaml found', root);
    }
    final project = Project._(root, config ?? AegisConfig.load(root));
    project._loadPubspec(pubspecFile.readAsStringSync());
    project._loadLock();
    project._loadDart();
    project._loadFirstPartyPackages();
    project._loadAndroid();
    project._loadIos();
    project._loadBuildScripts();
    project._loadGitignore();
    return project;
  }

  /// A project with no source code, used to audit an APK on its own.
  static Project binaryOnly(String path, ApkContext apk, {AegisConfig? config}) {
    final root = p.normalize(p.absolute(path));
    final project = Project._(root, config ?? AegisConfig.load(root))
      ..hasSource = false
      ..apk = apk;
    project.name = apk.packageName ?? p.basenameWithoutExtension(apk.path);
    return project;
  }

  static Project ipaOnly(String path, IpaContext ipa, {AegisConfig? config}) {
    final root = p.normalize(p.absolute(path));
    final project = Project._(root, config ?? AegisConfig.load(root))
      ..hasSource = false
      ..name = ipa.bundleId;
    return project;
  }

  void useIpa(IpaContext artifact, IosSignature signature) {
    ipa = artifact;
    iosSignature = signature;
    final infoPath = '${artifact.label}!/${artifact.appPath}/Info.plist';
    infoPlist = ProjectFile(infoPath, '');
    infoPlistData = artifact.info;
    entitlements.clear();
    for (final slice in artifact.machO) {
      if (slice.entitlements case final value?) {
        entitlements['${artifact.label}!/${artifact.appPath}/${artifact.executable} [${slice.architecture}]'] = value;
      }
    }
  }

  void _loadPubspec(String text) {
    final Object? doc;
    try {
      doc = loadYaml(text);
    } on YamlException catch (e) {
      throw FormatException('Invalid pubspec.yaml: ${e.message}');
    }
    if (doc is! Map) throw const FormatException('pubspec.yaml must be a map.');
    pubspec = doc;
    name = (pubspec['name'] ?? p.basename(root)).toString();
    void fill(Object? section, Map<String, Object?> into) {
      if (section is Map) {
        section.forEach((k, v) => into[k.toString()] = v);
      }
    }

    fill(pubspec['dependencies'], dependencies);
    fill(pubspec['dev_dependencies'], devDependencies);
    fill(pubspec['dependency_overrides'], dependencyOverrides);

    final flutter = pubspec['flutter'];
    if (flutter is Map && flutter['assets'] is List) {
      for (final a in flutter['assets'] as List) {
        if (a is String) {
          assets.add(a);
        } else if (a is Map && a['path'] != null) {
          assets.add(a['path'].toString());
        }
      }
    }
  }

  /// [relative] in the project root or, for members of a pub workspace
  /// (`resolution: workspace`), in up to three parent folders.
  File? _findUp(String relative) {
    final levels = pubspec['resolution'] == 'workspace' ? 4 : 1;
    var dir = root;
    for (var i = 0; i < levels; i++) {
      final f = File(p.join(dir, relative));
      if (f.existsSync()) return f;
      final parent = p.dirname(dir);
      if (parent == dir) break;
      dir = parent;
    }
    return null;
  }

  void _loadLock() {
    final f = _findUp('pubspec.lock');
    if (f == null) return;
    try {
      final doc = loadYaml(f.readAsStringSync());
      final pkgs = doc is Map ? doc['packages'] : null;
      if (pkgs is! Map) {
        lockIssue = En.lockPackagesMissing;
        lockIssueAr = Ar.lockPackagesMissing;
        return;
      }
      pkgs.forEach((k, v) {
        if (v is Map) {
          locked[k.toString()] = LockedPackage(
              k.toString(), (v['version'] ?? '').toString(),
              (v['source'] ?? 'hosted').toString());
        }
      });
    } catch (_) {
      lockIssue = En.lockUnreadable;
        lockIssueAr = Ar.lockUnreadable;
    }
  }

  static final _generated = RegExp(
      r'(\.g|\.freezed|\.gr|\.config|\.mocks|\.pb|\.pbenum|\.pbjson|\.chopper|\.gen)\.dart$');

  void _loadDart() {
    for (final dir in const ['lib', 'bin']) {
      final d = Directory(p.join(root, dir));
      if (!d.existsSync()) continue;
      for (final e in d.listSync(recursive: true, followLinks: false)) {
        if (e is! File || !e.path.endsWith('.dart')) continue;
        final r = rel(e.path);
        if (_generated.hasMatch(r)) continue;
        if (r.startsWith('lib/generated/') || r.contains('/l10n/generated')) {
          continue;
        }
        if (config.isExcluded(r)) continue;
        try {
          dartFiles.add(DartFile(r, e.readAsStringSync()));
        } catch (_) {
          // Skip unreadable files (encoding errors etc).
        }
      }
    }
    dartFiles.sort((a, b) => a.path.compareTo(b.path));
  }

  /// Adds the Dart code of git and path dependencies: in most companies these
  /// are your own packages (auth, networking, storage) and that is where the
  /// security-relevant code lives. pub.dev packages are not scanned.
  void _loadFirstPartyPackages() {
    if (!config.scanPackages) return;
    final cfgFile = _findUp(p.join('.dart_tool', 'package_config.json'));
    if (cfgFile == null) return;
    Object? json;
    try {
      json = jsonDecode(cfgFile.readAsStringSync());
    } catch (_) {
      return;
    }
    final packages = json is Map ? json['packages'] : null;
    if (packages is! List) return;
    final base = Uri.directory(cfgFile.parent.path);
    for (final e in packages) {
      if (e is! Map) continue;
      final pkg = e['name']?.toString();
      final rootUri = e['rootUri']?.toString();
      if (pkg == null || rootUri == null || pkg == name) continue;
      final source = locked[pkg]?.source;
      if (source != 'git' && source != 'path') continue;
      final pkgRoot = base.resolve(rootUri.endsWith('/') ? rootUri : '$rootUri/');
      final libDir = Directory.fromUri(pkgRoot.resolve(e['packageUri']?.toString() ?? 'lib/'));
      if (!libDir.existsSync()) continue;
      // A path dependency inside lib/ would be scanned twice.
      if (p.isWithin(p.join(root, 'lib'), libDir.path)) continue;
      var count = 0;
      for (final f in libDir.listSync(recursive: true, followLinks: false)) {
        if (f is! File || !f.path.endsWith('.dart')) continue;
        final inLib = slash(p.relative(f.path, from: libDir.path));
        if (_generated.hasMatch(inLib) || inLib.startsWith('generated/')) continue;
        final virtual = 'package:$pkg/$inLib';
        if (config.isExcluded(virtual)) continue;
        try {
          dartFiles.add(DartFile(virtual, f.readAsStringSync()));
          count++;
        } catch (_) {
          // Skip unreadable files.
        }
      }
      if (count > 0) scannedPackages.add(pkg);
    }
    scannedPackages.sort();
  }

  ProjectFile? _read(String relative) {
    final f = File(p.join(root, relative));
    if (!f.existsSync()) return null;
    try {
      return ProjectFile(slash(relative), f.readAsStringSync());
    } catch (_) {
      return null;
    }
  }

  void _loadAndroid() {
    if (!hasAndroid) return;
    androidManifest = _read('android/app/src/main/AndroidManifest.xml');
    if (androidManifest != null) {
      try {
        androidManifestXml = XmlDocument.parse(androidManifest!.text);
      } catch (_) {
        // Invalid XML: the rules report the file as not applicable.
      }
    }
    appGradle = _read('android/app/build.gradle.kts') ??
        _read('android/app/build.gradle');

    final app = androidManifestXml == null
        ? null
        : firstElement(androidManifestXml!, 'application');
    final nsc = app == null ? null : androidAttr(app, 'networkSecurityConfig');
    networkSecurityConfigReference = nsc;
    if (nsc != null && nsc.startsWith('@xml/')) {
      networkSecurityConfig =
          _read('android/app/src/main/res/xml/${nsc.substring(5)}.xml');
      if (networkSecurityConfig != null) {
        try {
          networkSecurityConfigXml =
              XmlDocument.parse(networkSecurityConfig!.text);
        } catch (_) {
        // Invalid XML: the rules report the file as not applicable.
      }
      }
    }

    for (final dir in const ['android/app/src/main/kotlin', 'android/app/src/main/java']) {
      final d = Directory(p.join(root, dir));
      if (!d.existsSync()) continue;
      for (final e in d.listSync(recursive: true, followLinks: false)) {
        if (e is File && (e.path.endsWith('.kt') || e.path.endsWith('.java'))) {
          final f = _read(rel(e.path));
          if (f != null) androidNativeSources.add(f);
        }
      }
    }
  }

  void _loadIos() {
    if (!hasIos) return;
    infoPlist = _read('ios/Runner/Info.plist');
    if (infoPlist != null) infoPlistData = parsePlist(infoPlist!.text);

    final runner = Directory(p.join(root, 'ios', 'Runner'));
    if (runner.existsSync()) {
      for (final e in runner.listSync(recursive: true, followLinks: false)) {
        if (e is! File) continue;
        if (e.path.endsWith('.entitlements')) {
          final f = _read(rel(e.path));
          final data = f == null ? null : parsePlist(f.text);
          if (data != null) entitlements[f!.path] = data;
        } else if (e.path.endsWith('.swift') || e.path.endsWith('.m')) {
          final f = _read(rel(e.path));
          if (f != null) iosNativeSources.add(f);
        }
      }
    }
  }

  void _loadBuildScripts() {
    const fixed = [
      'codemagic.yaml',
      'bitrise.yml',
      'azure-pipelines.yml',
      '.gitlab-ci.yml',
      'Jenkinsfile',
      'Makefile',
      'melos.yaml',
      'fastlane/Fastfile',
      'android/fastlane/Fastfile',
      'ios/fastlane/Fastfile',
      'appcenter-post-clone.sh',
    ];
    for (final f in fixed) {
      final file = _read(f);
      if (file != null) buildScripts.add(file);
    }
    for (final dir in const ['.github/workflows', 'scripts', '.circleci', 'ci']) {
      final d = Directory(p.join(root, dir));
      if (!d.existsSync()) continue;
      for (final e in d.listSync(recursive: true, followLinks: false)) {
        if (e is File &&
            (e.path.endsWith('.yml') ||
                e.path.endsWith('.yaml') ||
                e.path.endsWith('.sh'))) {
          final file = _read(rel(e.path));
          if (file != null) buildScripts.add(file);
        }
      }
    }
    final rootDir = Directory(root);
    for (final e in rootDir.listSync(followLinks: false)) {
      if (e is File && e.path.endsWith('.sh')) {
        final file = _read(rel(e.path));
        if (file != null) buildScripts.add(file);
      }
    }
  }

  void _loadGitignore() {
    for (final f in const ['.gitignore', 'android/.gitignore', 'ios/.gitignore']) {
      final file = _read(f);
      if (file == null) continue;
      final prefix = f.contains('/') ? '${p.dirname(f)}/' : '';
      for (final line in file.text.split('\n')) {
        final l = line.trim();
        if (l.isEmpty || l.startsWith('#')) continue;
        gitignore.add(l.startsWith('/') ? '$prefix${l.substring(1)}' : '$prefix$l');
        if (!l.contains('/')) gitignore.add(l); // matches at any depth
      }
    }
  }

  /// Rough `.gitignore` check for [relativePath].
  bool isGitIgnored(String relativePath) {
    final base = p.basename(relativePath);
    for (final pattern in gitignore) {
      final cleaned = pattern.endsWith('/')
          ? pattern.substring(0, pattern.length - 1)
          : pattern;
      if (cleaned == relativePath || cleaned == base) return true;
      if (cleaned.contains('*')) {
        final re = globToRegExp(cleaned);
        if (re.hasMatch(relativePath) || re.hasMatch(base)) return true;
      }
      if (relativePath.startsWith('$cleaned/')) return true;
    }
    return false;
  }

  /// Files on disk below [dir] (relative) matching [test].
  List<String> findFiles(String dir, bool Function(String rel) test) {
    final d = Directory(p.join(root, dir));
    if (!d.existsSync()) return const [];
    final out = <String>[];
    for (final e in d.listSync(recursive: true, followLinks: false)) {
      if (e is! File) continue;
      final r = rel(e.path);
      if (r.contains('/build/') || r.contains('/.dart_tool/')) continue;
      if (test(r)) out.add(r);
    }
    return out;
  }
}

/// First element named [name] anywhere in [doc].
XmlElement? firstElement(XmlNode doc, String name) {
  for (final e in doc.findAllElements(name)) {
    return e;
  }
  return null;
}

/// Reads `android:<name>` from [e].
String? androidAttr(XmlElement e, String name) {
  for (final a in e.attributes) {
    if (a.name.local == name &&
        (a.name.prefix == 'android' || a.name.namespaceUri == androidNs)) {
      return a.value;
    }
  }
  return null;
}
