/// Native dependency versions of a project, for OSV lookups: Maven (Gradle
/// files, version catalogs, Gradle lock files), npm (package-lock.json,
/// yarn.lock) and Swift Package Manager (Package.resolved).
library;

import 'dart:convert';
import 'dart:io';

import 'package:path/path.dart' as p;

import 'native_files.dart' show nativeIgnoredDirectories;

class NativeDependency {
  NativeDependency(this.ecosystem, this.name, this.version, this.file);

  /// OSV ecosystem: `Maven`, `npm` or `SwiftURL`.
  final String ecosystem;
  final String name;
  final String version;

  /// Where it was found, relative to the project.
  final String file;
}

/// Exact versions only: ranges, `+`, variables and snapshots are skipped.
final _exact = RegExp(r'^\d+(?:\.\d+)*(?:[-.][\w.]+)?$');

bool _isExact(String v) =>
    _exact.hasMatch(v) &&
    !v.contains('+') &&
    !v.toUpperCase().contains('SNAPSHOT');

/// Files named for dependencies under [root] (within six folders), as
/// (relative path, text).
List<(String, String)> dependencyFiles(String root) {
  const names = {
    'build.gradle',
    'build.gradle.kts',
    'libs.versions.toml',
    'gradle.lockfile',
    'package-lock.json',
    'yarn.lock',
    'Package.resolved',
  };
  final out = <(String, String)>[];
  var visited = 0;
  void visit(Directory dir, int depth) {
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
      if (e is File && names.contains(name)) {
        try {
          if (e.lengthSync() > 8 * 1024 * 1024) continue;
          out.add((
            p.relative(e.path, from: root).replaceAll(r'\', '/'),
            e.readAsStringSync()
          ));
        } catch (_) {}
      } else if (e is Directory &&
          depth < 6 &&
          !nativeIgnoredDirectories.contains(name) &&
          !const {'node_modules', 'Pods', 'build', '.dart_tool', 'DerivedData'}
              .contains(name)) {
        visit(e, depth + 1);
      }
    }
  }

  visit(Directory(root), 0);
  return out;
}

/// The dependencies declared in [files] (from [dependencyFiles]).
List<NativeDependency> parseNativeDependencies(List<(String, String)> files) {
  final out = <NativeDependency>[];
  final seen = <String>{};
  void add(String ecosystem, String name, String version, String file) {
    if (name.isEmpty || !_isExact(version)) return;
    if (seen.add('$ecosystem|$name|$version')) {
      out.add(NativeDependency(ecosystem, name, version, file));
    }
  }

  for (final (file, text) in files) {
    final name = p.basename(file);
    switch (name) {
      case 'build.gradle' || 'build.gradle.kts':
        for (final m in RegExp(
                r'''\b(?:implementation|api|compileOnly|runtimeOnly|kapt|ksp|classpath|releaseImplementation|platform)\s*\(?\s*["']([\w.\-]+):([\w.\-]+):([\w.\-]+)["']''')
            .allMatches(text)) {
          add('Maven', '${m[1]}:${m[2]}', m[3]!, file);
        }
      case 'gradle.lockfile':
        for (final m
            in RegExp(r'^([\w.\-]+):([\w.\-]+):([\w.\-]+)=', multiLine: true)
                .allMatches(text)) {
          add('Maven', '${m[1]}:${m[2]}', m[3]!, file);
        }
      case 'libs.versions.toml':
        _catalog(text).forEach((module, version) {
          add('Maven', module, version, file);
        });
      case 'package-lock.json':
        _packageLock(text).forEach((n, v) => add('npm', n, v, file));
      case 'yarn.lock':
        _yarnLock(text).forEach((n, v) => add('npm', n, v, file));
      case 'Package.resolved':
        _packageResolved(text).forEach((n, v) => add('SwiftURL', n, v, file));
    }
  }
  return out;
}

/// `[libraries]` of a Gradle version catalog, with `version.ref` resolved.
Map<String, String> _catalog(String text) {
  final versions = <String, String>{};
  final out = <String, String>{};
  var section = '';
  for (final raw in text.split('\n')) {
    final line = raw.split('#').first.trim();
    final header = RegExp(r'^\[(\w+)\]$').firstMatch(line);
    if (header != null) {
      section = header[1]!;
      continue;
    }
    final kv = RegExp(r'^([\w.\-]+)\s*=\s*(.+)$').firstMatch(line);
    if (kv == null) continue;
    final value = kv[2]!;
    if (section == 'versions') {
      final s = RegExp(r'^"([^"]+)"$').firstMatch(value);
      if (s != null) versions[kv[1]!] = s[1]!;
    } else if (section == 'libraries') {
      final plain =
          RegExp(r'^"([\w.\-]+):([\w.\-]+):([\w.\-]+)"$').firstMatch(value);
      if (plain != null) {
        out['${plain[1]}:${plain[2]}'] = plain[3]!;
        continue;
      }
      final module =
          RegExp(r'module\s*=\s*"([\w.\-]+:[\w.\-]+)"').firstMatch(value)?[1] ??
              (() {
                final g =
                    RegExp(r'group\s*=\s*"([\w.\-]+)"').firstMatch(value)?[1];
                final n =
                    RegExp(r'\bname\s*=\s*"([\w.\-]+)"').firstMatch(value)?[1];
                return g == null || n == null ? null : '$g:$n';
              })();
      if (module == null) continue;
      final version = RegExp(r'version\s*=\s*"([^"]+)"')
              .firstMatch(value)?[1] ??
          versions[
              RegExp(r'version\.ref\s*=\s*"([\w.\-]+)"').firstMatch(value)?[1]];
      if (version != null) out[module] = version;
    }
  }
  return out;
}

Map<String, String> _packageLock(String text) {
  final out = <String, String>{};
  Object? json;
  try {
    json = jsonDecode(text);
  } catch (_) {
    return out;
  }
  if (json is! Map) return out;
  final packages = json['packages'];
  if (packages is Map) {
    packages.forEach((key, value) {
      final k = key.toString();
      final i = k.lastIndexOf('node_modules/');
      if (i < 0 || value is! Map) return;
      final v = value['version'];
      if (v is String) out[k.substring(i + 'node_modules/'.length)] = v;
    });
    return out;
  }
  void visit(Object? deps) {
    if (deps is! Map) return;
    deps.forEach((name, value) {
      if (value is! Map) return;
      final v = value['version'];
      if (v is String) out[name.toString()] = v;
      visit(value['dependencies']);
    });
  }

  visit(json['dependencies']);
  return out;
}

Map<String, String> _yarnLock(String text) {
  final out = <String, String>{};
  String? current;
  for (final line in text.split('\n')) {
    if (line.isEmpty || line.startsWith('#')) continue;
    if (!line.startsWith(' ') && line.trimRight().endsWith(':')) {
      final spec = line.split(',').first.trim().replaceAll('"', '');
      final at = spec.lastIndexOf('@');
      current = at > 0 ? spec.substring(0, at) : null;
      continue;
    }
    final v = RegExp(r'^\s+version:?\s+"?([^"\s]+)"?').firstMatch(line);
    if (v != null && current != null) {
      out[current] = v[1]!;
      current = null;
    }
  }
  return out;
}

Map<String, String> _packageResolved(String text) {
  final out = <String, String>{};
  Object? json;
  try {
    json = jsonDecode(text);
  } catch (_) {
    return out;
  }
  if (json is! Map) return out;
  final pins =
      json['pins'] ?? (json['object'] is Map ? json['object']['pins'] : null);
  if (pins is! List) return out;
  for (final pin in pins) {
    if (pin is! Map) continue;
    final url = (pin['location'] ?? pin['repositoryURL'])?.toString();
    final state = pin['state'];
    final version = state is Map ? state['version']?.toString() : null;
    if (url == null || version == null) continue;
    final name = url
        .replaceFirst(RegExp(r'^[a-z+]+://'), '')
        .replaceFirstMapped(RegExp(r'^git@([^:]+):'), (m) => '${m[1]}/')
        .replaceFirst(RegExp(r'\.git$'), '')
        .replaceFirst(RegExp(r'/+$'), '');
    out[name] = version;
  }
  return out;
}
