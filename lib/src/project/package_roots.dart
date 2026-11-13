/// Finds where each Dart dependency's files are, so their native code can be
/// read: `.dart_tool/package_config.json` first, then pubspec.lock and the pub
/// cache, and as a last step `pub get`.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:path/path.dart' as p;
import 'package:yaml/yaml.dart';

/// Runs `executable arguments` in a folder. Returns the exit code and the
/// error output, or null when the tool could not be started.
typedef PubRunner = Future<(int exitCode, String error)?> Function(
    String executable, List<String> arguments, String workingDirectory);

class PackageRoots {
  PackageRoots(this.roots, {this.command, this.created = false, this.issue});

  /// Package name -> folder.
  final Map<String, String> roots;

  /// The `pub get` command that was run, if one was.
  final String? command;

  /// True when that command wrote a pubspec.lock that was not there before.
  final bool created;

  /// Why some packages are still missing: `not-resolved` (pub get was not
  /// allowed), `tool-missing` or `failed`.
  final String? issue;
}

/// Locates [needed] packages of the project at [root].
///
/// With [pubGet], dependencies that neither `package_config.json` nor the pub
/// cache has are fetched with `flutter pub get` or `dart pub get`. When a
/// pubspec.lock exists the command runs with `--enforce-lockfile`, so the
/// lock file is never changed.
Future<PackageRoots> resolvePackageRoots(
  String root,
  Set<String> needed, {
  bool pubGet = false,
  bool offline = false,
  Map<String, String>? environment,
  PubRunner? run,
}) async {
  final roots = _fromPackageConfig(root);
  Set<String> missing() => needed.where((n) => !roots.containsKey(n)).toSet();
  if (missing().isEmpty) return PackageRoots(roots);

  final lock = _findUp(root, 'pubspec.lock');
  if (lock != null) {
    roots.addAll(_fromLock(lock, missing(), environment ?? Platform.environment)
      ..removeWhere((name, _) => roots.containsKey(name)));
    if (missing().isEmpty) return PackageRoots(roots);
  }

  final pubspec = File(p.join(root, 'pubspec.yaml'));
  if (!pubspec.existsSync()) return PackageRoots(roots);
  if (!pubGet) return PackageRoots(roots, issue: 'not-resolved');

  String text;
  try {
    text = pubspec.readAsStringSync();
  } catch (_) {
    text = '';
  }
  final tool = RegExp(r'^\s*sdk:\s*flutter\b', multiLine: true).hasMatch(text)
      ? 'flutter'
      : 'dart';
  final arguments = [
    'pub',
    'get',
    if (lock != null) '--enforce-lockfile',
    if (offline) '--offline',
  ];
  final command = '$tool ${arguments.join(' ')}';
  final result = await (run ?? _run)(tool, arguments, root);
  if (result == null) {
    return PackageRoots(roots, command: command, issue: 'tool-missing');
  }
  if (result.$1 != 0) {
    return PackageRoots(roots, command: command, issue: 'failed');
  }
  roots.addAll(_fromPackageConfig(root));
  return PackageRoots(roots,
      command: command,
      created: lock == null && _findUp(root, 'pubspec.lock') != null);
}

Future<(int, String)?> _run(
    String executable, List<String> arguments, String workingDirectory) async {
  final Process process;
  try {
    process = await Process.start(executable, arguments,
        workingDirectory: workingDirectory, runInShell: Platform.isWindows);
  } on ProcessException {
    return null;
  }
  final error = StringBuffer();
  unawaited(process.stdout.drain<void>().catchError((_) {}));
  final errors = process.stderr
      .transform(const Utf8Decoder(allowMalformed: true))
      .forEach((chunk) {
    if (error.length < 4000) error.write(chunk);
  }).catchError((_) {});
  try {
    final code = await process.exitCode.timeout(const Duration(minutes: 3));
    await errors;
    return (code, error.toString());
  } on TimeoutException {
    process.kill();
    return (-1, 'timed out');
  }
}

File? _findUp(String root, String name) {
  var dir = Directory(root);
  for (var i = 0; i < 6; i++) {
    final f = File(p.join(dir.path, name));
    if (f.existsSync()) return f;
    if (dir.parent.path == dir.path) break;
    dir = dir.parent;
  }
  return null;
}

Map<String, String> _fromPackageConfig(String root) {
  final out = <String, String>{};
  final config = _findUp(root, p.join('.dart_tool', 'package_config.json'));
  if (config == null) return out;
  Object? json;
  try {
    json = jsonDecode(config.readAsStringSync());
  } catch (_) {
    return out;
  }
  final packages = json is Map ? json['packages'] : null;
  if (packages is! List) return out;
  final base = Uri.directory(config.parent.path);
  for (final e in packages) {
    if (e is! Map) continue;
    final name = e['name']?.toString();
    final rootUri = e['rootUri']?.toString();
    if (name == null || rootUri == null) continue;
    try {
      final dir = base
          .resolve(rootUri.endsWith('/') ? rootUri : '$rootUri/')
          .toFilePath();
      if (Directory(dir).existsSync()) out[name] = dir;
    } catch (_) {}
  }
  return out;
}

/// The folders pub would use for the locked versions, when they are already
/// in the pub cache (or are path dependencies).
Map<String, String> _fromLock(
    File lock, Set<String> names, Map<String, String> environment) {
  final out = <String, String>{};
  Object? doc;
  try {
    doc = loadYaml(lock.readAsStringSync());
  } catch (_) {
    return out;
  }
  final packages = doc is Map ? doc['packages'] : null;
  if (packages is! Map) return out;
  final cache = pubCacheDirectory(environment);
  for (final name in names) {
    final entry = packages[name];
    if (entry is! Map) continue;
    final description = entry['description'];
    final version = entry['version']?.toString();
    String? dir;
    switch (entry['source']?.toString()) {
      case 'hosted':
        if (cache == null || version == null) break;
        final url = description is Map ? description['url']?.toString() : null;
        final hosted = description is Map
            ? (description['name']?.toString() ?? name)
            : name;
        for (final host in _hostDirectories(url)) {
          dir = p.join(cache, 'hosted', host, '$hosted-$version');
          if (Directory(dir).existsSync()) break;
        }
      case 'path':
        final path =
            description is Map ? description['path']?.toString() : null;
        if (path == null) break;
        dir = p.normalize(
            p.isAbsolute(path) ? path : p.join(lock.parent.path, path));
      case 'git':
        if (cache == null || description is! Map) break;
        final url = description['url']?.toString();
        final ref = description['resolved-ref']?.toString();
        if (url == null || ref == null) break;
        final repo = p.url
            .basename(url.replaceFirst(RegExp(r'/+$'), ''))
            .replaceFirst(RegExp(r'\.git$'), '');
        dir = p.normalize(p.join(cache, 'git', '$repo-$ref',
            description['path']?.toString() ?? '.'));
    }
    if (dir != null && Directory(dir).existsSync()) out[name] = dir;
  }
  return out;
}

/// `PUB_CACHE`, or pub's default location for this system.
String? pubCacheDirectory(Map<String, String> environment) {
  final custom = environment['PUB_CACHE'];
  if (custom != null && custom.isNotEmpty) return custom;
  if (Platform.isWindows) {
    final local = environment['LOCALAPPDATA'];
    return local == null ? null : p.join(local, 'Pub', 'Cache');
  }
  final home = environment['HOME'];
  return home == null ? null : p.join(home, '.pub-cache');
}

/// The cache folders pub derives from a hosted URL (pub.dev also has the
/// name older SDKs used).
List<String> _hostDirectories(String? url) {
  if (url == null ||
      RegExp(r'^https://pub\.(?:dev|dartlang\.org)/?$').hasMatch(url)) {
    return const ['pub.dev', 'pub.dartlang.org'];
  }
  final trimmed = url.replaceFirst(RegExp(r'/+$'), '').replaceFirstMapped(
      RegExp(r'^(https?://)(127\.0\.0\.1|\[::1\]|localhost)?'), (m) {
    final local = m[2] == null ? '' : 'localhost';
    final scheme = m[1] == 'https://' || local.isEmpty ? '' : m[1]!;
    return '$scheme$local';
  });
  return [
    trimmed.replaceAllMapped(
        RegExp(r'[<>:"\\/|?*%]'), (m) => '%${m[0]!.codeUnitAt(0)}')
  ];
}
