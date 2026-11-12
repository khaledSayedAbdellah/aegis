/// Finds the release APK or AAB that `flutter build` left in a project, so
/// `aegis run --mode apk|aab` works without a path.
library;

import 'dart:io';

import 'package:path/path.dart' as p;

/// Where `flutter build apk` and `flutter build appbundle` write their files.
const flutterApkDir = 'build/app/outputs/flutter-apk';
const flutterBundleDir = 'build/app/outputs/bundle';

/// The newest release `.apk` (when [kind] is `apk`) or `.aab` (`aab`) under
/// the project at [root], or null when none has been built.
///
/// Debug and profile builds are ignored, so with several flavors the file
/// that was built last wins (e.g. `app-prod-release.aab`).
File? findBuiltBinary(String root, String kind) {
  assert(kind == 'apk' || kind == 'aab');
  final dir =
      Directory(p.join(root, kind == 'aab' ? flutterBundleDir : flutterApkDir));
  if (!dir.existsSync()) return null;
  File? newest;
  DateTime? newestTime;
  for (final e in dir.listSync(recursive: true, followLinks: false)) {
    if (e is! File || !e.path.toLowerCase().endsWith('.$kind')) continue;
    final rel = p.relative(e.path, from: dir.path).toLowerCase();
    if (!rel.contains('release')) continue;
    final time = e.lastModifiedSync();
    if (newestTime == null || time.isAfter(newestTime)) {
      newest = e;
      newestTime = time;
    }
  }
  return newest;
}

/// The release APK or AAB built most recently, whichever is newer.
File? findNewestBinary(String root) {
  final candidates = [
    findBuiltBinary(root, 'aab'),
    findBuiltBinary(root, 'apk')
  ].whereType<File>().toList()
    ..sort((a, b) => b.lastModifiedSync().compareTo(a.lastModifiedSync()));
  return candidates.isEmpty ? null : candidates.first;
}

/// The Flutter project a build file came from: the nearest folder at or above
/// [file]'s folder that has a pubspec.yaml, or null.
String? projectOf(String file) {
  var dir = p.dirname(p.absolute(file));
  while (true) {
    if (File(p.join(dir, 'pubspec.yaml')).existsSync()) return dir;
    final parent = p.dirname(dir);
    if (parent == dir) return null;
    dir = parent;
  }
}
