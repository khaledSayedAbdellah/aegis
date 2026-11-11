/// Bounded, deterministic discovery of first-party native sources/configuration.
library;

import 'dart:io';
import 'package:path/path.dart' as p;

const nativeIgnoredDirectories = {
  '.git',
  '.gradle',
  '.dart_tool',
  '.build',
  '.swiftpm',
  '.idea',
  'build',
  'Build',
  'DerivedData',
  'Pods',
  'Carthage',
  'node_modules',
  '.expo',
  '.next',
  '.turbo',
  'dist',
  'coverage',
  '__tests__',
  '__mocks__',
  'vendor',
  'generated',
  'test',
  'tests',
  'androidTest',
  'testFixtures',
};

const scriptExtensions = {
  '.js',
  '.jsx',
  '.ts',
  '.tsx',
  '.mjs',
  '.cjs',
  '.mts',
  '.cts'
};
const unsupportedSourceExtensions = {
  '.cs',
  '.fs',
  '.cpp',
  '.cc',
  '.cxx',
  '.qml',
  '.vue',
  '.svelte'
};

class NativeFiles {
  NativeFiles(this.files, this.projects, this.issues);
  final List<String> files;
  final List<String> projects;
  final List<String> issues;
  bool get recognized =>
      projects.isNotEmpty ||
      files.any((f) =>
          {
            '.kt',
            '.java',
            '.swift',
            '.m',
            '.mm',
            ...scriptExtensions,
            ...unsupportedSourceExtensions
          }.contains(p.extension(f)) ||
          p.basename(f) == 'package.json' ||
          p.basename(f) == 'AndroidManifest.xml');
}

NativeFiles discoverNativeFiles(String root,
    {bool Function(String)? excluded}) {
  final files = <String>[], projects = <String>[], issues = <String>[];
  var visited = 0;
  void visit(Directory dir, int depth) {
    if (depth > 24 || visited > 30000) {
      issues.add(p.relative(dir.path, from: root));
      return;
    }
    final List<FileSystemEntity> entries;
    try {
      entries = dir.listSync(followLinks: false)
        ..sort((a, b) => a.path.compareTo(b.path));
    } on FileSystemException {
      issues.add(p.relative(dir.path, from: root));
      return;
    }
    for (final entry in entries) {
      if (++visited > 30000) {
        issues.add('file-limit');
        break;
      }
      final relative = p.relative(entry.path, from: root).replaceAll('\\', '/');
      if (excluded?.call(relative) == true) continue;
      final name = p.basename(entry.path);
      if (entry is Directory) {
        if (name.endsWith('.xcodeproj') || name.endsWith('.xcworkspace')) {
          projects.add(relative);
        } else if (!nativeIgnoredDirectories.contains(name) &&
            !(p.basename(dir.path) == 'src' && name.endsWith('Test')) &&
            !name.endsWith('Tests') &&
            !name.endsWith('UITests') &&
            !name.endsWith('.app') &&
            !name.endsWith('.framework') &&
            !name.endsWith('.xcarchive')) {
          visit(entry, depth + 1);
        }
      } else if (entry is File &&
          ({
                '.kt',
                '.java',
                '.swift',
                '.m',
                '.mm',
                '.h',
                '.plist',
                '.entitlements',
                ...scriptExtensions,
                ...unsupportedSourceExtensions,
              }.contains(p.extension(name)) ||
              {
                'AndroidManifest.xml',
                'build.gradle',
                'build.gradle.kts',
                'package.json'
              }.contains(name))) {
        if (RegExp(r'\.(?:test|spec|d|min)\.[cm]?[jt]sx?$').hasMatch(name)) {
          continue;
        }
        files.add(relative);
      }
    }
  }

  visit(Directory(root), 0);
  return NativeFiles(files, projects, issues);
}
