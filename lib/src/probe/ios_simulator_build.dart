/// Builds a separate Flutter Simulator artifact, then verifies its identity.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:path/path.dart' as p;
import 'package:crypto/crypto.dart';
import 'package:yaml/yaml.dart';

import '../binary/ipa.dart';
import '../plist.dart';

typedef SimulatorBuildCommand = Future<int> Function(
    String executable,
    List<String> arguments,
    String project,
    File output,
    void Function(String)? log);

const _incompleteBuildMarker = '.aegis-simulator-build-incomplete';

class IosSimulatorBuilder {
  IosSimulatorBuilder({SimulatorBuildCommand? command})
      : _command = command ?? _build;

  final SimulatorBuildCommand _command;

  Future<String> ensure(IpaContext ipa,
      {String? project,
      String? app,
      String? flavor,
      String? target,
      void Function(String)? log}) async {
    String? matching(String? path) {
      if (path == null) return null;
      // Flutter may leave valid Info.plist/Mach-O files in a partially copied
      // bundle when rsync fails (for example, on a full disk).
      if (File(p.join(p.dirname(p.normalize(path)), _incompleteBuildMarker))
          .existsSync()) {
        return null;
      }
      try {
        return matchingSimulatorApp(ipa, path);
      } on FormatException {
        return null;
      } on FileSystemException {
        return null;
      }
    }

    final existing = matching(app);
    if (existing != null) return existing;
    if (project == null ||
        !File(p.join(project, 'pubspec.yaml')).existsSync() ||
        !Directory(p.join(project, 'ios')).existsSync()) {
      throw const FormatException(
          'Automatic Simulator build needs the Flutter project source (pubspec.yaml and ios/). '
          'Run aegis run <project> --mode ipa, or supply an existing matching ios_simulator_app.');
    }
    project = p.absolute(project);
    final pubspec =
        loadYaml(File(p.join(project, 'pubspec.yaml')).readAsStringSync());
    if (pubspec is! Map ||
        pubspec['dependencies'] is! Map ||
        (pubspec['dependencies'] as Map)['flutter'] == null) {
      throw const FormatException(
          'Automatic Simulator build supports Flutter projects. Supply ios_simulator_app for other projects.');
    }
    final generated = _generatedSettings(project);
    final buildDir = generated['FLUTTER_BUILD_DIR'] ?? 'build';
    final outputDir = p.join(project, buildDir, 'ios', 'iphonesimulator');
    // Flutter may use a product name different from its executable name.
    final candidates = <String>{
      p.join(outputDir, '${ipa.executable}.app'),
      if (Directory(outputDir).existsSync())
        ...Directory(outputDir)
            .listSync()
            .whereType<Directory>()
            .where((dir) => dir.path.endsWith('.app'))
            .map((dir) => dir.path),
    };
    final explicitInputs = flavor != null || target != null;
    if (!explicitInputs) {
      for (final candidate in candidates) {
        final found = matching(candidate);
        if (found != null) return found;
      }
    }
    if (ipa.version == null || ipa.build == null) {
      throw const FormatException(
          'The IPA must declare a version and build number for an automatic Simulator build.');
    }
    final flutterSection = pubspec['flutter'];
    final defines = _defines(generated['DART_DEFINES']);
    final previousFlavor = defines
        .where((value) => value.startsWith('FLUTTER_APP_FLAVOR='))
        .map((value) => value.substring('FLUTTER_APP_FLAVOR='.length))
        .where((value) => value.isNotEmpty)
        .toList();
    final selectedFlavor = flavor ??
        generated['FLAVOR'] ??
        (previousFlavor.length == 1 ? previousFlavor.single : null) ??
        (flutterSection is Map
            ? flutterSection['default-flavor']?.toString()
            : null) ??
        _archiveFlavor(project, ipa);
    final selectedTarget =
        target ?? generated['FLUTTER_TARGET'] ?? 'lib/main.dart';
    final args = <String>[
      'build', 'ios', '--simulator', '--debug',
      '--build-name=${ipa.version}', '--build-number=${ipa.build}',
      if (selectedFlavor != null) '--flavor=$selectedFlavor',
      '--target=$selectedTarget',
      // Preserve the project's last Flutter build inputs, including app defines.
      ...defines
          .where((value) => !_flutterDefines.contains(value.split('=').first))
          .map((value) => '--dart-define=$value'),
    ];
    final inputs = sha256.convert(utf8.encode(jsonEncode(args))).toString();
    final receipt = File(
        p.join(project, '.dart_tool', 'aegis', 'ios-simulator-inputs.json'));
    for (final candidate in candidates) {
      final found = matching(candidate);
      if (found != null && await _matchesInputs(receipt, found, inputs)) {
        return found;
      }
    }
    final output =
        File(p.join(project, '.dart_tool', 'aegis', 'ios-simulator-build.log'));
    output.parent.createSync(recursive: true);
    log?.call('iOS: building Simulator app ${ipa.version}+${ipa.build}'
        '${selectedFlavor == null ? '' : ' (flavor $selectedFlavor)'}… Log: ${output.path}');
    // A failed build must not leave a receipt authorizing reuse of its output.
    if (receipt.existsSync()) receipt.deleteSync();
    final incomplete = File(p.join(outputDir, _incompleteBuildMarker));
    incomplete.parent.createSync(recursive: true);
    incomplete
        .writeAsStringSync('Simulator build has not completed verification.\n');
    final code = await _command(
        _flutter(project, generated), args, project, output, log);
    if (code != 0) {
      throw StateError(
          'Simulator build failed (exit $code). See ${output.path}. '
          'Check Flutter/Xcode dependencies and ios_simulator_flavor / ios_simulator_target in aegis.yaml.');
    }
    // Re-list after building; never accept an exit code as proof of a good app.
    final built = Directory(outputDir);
    final products = built.existsSync()
        ? built
            .listSync()
            .whereType<Directory>()
            .where((dir) => dir.path.endsWith('.app'))
        : <Directory>[];
    for (final product in products) {
      // The marker intentionally rejects reuse until a successful build has
      // produced an identity-verified artifact and its receipt is saved.
      final String found;
      try {
        found = matchingSimulatorApp(ipa, product.path);
      } on FormatException {
        continue;
      } on FileSystemException {
        continue;
      }
      receipt.writeAsStringSync(jsonEncode({
        'app': p.normalize(p.absolute(found)),
        'inputs': inputs,
        'artifact': await _artifactDigest(found)
      }));
      incomplete.deleteSync();
      log?.call('iOS: Simulator build verified against the IPA.');
      return found;
    }
    throw StateError(
        'Flutter finished but no matching Simulator app was produced in $outputDir. '
        'Expected ${ipa.bundleId} (${ipa.executable}), version ${ipa.version} build ${ipa.build}. '
        'Check ios_simulator_flavor / ios_simulator_target. See ${output.path}.');
  }
}

// Only Aegis-verified automatic builds may satisfy explicit build overrides.
// The receipt stores a digest, not potentially sensitive --dart-define values.
Future<bool> _matchesInputs(File receipt, String app, String inputs) async {
  try {
    final data = jsonDecode(receipt.readAsStringSync());
    return data is Map &&
        data['app'] == p.normalize(p.absolute(app)) &&
        data['inputs'] == inputs &&
        data['artifact'] is String &&
        data['artifact'] == await _artifactDigest(app);
  } on FileSystemException {
    return false;
  } on FormatException {
    return false;
  }
}

// Bind the receipt to the complete product, including Flutter assets and
// frameworks. Another build can replace those while retaining the same Runner
// executable and Info.plist identity. Stream file hashes to bound memory use.
Future<String?> _artifactDigest(String app) async {
  final entries = Directory(app).listSync(recursive: true, followLinks: false)
    ..sort((a, b) => a.path.compareTo(b.path));
  final records = <List<String>>[];
  for (final entry in entries) {
    final relative = p.relative(entry.path, from: app);
    if (entry is File) {
      records.add([
        'file',
        relative,
        (await sha256.bind(entry.openRead()).first).toString()
      ]);
    } else if (entry is Directory) {
      records.add(['directory', relative]);
    } else {
      // Do not authorize reuse when external symlink targets or special files
      // could change without changing the recorded product tree.
      return null;
    }
  }
  return sha256.convert(utf8.encode(jsonEncode(records))).toString();
}

Map<String, String> _generatedSettings(String project) {
  final file = File(p.join(project, 'ios', 'Flutter', 'Generated.xcconfig'));
  if (!file.existsSync()) return {};
  return {
    for (final line in file.readAsLinesSync())
      if (line.contains('=') && !line.trimLeft().startsWith('//'))
        line.substring(0, line.indexOf('=')).trim():
            line.substring(line.indexOf('=') + 1).trim(),
  };
}

String _flutter(String project, Map<String, String> settings) {
  final roots = [
    p.join(project, '.fvm', 'flutter_sdk'),
    settings['FLUTTER_ROOT'],
    Platform.environment['FLUTTER_ROOT'],
  ];
  for (final root in roots) {
    if (root == null) continue;
    final executable = p.join(root, 'bin', 'flutter');
    if (File(executable).existsSync()) return executable;
  }
  return 'flutter';
}

String? _archiveFlavor(String project, IpaContext ipa) {
  final dir = Directory(p.join(project, 'build', 'ios', 'archive'));
  if (!dir.existsSync()) return null;
  final schemes = <String>{};
  for (final archive in dir.listSync().whereType<Directory>()) {
    if (!archive.path.endsWith('.xcarchive')) continue;
    final file = File(p.join(archive.path, 'Info.plist'));
    if (!file.existsSync()) continue;
    final info = decodeApplePlist(file.readAsBytesSync());
    final props = info?['ApplicationProperties'];
    if (props is Map &&
        props['CFBundleIdentifier'] == ipa.bundleId &&
        props['CFBundleShortVersionString']?.toString() == ipa.version &&
        props['CFBundleVersion']?.toString() == ipa.build &&
        info?['SchemeName'] is String) {
      schemes.add(info!['SchemeName'] as String);
    }
  }
  if (schemes.length != 1 || schemes.single.toLowerCase() == 'runner') {
    return null;
  }
  return schemes.single;
}

// Flutter writes these into Generated.xcconfig itself and rejects them as CLI
// input on the next build. Let the selected SDK regenerate its own metadata.
const _flutterDefines = {
  'FLUTTER_APP_FLAVOR',
  'FLUTTER_VERSION',
  'FLUTTER_CHANNEL',
  'FLUTTER_GIT_URL',
  'FLUTTER_FRAMEWORK_REVISION',
  'FLUTTER_ENGINE_REVISION',
  'FLUTTER_DART_VERSION',
  'FLUTTER_ENABLED_FEATURE_FLAGS',
};

List<String> _defines(String? encoded) {
  if (encoded == null || encoded.isEmpty) return [];
  try {
    return encoded
        .split(',')
        .map((v) => utf8.decode(base64.decode(v)))
        .toList();
  } on FormatException {
    throw const FormatException(
        'Invalid DART_DEFINES in ios/Flutter/Generated.xcconfig. Rebuild the Flutter project configuration.');
  }
}

Future<int> _build(String executable, List<String> args, String project,
    File output, void Function(String)? log) async {
  final sink = output.openWrite();
  Timer? progress;
  try {
    final process =
        await Process.start(executable, args, workingDirectory: project);
    progress = Timer.periodic(const Duration(seconds: 30), (_) {
      log?.call('iOS: Simulator build still running… Log: ${output.path}');
    });
    final streams = Future.wait([
      process.stdout.forEach(sink.add),
      process.stderr.forEach(sink.add),
    ]);
    final code = await process.exitCode;
    await streams;
    return code;
  } on ProcessException catch (e) {
    throw StateError('Could not start Flutter ($executable): ${e.message}. '
        'Install Flutter or configure the project SDK.');
  } finally {
    progress?.cancel();
    await sink.close();
  }
}

String matchingSimulatorApp(IpaContext ipa, String app) {
  final full = p.absolute(app);
  final infoFile = File(p.join(full, 'Info.plist'));
  if (!infoFile.existsSync()) {
    throw FormatException(
        'The Simulator app at $full is missing Info.plist. Build the app for iOS Simulator and set ios_simulator_app in aegis.yaml or pass --ios-simulator-app.');
  }
  final info = decodeApplePlist(infoFile.readAsBytesSync());
  if (info?['CFBundleIdentifier'] != ipa.bundleId ||
      info?['CFBundleExecutable'] != ipa.executable ||
      info?['CFBundleVersion']?.toString() != ipa.build ||
      info?['CFBundleShortVersionString']?.toString() != ipa.version) {
    throw FormatException(
        'The Simulator app must match the IPA bundle ID, executable and version. '
        'Expected ${ipa.bundleId} (${ipa.executable}), version ${ipa.version} build ${ipa.build}.');
  }
  final slices =
      inspectMachO(File(p.join(full, ipa.executable)).readAsBytesSync());
  if (slices.isEmpty || slices.any((s) => s.platform != 7)) {
    throw const FormatException('Provide an app built for iOS Simulator.');
  }
  return full;
}
