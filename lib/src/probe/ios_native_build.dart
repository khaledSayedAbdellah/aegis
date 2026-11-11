part of 'ios_simulator_build.dart';

Future<String> _ensureNativeSimulator(
    IpaContext ipa, String root, SimulatorBuildCommand command,
    {String? xcodeProject,
    String? scheme,
    String? configuration,
    void Function(String)? log}) async {
  if (ipa.version == null || ipa.build == null) {
    throw const FormatException('The IPA needs a version and build number.');
  }
  final cache = p.join(root, '.dart_tool', 'aegis', 'native-ios');
  Directory(cache).createSync(recursive: true);
  final config = configuration ?? 'Release';
  final containers = <String>[];
  if (xcodeProject != null) {
    final selected = p.normalize(
        p.isAbsolute(xcodeProject) ? xcodeProject : p.join(root, xcodeProject));
    if (!Directory(selected).existsSync() ||
        !{'.xcodeproj', '.xcworkspace'}.contains(p.extension(selected))) {
      throw const FormatException(
          'ios_xcode_project must name an existing .xcodeproj or .xcworkspace.');
    }
    containers.add(selected);
  } else {
    final found = discoverNativeFiles(root);
    if (found.issues.isNotEmpty) {
      throw const FormatException(
          'Xcode project discovery was incomplete. Set ios_xcode_project.');
    }
    final workspaces =
        found.projects.where((f) => f.endsWith('.xcworkspace')).toList();
    containers.addAll((workspaces.isEmpty ? found.projects : workspaces)
        .map((f) => p.join(root, f)));
  }
  if (containers.isEmpty || containers.length > 8) {
    throw const FormatException(
        'No unique Xcode project search scope. Set ios_xcode_project to the app .xcodeproj or .xcworkspace, or supply an existing matching ios_simulator_app.');
  }
  List<String> containerArgs(String path) =>
      [path.endsWith('.xcworkspace') ? '-workspace' : '-project', path];
  var queryIndex = 0;
  Future<Object?> query(List<String> args) async {
    final file = File(p.join(cache, 'query-${queryIndex++}.log'));
    final code =
        await command('xcodebuild', [...args, '-json'], root, file, log);
    if (code != 0 ||
        !file.existsSync() ||
        file.lengthSync() > 8 * 1024 * 1024) {
      throw StateError(
          'Xcode project query failed (exit $code). See ${file.path}.');
    }
    final text = file.readAsStringSync();
    // Xcode occasionally prints diagnostics before its JSON payload.
    for (var i = 0; i < text.length; i++) {
      if (text[i] != '[' && text[i] != '{') continue;
      try {
        return jsonDecode(text.substring(i));
      } on FormatException {/* next */}
    }
    throw FormatException(
        'Xcode returned no valid project JSON. See ${file.path}.');
  }

  final choices = <({
    String container,
    String scheme,
    String product,
    List<String> args
  })>[];
  final failures = <String>[];
  for (final container in containers) {
    List<String> schemes;
    if (scheme != null) {
      schemes = [scheme];
    } else {
      final listing = await query([...containerArgs(container), '-list']);
      final info =
          listing is Map ? listing['workspace'] ?? listing['project'] : null;
      final values = info is Map ? info['schemes'] : null;
      if (values is! List || values.length > 64) {
        throw const FormatException(
            'Xcode scheme discovery is unavailable or too broad. Set ios_xcode_scheme.');
      }
      schemes = values.whereType<String>().toList();
    }
    for (final candidate in schemes) {
      final args = [
        ...containerArgs(container),
        '-scheme',
        candidate,
        '-configuration',
        config,
        '-sdk',
        'iphonesimulator',
        '-destination',
        'generic/platform=iOS Simulator',
        '-derivedDataPath',
        p.join(cache, 'DerivedData'),
        'ARCHS=${Abi.current() == Abi.macosArm64 ? 'arm64' : 'x86_64'}',
        'ONLY_ACTIVE_ARCH=YES',
        'CODE_SIGN_IDENTITY=-',
        'CODE_SIGNING_ALLOWED=YES',
        'MARKETING_VERSION=${ipa.version}',
        'CURRENT_PROJECT_VERSION=${ipa.build}',
      ];
      final Object? settings;
      try {
        settings = await query([...args, '-showBuildSettings']);
      } catch (e) {
        failures.add('$candidate: $e');
        continue;
      }
      if (settings is! List) {
        failures.add('$candidate: invalid build settings');
        continue;
      }
      for (final row in settings.whereType<Map>()) {
        final s = row['buildSettings'];
        if (s is! Map ||
            s['PRODUCT_BUNDLE_IDENTIFIER'] != ipa.bundleId ||
            s['WRAPPER_EXTENSION'] != 'app' ||
            s['EXECUTABLE_NAME'] != ipa.executable ||
            s['PLATFORM_NAME'] != 'iphonesimulator') {
          continue;
        }
        final directory = s['TARGET_BUILD_DIR'], name = s['FULL_PRODUCT_NAME'];
        if (directory is! String ||
            name is! String ||
            p.basename(name) != name) {
          continue;
        }
        final product = p.normalize(p.join(directory, name));
        // Never adopt or modify products outside our own DerivedData directory.
        if (!p.isWithin(p.join(cache, 'DerivedData'), product)) continue;
        choices.add((
          container: container,
          scheme: candidate,
          product: product,
          args: args
        ));
      }
    }
  }
  if (failures.isNotEmpty) {
    throw StateError(
        'Could not verify all candidate schemes; set ios_xcode_project / ios_xcode_scheme. ${failures.join('\n')}');
  }
  if (choices.length != 1) {
    throw FormatException(
        'Expected one Simulator app matching ${ipa.bundleId} (${ipa.executable}); found ${choices.length}. Set ios_xcode_project / ios_xcode_scheme / ios_xcode_configuration.');
  }
  final selected = choices.single;
  final receipt = File(p.join(cache, 'inputs.json'));
  final marker =
      File(p.join(p.dirname(selected.product), _incompleteBuildMarker));
  final inputs =
      sha256.convert(utf8.encode(jsonEncode(selected.args))).toString();
  if (!marker.existsSync()) {
    try {
      final app = matchingSimulatorApp(ipa, selected.product);
      if (await _matchesInputs(receipt, app, inputs)) return app;
    } on FormatException {
      /* Build missing or outdated output. */
    } on FileSystemException {/* Build missing output. */}
  }
  if (receipt.existsSync()) receipt.deleteSync();
  marker.parent.createSync(recursive: true);
  marker.writeAsStringSync(
      'Native Simulator build has not completed verification.\n');
  final output = File(p.join(cache, 'build.log'));
  log?.call(
      'iOS: building native Simulator app (${selected.scheme}, $config)… Log: ${output.path}');
  final code = await command(
      'xcodebuild', [...selected.args, 'build'], root, output, log);
  if (code != 0) {
    throw StateError(
        'Native Simulator build failed (exit $code). See ${output.path}.');
  }
  final app = matchingSimulatorApp(ipa, selected.product);
  receipt.writeAsStringSync(jsonEncode(
      {'app': app, 'inputs': inputs, 'artifact': await _artifactDigest(app)}));
  marker.deleteSync();
  log?.call('iOS: native Simulator build verified against the IPA.');
  return app;
}
