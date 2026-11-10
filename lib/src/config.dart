/// `aegis.yaml` configuration.
library;

import 'dart:io';

import 'package:path/path.dart' as p;
import 'package:yaml/yaml.dart';

import 'model.dart';
import 'util.dart';

class AegisConfig {
  AegisConfig({
    this.profile = ProfileSet.standard,
    this.lang = 'en',
    this.failOn,
    this.minScore,
    this.disabledRules = const {},
    this.exclude = const [],
    this.severityOverrides = const {},
    this.scanPackages = true,
    this.baseline,
    this.langSet = false,
    this.file,
    this.apk,
    this.aab,
    this.ipa,
    this.iosControlDevice,
    this.iosJailbreakDevice,
    this.iosResignedIpa,
    this.iosSimulator,
    this.iosSimulatorApp,
    this.iosSimulatorFlavor,
    this.iosSimulatorTarget,
    this.probeApk,
    this.probeCertSha256,
    this.trackerSignatures,
    this.runtimeSecurity = const {},
  });

  final ProfileSet profile;
  final String lang;

  /// Exit with code 1 when a finding at or above this severity exists.
  final Severity? failOn;

  /// Exit with code 1 when the score is below this value.
  final int? minScore;
  final Set<String> disabledRules;
  final List<String> exclude;
  final Map<String, Severity> severityOverrides;

  /// Also scan the Dart code of git and path dependencies.
  final bool scanPackages;

  /// Baseline file, relative to the project root. Defaults to
  /// `aegis-baseline.json` when that file exists.
  final String? baseline;

  /// Whether `lang:` was given in aegis.yaml (otherwise `aegis run` follows
  /// the system language).
  final bool langSet;

  /// The aegis.yaml this was read from, if any.
  final String? file;

  /// The release APK to audit with `aegis run --mode apk` and `aegis
  /// probe`, as written in aegis.yaml (relative to the project or absolute).
  /// Build paths change with flavors and versions, so the developer keeps it
  /// up to date; aegis does not search build/ for it.
  final String? apk;

  /// The release App Bundle, for `--mode aab`. Same rules as [apk].
  final String? aab;
  final String? ipa;
  final String? iosControlDevice;
  final String? iosJailbreakDevice;
  final String? iosResignedIpa;
  final String? iosSimulator;
  final String? iosSimulatorApp;
  final String? iosSimulatorFlavor;
  final String? iosSimulatorTarget;

  /// Companion APK for the AAB probe, relative to the project or absolute.
  final String? probeApk;

  /// Expected SHA-256 fingerprint of the companion APK's signing certificate.
  final String? probeCertSha256;
  final String? trackerSignatures;
  final Map<String, Object?> runtimeSecurity;

  /// An artifact path made absolute against [projectRoot], or null when unset.
  static String? resolve(String projectRoot, String? path) {
    if (path == null || path.trim().isEmpty) return null;
    final v = path.trim();
    return p.normalize(p.isAbsolute(v) ? v : p.join(projectRoot, v));
  }

  late final List<RegExp> _excludeRes = exclude.map(globToRegExp).toList();

  bool isExcluded(String relativePath) =>
      _excludeRes.any((r) => r.hasMatch(relativePath));

  static const fileName = 'aegis.yaml';

  /// Loads `aegis.yaml` from [projectRoot] if present.
  static AegisConfig load(String projectRoot) {
    final f = File(p.join(projectRoot, fileName));
    if (!f.existsSync()) return AegisConfig();
    return parse(f.readAsStringSync(), file: f.path);
  }

  static AegisConfig parse(String text, {String? file}) {
    final doc = _loadYaml(text);
    if (doc == null) return AegisConfig(file: file);
    if (doc is! Map) throw const FormatException('$fileName must be a map.');

    ProfileSet profile = ProfileSet.standard;
    if (doc['profile'] != null) {
      final parsed = ProfileSet.tryParse(doc['profile'].toString());
      if (parsed == null) {
        throw FormatException(
            'Unknown profile "${doc['profile']}". Use l1, l2, l1+r, l2+r or a preset like banking.');
      }
      profile = parsed;
    }

    final disabled = <String>{};
    final overrides = <String, Severity>{};
    final rules = doc['rules'];
    if (rules is Map) {
      rules.forEach((k, v) {
        final id = k.toString().toUpperCase();
        if (v == false || v.toString() == 'off') {
          disabled.add(id);
        } else {
          final s = Severity.tryParse(v.toString());
          if (s != null) overrides[id] = s;
        }
      });
    }

    final exclude = <String>[];
    final ex = doc['exclude'];
    if (ex is List) exclude.addAll(ex.map((e) => e.toString()));

    final lang = (doc['lang'] ?? 'en').toString().toLowerCase();

    return AegisConfig(
      profile: profile,
      lang: lang == 'ar' ? 'ar' : 'en',
      failOn: Severity.tryParse(doc['fail_on']?.toString()),
      minScore: int.tryParse(doc['min_score']?.toString() ?? ''),
      disabledRules: disabled,
      exclude: exclude,
      severityOverrides: overrides,
      scanPackages: doc['scan_packages'] != false,
      baseline: _path(doc['baseline']),
      langSet: doc['lang'] != null,
      file: file,
      apk: _path(doc['apk']),
      aab: _path(doc['aab']),
      ipa: _path(doc['ipa']),
      iosControlDevice: _path(doc['ios_control_device']),
      iosJailbreakDevice: _path(doc['ios_jailbreak_device']),
      iosResignedIpa: _path(doc['ios_resigned_ipa']),
      iosSimulator: _path(doc['ios_simulator']),
      iosSimulatorApp: _path(doc['ios_simulator_app']),
      iosSimulatorFlavor: _path(doc['ios_simulator_flavor']),
      iosSimulatorTarget: _path(doc['ios_simulator_target']),
      probeApk: _path(doc['probe_apk']),
      probeCertSha256: _path(doc['probe_cert_sha256']),
      trackerSignatures: _path(doc['tracker_signatures']),
      runtimeSecurity: _runtime(doc['runtime_security']),
    );
  }

  static Map<String, Object?> _runtime(Object? value) {
    if (value == null) return const {};
    if (value is! Map) throw const FormatException('runtime_security must be a map');
    return value.map((k, v) => MapEntry(k.toString(), v));
  }

  static String? _path(Object? v) {
    final s = v?.toString().trim();
    // init includes editable placeholders for optional paths, IDs and flavors.
    // They must not select a device or become a literal filesystem path.
    return s == null || s.isEmpty || RegExp(r'^<[a-z][a-z0-9-]*>$').hasMatch(s)
        ? null
        : s;
  }

  static Object? _loadYaml(String text) {
    try {
      return loadYaml(text);
    } on YamlException catch (e) {
      throw FormatException('Invalid $fileName: ${e.message}');
    }
  }

  AegisConfig copyWith({
    ProfileSet? profile,
    String? lang,
    Severity? failOn,
    int? minScore,
  }) =>
      AegisConfig(
        profile: profile ?? this.profile,
        lang: lang ?? this.lang,
        failOn: failOn ?? this.failOn,
        minScore: minScore ?? this.minScore,
        disabledRules: disabledRules,
        exclude: exclude,
        severityOverrides: severityOverrides,
        scanPackages: scanPackages,
        baseline: baseline,
        langSet: lang != null || langSet,
        file: file,
        apk: apk,
        aab: aab,
        ipa: ipa,
        iosControlDevice: iosControlDevice,
        iosJailbreakDevice: iosJailbreakDevice,
        iosResignedIpa: iosResignedIpa,
        iosSimulator: iosSimulator,
        iosSimulatorApp: iosSimulatorApp,
        iosSimulatorFlavor: iosSimulatorFlavor,
        iosSimulatorTarget: iosSimulatorTarget,
        probeApk: probeApk,
        probeCertSha256: probeCertSha256,
        trackerSignatures: trackerSignatures,
        runtimeSecurity: runtimeSecurity,
      );
}
