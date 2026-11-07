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
      baseline: doc['baseline']?.toString(),
      langSet: doc['lang'] != null,
      file: file,
    );
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
      );
}
