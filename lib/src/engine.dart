/// Runs the rules and produces an [AuditReport].
library;

import 'dart:io';

import 'package:path/path.dart' as p;

import 'baseline.dart';
import 'binary/apk.dart';
import 'config.dart';
import 'masvs.dart';
import 'model.dart';
import 'project.dart';
import 'rules/registry.dart';
import 'rules/rule.dart';
import 'scoring.dart';
import 'version.dart';

class AuditReport {
  AuditReport({
    required this.projectName,
    required this.root,
    required this.profile,
    required this.results,
    required this.score,
    required this.coverage,
    required this.manual,
    required this.generatedAt,
    this.binary,
    this.scannedPackages = const [],
    this.baselinePath,
    this.baselineResolved = const [],
  });

  final String projectName;
  final String root;
  final ProfileSet profile;
  final List<RuleResult> results;
  final Score score;
  final Coverage coverage;
  final List<ManualCheck> manual;
  final DateTime generatedAt;
  final String version = aegisVersion;

  /// Facts about the audited APK, when --apk was used.
  final BinaryInfo? binary;

  /// Git and path dependencies whose Dart code was scanned with the app.
  final List<String> scannedPackages;

  /// The baseline used, if any. Findings it lists are marked
  /// [Finding.baselined] and do not trigger --fail-on.
  final String? baselinePath;

  /// Baseline entries that no longer match a finding: fixed since the
  /// baseline was written.
  final List<BaselineEntry> baselineResolved;

  bool get usesBaseline => baselinePath != null;

  Iterable<RuleResult> get failed =>
      results.where((r) => r.status == RuleStatus.failed);
  Iterable<RuleResult> get passed =>
      results.where((r) => r.status == RuleStatus.passed);
  Iterable<RuleResult> get notApplicable =>
      results.where((r) => r.status == RuleStatus.notApplicable);

  int get suppressed => results.fold(0, (s, r) => s + r.suppressed);

  /// The most severe failing severity, if any.
  Severity? get worst {
    Severity? w;
    for (final r in failed) {
      if (w == null || r.severity > w) w = r.severity;
    }
    return w;
  }

  /// Failed rules with at least one finding outside the baseline.
  Iterable<RuleResult> get newFailed => failed.where((r) => r.hasNew);

  int get newFindingCount => failed.fold(0, (s, r) => s + r.newFindings.length);
  int get knownFindingCount =>
      failed.fold(0, (s, r) => s + r.knownFindings.length);
  int get resolvedCount => baselineResolved.fold(0, (s, e) => s + e.count);

  /// Failed rules at or above [s] with new findings. Rules whose findings are
  /// all in the baseline are not counted, so --fail-on only reacts to new
  /// problems.
  int countAtLeast(Severity s) => newFailed.where((r) => r.severity >= s).length;
}

/// Facts read from the APK, shown at the top of reports.
class BinaryInfo {
  BinaryInfo({
    required this.file,
    required this.sizeBytes,
    this.packageName,
    this.versionName,
    this.versionCode,
    this.minSdk,
    this.targetSdk,
    this.abis = const [],
    this.isFlutter = false,
    this.certificates = const [],
    this.kind = 'APK',
  });

  factory BinaryInfo.from(ApkContext apk) => BinaryInfo(
        file: apk.fileName,
        sizeBytes: apk.sizeBytes,
        packageName: apk.packageName,
        versionName: apk.versionName,
        versionCode: apk.versionCode,
        minSdk: apk.minSdk,
        targetSdk: apk.targetSdk,
        abis: apk.abis,
        isFlutter: apk.isFlutter,
        kind: apk.kind,
        certificates: [
          for (final c in apk.certificates)
            CertificateInfo(c.commonName, c.scheme, c.sha256Base64, c.sha256Hex)
        ],
      );

  final String file;
  final int sizeBytes;
  final String? packageName;
  final String? versionName;
  final String? versionCode;
  final int? minSdk;
  final int? targetSdk;
  final List<String> abis;
  final bool isFlutter;
  final List<CertificateInfo> certificates;

  /// `APK` or `AAB`. An AAB's certificate is the upload key.
  final String kind;

  Map<String, Object?> toJson() => {
        'file': file,
        'kind': kind,
        'sizeBytes': sizeBytes,
        'packageName': packageName,
        'versionName': versionName,
        'versionCode': versionCode,
        'minSdk': minSdk,
        'targetSdk': targetSdk,
        'abis': abis,
        'flutter': isFlutter,
        'certificates': [for (final c in certificates) c.toJson()],
      };
}

class CertificateInfo {
  CertificateInfo(this.commonName, this.scheme, this.sha256Base64, this.sha256Hex);
  final String? commonName;
  final String scheme;

  /// The value to paste into freeRASP signingCertHashes.
  final String sha256Base64;
  final String sha256Hex;

  Map<String, Object?> toJson() => {
        'commonName': commonName,
        'scheme': scheme,
        'sha256Base64': sha256Base64,
        'sha256Hex': sha256Hex,
      };
}

/// Runs one rule; a crashing rule is reported as not applicable instead of
/// stopping the whole audit.
Future<RuleCheck> _safeCheck(Rule rule, Project project, ProfileSet profile) async {
  try {
    return await rule.check(project, profile);
  } catch (e) {
    return RuleCheck.notApplicable('Rule error: $e');
  }
}

/// Audits the Flutter project at [path].
///
/// With [apkPath], the release APK is audited too. When [path] has no
/// pubspec.yaml and an APK is given, only the APK is audited.
Future<AuditReport> runAudit(
  String path, {
  AegisConfig? config,
  bool offline = false,
  List<Rule>? rules,
  String? apkPath,
  Baseline? baseline,
}) async {
  final apk = apkPath == null ? null : ApkContext.load(apkPath);
  final hasPubspec = File(p.join(path, 'pubspec.yaml')).existsSync();
  final Project project;
  if (!hasPubspec && apk != null) {
    project = Project.binaryOnly(path, apk, config: config);
  } else {
    project = Project.load(path, config: config)..apk = apk;
  }
  project.offline = offline;
  final cfg = project.config;
  final profile = cfg.profile;
  final results = <RuleResult>[];
  final textCache = <String, List<String>>{};

  bool suppressed(Finding f) {
    if (f.file == null) return false;
    if (cfg.isExcluded(f.file!)) return true;
    if (f.line == null) return false;
    for (final d in project.dartFiles) {
      if (d.path == f.file) return d.isSuppressed(f.ruleId, f.line!);
    }
    final lines = textCache.putIfAbsent(f.file!, () {
      final file = File(p.join(project.root, f.file!));
      if (!file.existsSync()) return const [];
      try {
        return file.readAsLinesSync();
      } catch (_) {
        return const [];
      }
    });
    bool hit(int line) {
      if (line < 1 || line > lines.length) return false;
      final t = lines[line - 1];
      return t.contains('aegis:ignore') && t.toUpperCase().contains(f.ruleId);
    }

    return hit(f.line!) || hit(f.line! - 1);
  }

  final ruleSet = rules ??
      [
        if (project.hasSource) ...allRules,
        if (project.apk != null) ...apkRules,
      ];
  for (final rule in ruleSet) {
    final meta = rule.meta;
    final severity = cfg.severityOverrides[meta.id] ?? meta.severityFor(profile);
    if (cfg.disabledRules.contains(meta.id)) {
      results.add(RuleResult(meta: meta, status: RuleStatus.disabled, severity: severity));
      continue;
    }
    if (!profile.includesAny(meta.profiles)) {
      results.add(RuleResult(meta: meta, status: RuleStatus.outOfProfile, severity: severity));
      continue;
    }
    final check = await _safeCheck(rule, project, profile);
    if (!check.applicable) {
      results.add(RuleResult(
          meta: meta,
          status: RuleStatus.notApplicable,
          severity: severity,
          note: check.note));
      continue;
    }
    final kept = <Finding>[];
    var hidden = 0;
    for (final f in check.findings) {
      if (suppressed(f)) {
        hidden++;
      } else {
        kept.add(f);
      }
    }
    results.add(RuleResult(
      meta: meta,
      status: kept.isEmpty ? RuleStatus.passed : RuleStatus.failed,
      severity: severity,
      findings: kept,
      suppressed: hidden,
    ));
  }

  final resolved = baseline?.apply(results) ?? const <BaselineEntry>[];

  // Most severe first, then by id.
  results.sort((a, b) {
    final s = b.severity.index.compareTo(a.severity.index);
    return s != 0 ? s : a.meta.id.compareTo(b.meta.id);
  });

  return AuditReport(
    projectName: project.name,
    root: project.root,
    profile: profile,
    results: results,
    score: computeScore(results),
    coverage: computeCoverage(results, profile),
    manual: manualChecks
        .where((m) => profile.includesAny(m.profiles))
        // The APK scan verifies obfuscation directly (AEG-B07).
        .where((m) => !(apk != null && m.id == 'AEG-M05'))
        .toList(),
    generatedAt: DateTime.now(),
    binary: apk == null ? null : BinaryInfo.from(apk),
    scannedPackages: project.scannedPackages,
    baselinePath: baseline == null ? null : (baseline.path ?? defaultBaselineFile),
    baselineResolved: resolved,
  );
}
