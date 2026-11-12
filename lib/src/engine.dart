/// Runs the rules and produces an [AuditReport].
library;

import 'dart:io';

import 'package:path/path.dart' as p;

import 'baseline.dart';
import 'binary/apk.dart';
import 'binary/ipa.dart';
import 'binary/ios_static.dart';
import 'binary/ios_signature.dart';
import 'binary/signing.dart';
import 'config.dart';
import 'l10n/messages.g.dart';
import 'masvs.dart';
import 'model.dart';
import 'probe/probe_model.dart';
import 'project.dart';
import 'project/native_files.dart';
import 'rules/android_rules.dart';
import 'rules/platform_security_rules.dart';
import 'rules/platform_protection_rules.dart';
import 'rules/native_security_rules.dart';
import 'rules/native_source_rules.dart';
import 'rules/probe_rules.dart';
import 'rules/ios_rules.dart';
import 'rules/ipa_rules.dart';
import 'rules/registry.dart';
import 'rules/rule.dart';
import 'scoring.dart';
import 'security/evidence.dart';
import 'security/runtime_security.dart';
import 'rules/runtime_security_rules.dart';
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
    this.probe,
    this.iosStatic,
    this.securityEvidence = const [],
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

  /// The resilience probe's outcome when this run tried it: its report (also
  /// reflected in rules AEG-R01..R04) or why it was skipped.
  final ProbeOutcome? probe;

  /// Packaged iOS binary facts; these never replace runtime probe verdicts.
  final IosStaticAnalysis? iosStatic;
  final List<SecurityEvidence> securityEvidence;

  Iterable<RuleResult> get failed =>
      results.where((r) => r.status == RuleStatus.failed);
  Iterable<RuleResult> get passed =>
      results.where((r) => r.status == RuleStatus.passed);
  Iterable<RuleResult> get notApplicable =>
      results.where((r) => r.status == RuleStatus.notApplicable);

  /// Rules that listed review evidence without reaching a verdict.
  Iterable<RuleResult> get evidenceOnly =>
      results.where((r) => r.status == RuleStatus.evidenceOnly);

  Iterable<RuleResult> get incomplete =>
      results.where((r) => r.status == RuleStatus.incomplete || r.incomplete);

  bool get complete =>
      probe?.incomplete != true &&
      incomplete.isEmpty &&
      results.any((r) => r.counts);

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
  int countAtLeast(Severity s) =>
      newFailed.where((r) => r.severity >= s).length;
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
    this.encrypted,
    this.signatureVerified,
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

  factory BinaryInfo.fromIpa(IpaContext ipa, IosSignature signature) {
    final der = signature.certificate;
    final cert = der == null ? null : SigningCert(der, 'Apple code signing');
    return BinaryInfo(
      file: ipa.label,
      sizeBytes: ipa.archive.bytes.length,
      packageName: ipa.bundleId,
      versionName: ipa.version,
      versionCode: ipa.build,
      abis: ipa.machO.map((slice) => slice.architecture).toSet().toList(),
      isFlutter: ipa.isFlutter,
      encrypted: ipa.encrypted,
      signatureVerified: signature.valid,
      kind: 'IPA',
      certificates: [
        if (cert != null)
          CertificateInfo(cert.commonName, cert.scheme, cert.sha256Base64,
              cert.sha256Hex.replaceAll(':', '').toLowerCase()),
      ],
    );
  }

  final bool? encrypted;
  final bool? signatureVerified;

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
        if (kind == 'IPA') 'encrypted': encrypted,
        if (kind == 'IPA') 'signatureVerified': signatureVerified,
        'certificates': [for (final c in certificates) c.toJson()],
      };
}

class CertificateInfo {
  CertificateInfo(
      this.commonName, this.scheme, this.sha256Base64, this.sha256Hex);
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

/// Runs one rule; a crashing rule is reported as incomplete instead of
/// stopping the whole audit.
Future<RuleCheck> _safeCheck(
    Rule rule, Project project, ProfileSet profile) async {
  try {
    final androidConfig = androidRules.contains(rule) ||
        rule is AndroidLinksRule ||
        rule is AndroidPermissionStrengthRule;
    final iosConfig = iosRules.contains(rule) || rule is AtsForwardSecrecyRule;
    final platformConfig = rule is PlatformProtectionRule &&
        project.apk == null &&
        project.ipa == null;
    if (project.nativeOnly &&
        (androidConfig ||
            (iosConfig && project.ipa == null) ||
            platformConfig)) {
      final contexts = project.nativeContexts.where(
          (c) => platformConfig || (androidConfig ? c.hasAndroid : c.hasIos));
      final checks = <RuleCheck>[];
      for (final context in contexts) {
        context.offline = project.offline;
        context.gitignore
          ..clear()
          ..addAll(project.gitignore);
        context.probe = project.probe;
        if (iosConfig &&
            context.infoPlistData == null &&
            rule.meta.id != 'AEG-I03') {
          checks.add(RuleCheck.incompleteLocalized(
              En.nativeConfigUnavailable, Ar.nativeConfigUnavailable));
        } else {
          try {
            checks.add(await rule.check(context, profile));
          } catch (e) {
            checks.add(RuleCheck.incompleteLocalized(
                En.ruleError(error: e), Ar.ruleError(error: e)));
          }
        }
        project.securityEvidence.addAll(context.securityEvidence);
        context.securityEvidence.clear();
      }
      final findings = [for (final c in checks) ...c.findings];
      if (checks.any((c) => c.isIncomplete) ||
          project.nativeSourceIssues.isNotEmpty) {
        return RuleCheck.incompleteLocalized(
            {
              if (project.nativeSourceIssues.isNotEmpty) En.nativeSourceScope,
              ...checks
                  .where((c) => c.isIncomplete)
                  .map((c) => c.note)
                  .whereType<String>()
            }.join(' '),
            {
              if (project.nativeSourceIssues.isNotEmpty) Ar.nativeSourceScope,
              ...checks
                  .where((c) => c.isIncomplete)
                  .map((c) => c.noteAr ?? c.note)
                  .whereType<String>()
            }.join(' '),
            findings);
      }
      return checks.any((c) => c.applicable)
          ? RuleCheck(findings)
          : RuleCheck.notApplicable();
    }
    final check = await rule.check(project, profile);
    if (project.nativeSourceIssues.isNotEmpty &&
        (rule is NativeSecurityRule || rule is NativeSourceRule)) {
      return RuleCheck.incompleteLocalized(
          En.nativeSourceScope, Ar.nativeSourceScope, check.findings);
    }
    return check;
  } catch (e) {
    return RuleCheck.incompleteLocalized(
        En.ruleError(error: e), Ar.ruleError(error: e));
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
  String? ipaPath,
  Baseline? baseline,
  ProbeOutcome? probe,
  RuntimeSecurityResult? runtimeSecurity,
}) async {
  if (apkPath != null && ipaPath != null) {
    throw const FormatException(
        'Audit one artifact at a time with --apk or --ipa.');
  }
  final ipa = ipaPath == null ? null : IpaContext.load(ipaPath);
  IosSignature? signature;
  if (ipa != null) {
    if (Platform.isMacOS) {
      final staging = Directory.systemTemp.createTempSync('aegis-ipa-');
      try {
        final app = ipa.stage(staging);
        signature = await verifyIosSignature(app, staging);
      } finally {
        staging.deleteSync(recursive: true);
      }
    } else {
      signature = (
        valid: null,
        evidence: En.signatureMacOnly,
        evidenceAr: Ar.signatureMacOnly,
        certificate: null
      );
    }
  }
  final apk = apkPath == null ? null : ApkContext.load(apkPath);
  final hasPubspec = File(p.join(path, 'pubspec.yaml')).existsSync();
  final hasNative = !hasPubspec &&
      discoverNativeFiles(path, excluded: config?.isExcluded).recognized;
  final Project project;
  if (!hasPubspec && !hasNative && apk != null) {
    project = Project.binaryOnly(path, apk, config: config);
  } else if (!hasPubspec && !hasNative && ipa != null) {
    project = Project.ipaOnly(path, ipa, config: config);
  } else {
    project = Project.load(path, config: config)..apk = apk;
  }
  if (ipa != null) project.useIpa(ipa, signature!);
  project.offline = offline;
  project.probe = probe;
  project.runtimeSecurity = runtimeSecurity;
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
        if (project.hasSource && !project.nativeOnly) ...allRules,
        if (project.nativeOnly) ...[...androidRules, ...iosRules],
        ...extendedRules,
        if (runtimeSecurity != null) ...runtimeSecurityRules,
        if (project.apk != null) ...apkRules,
        if (ipa != null) ...[
          if (!project.hasSource) ...iosRules,
          ...ipaRules,
        ],
        // Only in a run that tried the probe (aegis run --mode apk|aab).
        if (project.apk != null && probe != null) ...probeRules,
        if (ipa != null && probe != null) ...iosProbeRules,
      ];
  // Binary rules are written for APKs; for a bundle they say "AAB".
  final bundle = project.apk?.isBundle ?? false;
  String bundleText(String s) => s.replaceAll('APK', 'AAB');
  RuleMeta metaOf(Rule rule) {
    final meta =
        rule is ProbeRule ? rule.reportMeta(project.probe?.report) : rule.meta;
    return bundle && meta.id.startsWith('AEG-B')
        ? meta.mapText(bundleText)
        : meta;
  }

  Finding findingOf(Finding f) => !bundle || !f.ruleId.startsWith('AEG-B')
      ? f
      : Finding(
          ruleId: f.ruleId,
          message: bundleText(f.message),
          messageAr: f.messageAr == null ? null : bundleText(f.messageAr!),
          file: f.file,
          line: f.line,
          snippet: f.snippet,
          snippetAr: f.snippetAr);

  for (final rule in ruleSet) {
    final meta = metaOf(rule);
    final severity =
        cfg.severityOverrides[meta.id] ?? meta.severityFor(profile);
    if (cfg.disabledRules.contains(meta.id)) {
      results.add(RuleResult(
          meta: meta, status: RuleStatus.disabled, severity: severity));
      continue;
    }
    if (!profile.includesAny(meta.profiles)) {
      results.add(RuleResult(
          meta: meta, status: RuleStatus.outOfProfile, severity: severity));
      continue;
    }
    final check = await _safeCheck(rule, project, profile);
    if (!check.applicable && check.findings.isEmpty) {
      results.add(RuleResult(
          meta: meta,
          status: check.isIncomplete
              ? RuleStatus.incomplete
              : check.isEvidenceOnly
                  ? RuleStatus.evidenceOnly
                  : RuleStatus.notApplicable,
          severity: severity,
          note: check.note,
          noteAr: check.noteAr));
      continue;
    }
    final kept = <Finding>[];
    var hidden = 0;
    for (final f in check.findings) {
      if (suppressed(f)) {
        hidden++;
      } else {
        kept.add(findingOf(f));
      }
    }
    results.add(RuleResult(
      meta: meta,
      status: kept.isNotEmpty
          ? RuleStatus.failed
          : check.isIncomplete
              ? RuleStatus.incomplete
              : RuleStatus.passed,
      incomplete: check.isIncomplete,
      note: check.note,
      noteAr: check.noteAr,
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
    binary: ipa != null
        ? BinaryInfo.fromIpa(ipa, signature!)
        : apk == null
            ? null
            : BinaryInfo.from(apk),
    scannedPackages: project.scannedPackages,
    baselinePath:
        baseline == null ? null : (baseline.path ?? defaultBaselineFile),
    baselineResolved: resolved,
    probe: probe,
    iosStatic: ipa?.staticAnalysis,
    securityEvidence: project.securityEvidence,
  );
}
