/// Rules about third-party packages.
library;

import '../l10n/messages.g.dart';

import 'dart:convert';
import 'dart:io';

import 'package:path/path.dart' as p;

import '../model.dart';
import '../project.dart';
import '../project/native_dependencies.dart';
import '../project/package_roots.dart';
import '../security/evidence.dart';
import 'rule.dart';

const _all = {MasProfile.l1, MasProfile.l2, MasProfile.r};

class VulnerableDependencyRule extends Rule {
  const VulnerableDependencyRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-C01',
        title: Bilingual(En.dependencyRulesDependencyWithKnownVulnerabilities,
            Ar.dependencyRulesDependencyWithKnownVulnerabilities),
        description: Bilingual(
            En.dependencyRulesALockedPackageVersionHasAPublishedAdvisory,
            Ar.dependencyRulesALockedPackageVersionHasAPublishedAdvisory),
        fix: Bilingual(En.dependencyRulesUpgradeThePackageToAFixedVersionDart,
            Ar.dependencyRulesUpgradeThePackageToAFixedVersionDart),
        severity: Severity.high,
        masvs: ['MASVS-CODE-3'],
        maswe: ['MASWE-0044'],
        cwe: 'CWE-1395',
        profiles: _all,
      );

  @override
  Future<RuleCheck> check(Project project, ProfileSet profile) async {
    if (project.offline) {
      return RuleCheck.notApplicable('Skipped (--offline)');
    }
    final lockIssue = project.lockIssue;
    final pub = lockIssue != null
        ? const <LockedPackage>[]
        : project.locked.values
            .where((p) => p.source == 'hosted' && p.version.isNotEmpty)
            .toList();
    final native = await _nativeDependencies(project);
    if (pub.isEmpty && native.isEmpty) {
      if (lockIssue != null) {
        return RuleCheck.incompleteLocalized(lockIssue, project.lockIssueAr);
      }
      return RuleCheck.notApplicable('No locked hosted dependencies');
    }
    // (ecosystem, name, version, file); Pub first, as before.
    final queries = [
      for (final p in pub) ('Pub', p.name, p.version, 'pubspec.lock'),
      for (final d in native) (d.ecosystem, d.name, d.version, d.file),
    ];

    final client = HttpClient()
      ..connectionTimeout = const Duration(seconds: 10);
    final out = <Finding>[];
    try {
      for (var i = 0; i < queries.length; i += 500) {
        final batch =
            queries.sublist(i, (i + 500).clamp(0, queries.length).toInt());
        final body = jsonEncode({
          'queries': [
            for (final q in batch)
              {
                'package': {'name': q.$2, 'ecosystem': q.$1},
                'version': q.$3,
              }
          ]
        });
        final req = await client
            .postUrl(Uri.parse('https://api.osv.dev/v1/querybatch'))
            .timeout(const Duration(seconds: 15));
        req.headers.contentType = ContentType.json;
        req.write(body);
        final res = await req.close().timeout(const Duration(seconds: 20));
        final text = await res
            .transform(utf8.decoder)
            .join()
            .timeout(const Duration(seconds: 20));
        if (res.statusCode != 200) {
          return RuleCheck.incompleteLocalized(
              En.osvStatus(status: res.statusCode),
              Ar.osvStatus(status: res.statusCode),
              out);
        }
        final json = jsonDecode(text);
        final results = json is Map ? json['results'] : null;
        if (results is! List || results.length != batch.length) {
          return RuleCheck.incompleteLocalized(
              En.osvBatchInvalid, Ar.osvBatchInvalid, out);
        }
        for (var k = 0; k < results.length && k < batch.length; k++) {
          final r = results[k];
          if (r is! Map || r['vulns'] != null && r['vulns'] is! List) {
            return RuleCheck.incompleteLocalized(
                En.osvPackageInvalid, Ar.osvPackageInvalid, out);
          }
          final vulns = r['vulns'] as List?;
          if (vulns == null || vulns.isEmpty) continue;
          final ids = vulns
              .map((v) => v is Map ? v['id']?.toString() : null)
              .whereType<String>()
              .toList();
          if (ids.isEmpty) {
            return RuleCheck.incompleteLocalized(
                En.osvAdvisoryInvalid, Ar.osvAdvisoryInvalid, out);
          }
          final (ecosystem, name, version, file) = batch[k];
          // Pub keeps its original message, so existing baselines match.
          final label = ecosystem == 'Pub' ? name : '$ecosystem $name';
          out.add(inFile(file, null,
              '$label $version: ${ids.join(', ')} (https://osv.dev/vulnerability/${ids.first})',
              messageAr: '$label $version عليها: ${ids.join(', ')}'));
        }
      }
    } on Object catch (e) {
      return RuleCheck.incompleteLocalized(
          En.osvLookupFailed(error: e), Ar.osvLookupFailed(error: e), out);
    } finally {
      client.close(force: true);
    }
    _notChecked(project);
    if (lockIssue != null) {
      return RuleCheck.incompleteLocalized(lockIssue, project.lockIssueAr, out);
    }
    return RuleCheck(out);
  }

  /// Maven, npm and Swift Package Manager versions of the app and of the
  /// Android code of its Flutter plugins.
  static Future<List<NativeDependency>> _nativeDependencies(
      Project project) async {
    final files = dependencyFiles(project.root)
        .where((f) => !project.config.isExcluded(f.$1))
        .toList();
    if (project.locked.isNotEmpty) {
      final roots = await resolvePackageRoots(
          project.root, project.locked.keys.toSet(),
          pubGet: project.pubGet, offline: project.offline);
      for (final e in roots.roots.entries) {
        for (final name in const ['build.gradle', 'build.gradle.kts']) {
          final f = File(p.join(e.value, 'android', name));
          if (!f.existsSync()) continue;
          try {
            files.add(('package:${e.key}/android/$name', f.readAsStringSync()));
          } catch (_) {}
        }
      }
    }
    return parseNativeDependencies(files);
  }

  /// CocoaPods has no OSV data: say so instead of passing silently.
  void _notChecked(Project project) {
    for (final path in const [
      'ios/Podfile.lock',
      'Podfile.lock',
      'macos/Podfile.lock'
    ]) {
      if (!File(project.abs(path)).existsSync()) continue;
      project.securityEvidence.add(SecurityEvidence(
          meta.id, path, const Bilingual(En.podsNotChecked, Ar.podsNotChecked),
          status: 'facts', data: const {'ecosystem': 'CocoaPods'}));
      return;
    }
  }
}

class UnpinnedDependencyRule extends Rule {
  const UnpinnedDependencyRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-C02',
        title: Bilingual(En.dependencyRulesUnpinnedOrOverriddenDependencies,
            Ar.dependencyRulesUnpinnedOrOverriddenDependencies),
        description: Bilingual(
            En.dependencyRulesGitDependenciesWithoutARefFollowWhateverIs,
            Ar.dependencyRulesGitDependenciesWithoutARefFollowWhateverIs),
        fix: Bilingual(En.dependencyRulesPinGitDependenciesToACommitRefSha,
            Ar.dependencyRulesPinGitDependenciesToACommitRefSha),
        severity: Severity.low,
        masvs: ['MASVS-CODE-3'],
        maswe: ['MASWE-0044'],
        cwe: 'CWE-1357',
        profiles: _all,
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final out = <Finding>[];
    project.dependencies.forEach((name, spec) {
      if (spec is Map && spec['git'] != null) {
        final git = spec['git'];
        final ref = git is Map ? git['ref'] : null;
        if (ref == null ||
            RegExp(r'^(main|master|develop|dev)$').hasMatch(ref.toString())) {
          out.add(inFile('pubspec.yaml', null,
              En.dependencyRulesIsAGitDependencyWithoutAPinned(name: name),
              messageAr: Ar.dependencyRulesIsAGitDependencyWithoutAPinned(
                  name: name)));
        }
      }
    });
    for (final name in project.dependencyOverrides.keys) {
      out.add(inFile('pubspec.yaml', null,
          En.dependencyRulesIsOverriddenInDependencyOverrides(name: name),
          messageAr:
              Ar.dependencyRulesIsOverriddenInDependencyOverrides(name: name)));
    }
    return RuleCheck(out);
  }
}

const dependencyRules = <Rule>[
  VulnerableDependencyRule(),
  UnpinnedDependencyRule(),
];
