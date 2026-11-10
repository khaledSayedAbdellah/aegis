/// Rules about third-party packages.
library;

import '../l10n/messages.g.dart';

import 'dart:convert';
import 'dart:io';

import '../model.dart';
import '../project.dart';
import 'rule.dart';

const _all = {MasProfile.l1, MasProfile.l2, MasProfile.r};

class VulnerableDependencyRule extends Rule {
  const VulnerableDependencyRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-C01',
        title: Bilingual(En.dependencyRulesDependencyWithKnownVulnerabilities, Ar.dependencyRulesDependencyWithKnownVulnerabilities),
        description: Bilingual(En.dependencyRulesALockedPackageVersionHasAPublishedAdvisory, Ar.dependencyRulesALockedPackageVersionHasAPublishedAdvisory),
        fix: Bilingual(En.dependencyRulesUpgradeThePackageToAFixedVersionDart, Ar.dependencyRulesUpgradeThePackageToAFixedVersionDart),
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
    if (lockIssue != null) return RuleCheck.incompleteLocalized(lockIssue, project.lockIssueAr);
    final pkgs = project.locked.values
        .where((p) => p.source == 'hosted' && p.version.isNotEmpty)
        .toList();
    if (pkgs.isEmpty) return RuleCheck.notApplicable('No locked hosted dependencies');

    final client = HttpClient()..connectionTimeout = const Duration(seconds: 10);
    final out = <Finding>[];
    try {
      for (var i = 0; i < pkgs.length; i += 500) {
        final batch = pkgs.sublist(i, (i + 500).clamp(0, pkgs.length).toInt());
        final body = jsonEncode({
          'queries': [
            for (final p in batch)
              {
                'package': {'name': p.name, 'ecosystem': 'Pub'},
                'version': p.version,
              }
          ]
        });
        final req = await client
            .postUrl(Uri.parse('https://api.osv.dev/v1/querybatch'))
            .timeout(const Duration(seconds: 15));
        req.headers.contentType = ContentType.json;
        req.write(body);
        final res = await req.close().timeout(const Duration(seconds: 20));
        final text = await res.transform(utf8.decoder).join().timeout(const Duration(seconds: 20));
        if (res.statusCode != 200) {
          return RuleCheck.incompleteLocalized(En.osvStatus(status: res.statusCode), Ar.osvStatus(status: res.statusCode), out);
        }
        final json = jsonDecode(text);
        final results = json is Map ? json['results'] : null;
        if (results is! List || results.length != batch.length) {
          return RuleCheck.incompleteLocalized(En.osvBatchInvalid, Ar.osvBatchInvalid, out);
        }
        for (var k = 0; k < results.length && k < batch.length; k++) {
          final r = results[k];
          if (r is! Map || r['vulns'] != null && r['vulns'] is! List) {
            return RuleCheck.incompleteLocalized(En.osvPackageInvalid, Ar.osvPackageInvalid, out);
          }
          final vulns = r['vulns'] as List?;
          if (vulns == null || vulns.isEmpty) continue;
          final ids = vulns
              .map((v) => v is Map ? v['id']?.toString() : null)
              .whereType<String>()
              .toList();
          if (ids.isEmpty) return RuleCheck.incompleteLocalized(En.osvAdvisoryInvalid, Ar.osvAdvisoryInvalid, out);
          final p = batch[k];
          out.add(inFile('pubspec.lock', null,
              '${p.name} ${p.version}: ${ids.join(', ')} (https://osv.dev/vulnerability/${ids.first})',
              messageAr: '${p.name} ${p.version} عليها: ${ids.join(', ')}'));
        }
      }
    } on Object catch (e) {
      return RuleCheck.incompleteLocalized(En.osvLookupFailed(error: e), Ar.osvLookupFailed(error: e), out);
    } finally {
      client.close(force: true);
    }
    return RuleCheck(out);
  }
}

class UnpinnedDependencyRule extends Rule {
  const UnpinnedDependencyRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-C02',
        title: Bilingual(En.dependencyRulesUnpinnedOrOverriddenDependencies, Ar.dependencyRulesUnpinnedOrOverriddenDependencies),
        description: Bilingual(En.dependencyRulesGitDependenciesWithoutARefFollowWhateverIs, Ar.dependencyRulesGitDependenciesWithoutARefFollowWhateverIs),
        fix: Bilingual(En.dependencyRulesPinGitDependenciesToACommitRefSha, Ar.dependencyRulesPinGitDependenciesToACommitRefSha),
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
        if (ref == null || RegExp(r'^(main|master|develop|dev)$').hasMatch(ref.toString())) {
          out.add(inFile('pubspec.yaml', null,
              En.dependencyRulesIsAGitDependencyWithoutAPinned(name: name),
              messageAr: Ar.dependencyRulesIsAGitDependencyWithoutAPinned(name: name)));
        }
      }
    });
    for (final name in project.dependencyOverrides.keys) {
      out.add(inFile('pubspec.yaml', null, En.dependencyRulesIsOverriddenInDependencyOverrides(name: name),
          messageAr: Ar.dependencyRulesIsOverriddenInDependencyOverrides(name: name)));
    }
    return RuleCheck(out);
  }
}

const dependencyRules = <Rule>[
  VulnerableDependencyRule(),
  UnpinnedDependencyRule(),
];
