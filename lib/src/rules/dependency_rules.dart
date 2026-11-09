/// Rules about third-party packages.
library;

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
        title: Bilingual('Dependency with known vulnerabilities', 'مكتبة فيها ثغرات معروفة'),
        description: Bilingual(
            'A locked package version has a published advisory in the OSV database.',
            'فيه نسخة مكتبة في pubspec.lock عليها ثغرة منشورة في قاعدة بيانات OSV.'),
        fix: Bilingual('Upgrade the package to a fixed version (dart pub upgrade <package>).',
            'حدّث المكتبة لنسخة فيها الإصلاح (dart pub upgrade <package>).'),
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
    if (lockIssue != null) return RuleCheck.incomplete(lockIssue);
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
          return RuleCheck.incomplete('osv.dev returned ${res.statusCode}', out);
        }
        final json = jsonDecode(text);
        final results = json is Map ? json['results'] : null;
        if (results is! List || results.length != batch.length) {
          return RuleCheck.incomplete('Invalid OSV batch response', out);
        }
        for (var k = 0; k < results.length && k < batch.length; k++) {
          final r = results[k];
          if (r is! Map || r['vulns'] != null && r['vulns'] is! List) {
            return RuleCheck.incomplete('Invalid OSV package response', out);
          }
          final vulns = r['vulns'] as List?;
          if (vulns == null || vulns.isEmpty) continue;
          final ids = vulns
              .map((v) => v is Map ? v['id']?.toString() : null)
              .whereType<String>()
              .toList();
          if (ids.isEmpty) return RuleCheck.incomplete('Invalid OSV advisory response', out);
          final p = batch[k];
          out.add(inFile('pubspec.lock', null,
              '${p.name} ${p.version}: ${ids.join(', ')} (https://osv.dev/vulnerability/${ids.first})',
              messageAr: '${p.name} ${p.version} عليها: ${ids.join(', ')}'));
        }
      }
    } on Object catch (e) {
      return RuleCheck.incomplete('Could not complete OSV lookup ($e)', out);
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
        title: Bilingual('Unpinned or overridden dependencies', 'مكتبات مش متثبتة على نسخة أو متعمل لها override'),
        description: Bilingual(
            'Git dependencies without a ref follow whatever is pushed next, and dependency_overrides silently replace audited versions.',
            'مكتبات الـ git من غير ref بتاخد أي حاجة تترفع بعد كده، والـ dependency_overrides بتبدّل النسخ اللي اتراجعت من غير ما تحس.'),
        fix: Bilingual('Pin git dependencies to a commit (ref: <sha>) and remove dependency_overrides before release.',
            'ثبّت مكتبات الـ git على commit معين (ref: <sha>)، وشيل الـ dependency_overrides قبل الـ release.'),
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
              '$name is a git dependency without a pinned commit.',
              messageAr: '$name مكتبة git من غير commit ثابت.'));
        }
      }
    });
    for (final name in project.dependencyOverrides.keys) {
      out.add(inFile('pubspec.yaml', null, '$name is overridden in dependency_overrides.',
          messageAr: '$name متعمل لها override في dependency_overrides.'));
    }
    return RuleCheck(out);
  }
}

const dependencyRules = <Rule>[
  VulnerableDependencyRule(),
  UnpinnedDependencyRule(),
];
