import 'package:path/path.dart' as p;
import '../model.dart';
import '../project.dart';
import '../security/evidence.dart';
import '../security/metadata.dart';
import '../l10n/messages.g.dart';
import 'rule.dart';

/// Reports discovery coverage without awarding security points for file counts.
class SourceCoverageRule extends Rule {
  const SourceCoverageRule();
  @override
  RuleMeta get meta => extendedMeta('AEG-S01');
  @override
  RuleCheck check(Project project, ProfileSet profile) {
    if (!project.hasSource) return RuleCheck.notApplicable();
    final counts = <String, int>{};
    for (final path in [
      ...project.nativeSources.map((f) => f.path),
      ...project.scriptSources.map((f) => f.path),
      ...project.dartFiles.map((f) => f.path),
    ]) {
      final extension = p.extension(path);
      counts[extension] = (counts[extension] ?? 0) + 1;
    }
    final frameworks = {
      if (project.isFlutterApp) 'Flutter',
      ...project.sourceFrameworks,
    }.toList()
      ..sort();
    final languages = counts.keys.toList()..sort();
    final summary = languages.map((l) => '$l: ${counts[l]}').join(', ');
    final unsupported = project.unsupportedSources;
    project.securityEvidence.add(SecurityEvidence(
        meta.id,
        '.',
        Bilingual(
            En.sourceInventory(
                frameworks: frameworks.join(', '),
                files: summary,
                gaps: [...unsupported, ...project.nativeSourceIssues]
                    .take(20)
                    .join(', ')),
            Ar.sourceInventory(
                frameworks: frameworks.join(', '),
                files: summary,
                gaps: [...unsupported, ...project.nativeSourceIssues]
                    .take(20)
                    .join(', '))),
        data: {
          'frameworks': frameworks,
          'inspectedFilesByExtension': counts,
          'unsupportedFiles': unsupported,
          'unreadableOrLimitedInputs': project.nativeSourceIssues,
          'analysis': 'lexical-patterns',
          'dependencyVulnerabilityAudit':
              project.nativeOnly ? 'not-supported' : 'pubspec-only',
          'runtimeVerified': false,
        }));
    if (unsupported.isNotEmpty ||
        project.nativeSourceIssues.isNotEmpty ||
        counts.isEmpty) {
      return RuleCheck.incompleteLocalized(
          En.sourceCoverageGap, Ar.sourceCoverageGap);
    }
    return RuleCheck.notApplicableLocalized(
        En.sourceCoverageScope, Ar.sourceCoverageScope);
  }
}
