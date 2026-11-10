import '../model.dart';
import '../project.dart';
import '../l10n/messages.g.dart';
import '../security/evidence.dart';
import '../security/metadata.dart';
import '../security/native_analysis.dart';
import 'rule.dart';

class NativeSecurityRule extends Rule {
  const NativeSecurityRule(this.id);
  final String id;
  @override
  RuleMeta get meta => extendedMeta(id);
  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final files = [
      ...project.androidNativeSources,
      ...project.iosNativeSources,
      if (id == 'AEG-N02')
        ...project.dartFiles.map((f) => ProjectFile(f.path, f.source))
    ];
    final out = <Finding>[];
    var inspected = false, limited = false;
    void indicator(String file, Iterable<String> values) {
      final hits = <String>{};
      for (final value in values) {
        hits.addAll(nativeIndicators[id]!.allMatches(value).map((m) => m[0]!));
        if (hits.length >= 40) break;
      }
      if (hits.isNotEmpty) {
        project.securityEvidence.add(SecurityEvidence(
            id,
            file,
            Bilingual('${hits.join(', ')}. ${En.extScope}',
                '${hits.join(', ')}. ${Ar.extScope}'),
            data: {'references': hits.toList(), 'runtimeVerified': false}));
      }
    }

    for (final f in files) {
      inspected = true;
      final source = withoutComments(f.text);
      final code = maskNativeLiterals(source);
      for (final pattern in nativePatterns[id]!) {
        for (final m in pattern.allMatches(source).take(50)) {
          if (code[m.start].trim().isEmpty) continue;
          final token = m[0]!;
          out.add(inFile(
              f.path,
              '\n'.allMatches(source.substring(0, m.start)).length + 1,
              En.extNativeMatch(token: token),
              messageAr: Ar.extNativeMatch(token: token)));
        }
      }
      indicator(f.path, [source]);
    }
    final android = project.nativeAndroidReferences;
    if (android != null) {
      limited |= android.limited;
      for (final entry in android.files.entries) {
        indicator(entry.key, entry.value);
      }
    }
    // Compiled references deliberately remain evidence, never a source verdict.
    final ipa = project.ipa;
    if (ipa != null) {
      limited |= ipa.staticAnalysis.limited;
      for (final b in ipa.staticAnalysis.binaries) {
        for (final s in b.slices.where((s) => !s.encrypted)) {
          indicator('${ipa.label}!/${b.path} [${s.architecture}]', [
            ...s.symbols.map((s) => s.replaceFirst(RegExp(r'^_+'), '')),
            ...s.strings,
            ...s.metadata.entries.map((e) => e.qualifiedName),
          ]);
        }
      }
    }
    if (limited) {
      project.securityEvidence.add(SecurityEvidence(
          id,
          ipa?.label ?? project.apk!.fileName,
          const Bilingual(En.extIncomplete, Ar.extIncomplete),
          status: 'unavailable'));
    }
    if (!inspected) {
      return RuleCheck.notApplicableLocalized(
          En.extIndicatorOnly, Ar.extIndicatorOnly);
    }
    return RuleCheck(out);
  }
}
