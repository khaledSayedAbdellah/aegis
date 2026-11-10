/// Concrete build findings from IPA bytes, distinct from runtime resilience.
library;

import '../l10n/messages.g.dart';
import '../model.dart';
import '../project.dart';
import 'rule.dart';

enum _Check { pie, memory, debug }

class _IpaHardeningRule extends Rule {
  const _IpaHardeningRule._(this.kind);
  final _Check kind;

  @override
  RuleMeta get meta => switch (kind) {
        _Check.pie => const RuleMeta(
            id: 'AEG-I07',
            title: Bilingual(En.iosPieTitle, Ar.iosPieTitle),
            passTitleText: Bilingual(En.iosPiePass, Ar.iosPiePass),
            description: Bilingual(En.iosPieDescription, Ar.iosPieDescription),
            fix: Bilingual(En.iosPieFix, Ar.iosPieFix),
            severity: Severity.medium,
            masvs: ['MASVS-CODE-4'],
            profiles: {MasProfile.l1}),
        _Check.memory => const RuleMeta(
            id: 'AEG-I08',
            title: Bilingual(En.iosMemoryTitle, Ar.iosMemoryTitle),
            passTitleText: Bilingual(En.iosMemoryPass, Ar.iosMemoryPass),
            description:
                Bilingual(En.iosMemoryDescription, Ar.iosMemoryDescription),
            fix: Bilingual(En.iosMemoryFix, Ar.iosMemoryFix),
            severity: Severity.medium,
            masvs: ['MASVS-CODE-4'],
            profiles: {MasProfile.l1}),
        _Check.debug => const RuleMeta(
            id: 'AEG-I09',
            title: Bilingual(En.iosDebugTitle, Ar.iosDebugTitle),
            passTitleText: Bilingual(En.iosDebugPass, Ar.iosDebugPass),
            description:
                Bilingual(En.iosDebugDescription, Ar.iosDebugDescription),
            fix: Bilingual(En.iosDebugFix, Ar.iosDebugFix),
            severity: Severity.low,
            masvs: ['MASVS-RESILIENCE-3'],
            profiles: {MasProfile.r}),
      };

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final ipa = project.ipa;
    if (ipa == null) return RuleCheck.notApplicable();
    final analysis = ipa.staticAnalysis;
    final findings = <Finding>[];
    var missingSymbols = false, applicable = false;
    for (final binary in analysis.binaries) {
      for (final s in binary.slices) {
        String? en, ar;
        switch (kind) {
          case _Check.pie:
            if (s.fileType != 2) continue;
            applicable = true;
            if (!s.pie) {
              en = En.iosPieFinding(architecture: s.architecture);
              ar = Ar.iosPieFinding(architecture: s.architecture);
            }
          case _Check.memory:
            applicable = true;
            if (s.executableStackRequested ||
                s.writableExecutableSegments.isNotEmpty) {
              en = En.iosMemoryFinding(
                  architecture: s.architecture,
                  stack: s.executableStackRequested
                      ? En.iosStaticYes
                      : En.iosStaticNo,
                  segments: s.writableExecutableSegments.join(', '));
              ar = Ar.iosMemoryFinding(
                  architecture: s.architecture,
                  stack: s.executableStackRequested
                      ? Ar.iosStaticYes
                      : Ar.iosStaticNo,
                  segments: s.writableExecutableSegments.join(', '));
            }
          case _Check.debug:
            applicable = true;
            missingSymbols |= !s.symbolTable;
            if (s.debugSymbols > 0) {
              en = En.iosDebugFinding(
                  architecture: s.architecture, count: s.debugSymbols);
              ar = Ar.iosDebugFinding(
                  architecture: s.architecture, count: s.debugSymbols);
            }
        }
        if (en != null) {
          findings.add(
              inFile('${ipa.label}!/${binary.path}', null, en, messageAr: ar));
        }
      }
    }
    if (!analysis.complete || !applicable) {
      return RuleCheck.incompleteLocalized(
          En.iosHardeningIncomplete, Ar.iosHardeningIncomplete, findings);
    }
    if (missingSymbols) {
      return RuleCheck.incompleteLocalized(
          En.iosDebugUnavailable, Ar.iosDebugUnavailable, findings);
    }
    return RuleCheck(findings);
  }
}

const ipaHardeningRules = <Rule>[
  _IpaHardeningRule._(_Check.pie),
  _IpaHardeningRule._(_Check.memory),
  _IpaHardeningRule._(_Check.debug),
];
