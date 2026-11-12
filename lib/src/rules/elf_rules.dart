import '../binary/elf_security.dart';
import '../model.dart';
import '../project.dart';
import '../l10n/messages.g.dart';
import '../security/evidence.dart';
import '../security/metadata.dart';
import 'rule.dart';

class ElfHardeningRule extends Rule {
  const ElfHardeningRule();
  @override
  RuleMeta get meta => extendedMeta('AEG-B12');
  @override
  RuleCheck check(Project p, ProfileSet profile) {
    final apk = p.apk;
    if (apk == null) return RuleCheck.notApplicable();
    final entries = apk.archive.entries.values
        .where((e) =>
            e.name.endsWith('.so') && RegExp(r'(^|/)lib/').hasMatch(e.name))
        .toList();
    if (entries.isEmpty) return RuleCheck.notApplicable();
    final out = <Finding>[];
    var limited = entries.length > 128, total = 0;
    for (final entry in entries.take(128)) {
      final location = apk.location(entry.name);
      try {
        total += entry.size;
        if (entry.size > 128 * 1024 * 1024 || total > 512 * 1024 * 1024) {
          throw const FormatException('ELF limit');
        }
        final s = inspectElf(
            apk.archive.readEntry(entry, maxBytes: 128 * 1024 * 1024));
        p.securityEvidence.add(SecurityEvidence(
            meta.id,
            location,
            Bilingual('${s.toJson()}\n${En.extScope}',
                '${s.toJson()}\n${Ar.extScope}'),
            status: 'facts',
            data: s.toJson()));
        void add(String en, String ar) =>
            out.add(inFile(location, null, En.extElfFinding(detail: en),
                messageAr: Ar.extElfFinding(detail: ar)));
        if (s.executableStack) add(En.extElfStack, Ar.extElfStack);
        if (s.wx) add(En.extElfWx, Ar.extElfWx);
        if (s.dynamic && (!s.relro || !s.bindNow)) {
          add(En.extElfRelro, Ar.extElfRelro);
        }
        if (s.type == 2) add(En.extElfPie, Ar.extElfPie);
        if (s.debugSections.isNotEmpty) add(En.extElfDebug, Ar.extElfDebug);
        if (s.paths.any((v) =>
            v.isEmpty || !v.startsWith('/') && !v.startsWith(r'$ORIGIN/'))) {
          add(En.extElfRpath, Ar.extElfRpath);
        }
      } catch (_) {
        limited = true;
        p.securityEvidence.add(SecurityEvidence(meta.id, location,
            const Bilingual(En.extIncomplete, Ar.extIncomplete),
            status: 'unavailable'));
      }
    }
    return limited
        ? RuleCheck.incompleteLocalized(En.extIncomplete, Ar.extIncomplete, out)
        : RuleCheck(out);
  }
}
