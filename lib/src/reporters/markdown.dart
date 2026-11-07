/// Markdown report, handy for pull-request comments and wikis.
library;

import '../engine.dart';
import '../masvs.dart';
import '../scoring.dart';
import 'i18n.dart';

String renderMarkdown(AuditReport r, {String lang = 'en'}) {
  final t = Strings(lang);
  final b = StringBuffer();
  if (t.ar) b.writeln('<div dir="rtl">\n');
  b.writeln('# 🛡 ${t.title}');
  b.writeln();
  b.writeln('| | |');
  b.writeln('|---|---|');
  b.writeln('| ${t.project} | `${r.projectName}` |');
  b.writeln('| ${t.profile} | **${r.profile}** |');
  if (r.scannedPackages.isNotEmpty) {
    b.writeln('| ${t.packages} | ${r.scannedPackages.map((x) => '`$x`').join(', ')} |');
  }
  final bin = r.binary;
  if (bin != null) {
    b.writeln('| ${t.binary} | `${bin.file}` ${bin.packageName ?? ''} ${bin.versionName ?? ''} |');
    for (final c in bin.certificates) {
      b.writeln('| ${t.signer} | ${c.commonName ?? '?'} (${c.scheme}) |');
      b.writeln('| ${t.certHash} | `${c.sha256Base64}` |');
    }
  }
  b.writeln('| ${t.score} | **${r.score.value}/100 (${r.score.grade})** |');
  b.writeln('| ${t.coverage} | ${t.coverageLine(r.coverage.checked, r.coverage.inScope, r.coverage.percent)} |');
  if (r.usesBaseline) {
    b.writeln('| ${t.baseline} | ${t.baselineLine(r.knownFindingCount, r.newFindingCount, r.resolvedCount)} |');
  }
  b.writeln();

  if (r.score.categories.isNotEmpty) {
    b.writeln('## ${t.categories}');
    b.writeln();
    b.writeln('| | Score | Rules |');
    b.writeln('|---|---:|---:|');
    for (final c in r.score.categories.values) {
      b.writeln('| ${masvsCategories[c.category]?.of(lang) ?? c.category} | ${c.score} | ${c.checked - c.failed}/${c.checked} |');
    }
    b.writeln();
  }

  final failed = r.newFailed.toList();
  b.writeln('## ❌ ${r.usesBaseline ? t.newIssues : t.failed} (${failed.length})');
  b.writeln();
  if (failed.isEmpty) b.writeln(r.usesBaseline ? t.noNewIssues : t.noIssues);
  for (final res in failed) {
    final m = res.meta;
    b.writeln('### `${m.id}` ${m.title.of(lang)} — ${t.severity(res.severity)}');
    b.writeln();
    b.writeln('${m.masvs.join(', ')}${m.maswe.isEmpty ? '' : ' · ${m.maswe.join(', ')}'}${m.cwe == null ? '' : ' · ${m.cwe}'}');
    b.writeln();
    for (final f in res.newFindings) {
      final loc = f.location.isEmpty ? '' : '`${f.location}` — ';
      b.writeln('- $loc${f.messageOf(lang)}');
    }
    final knownCount = res.findings.length - res.newFindings.length;
    if (knownCount > 0) b.writeln('- _+ ${t.knownCount(knownCount)}_');
    b.writeln();
    b.writeln('**${t.why}:** ${m.description.of(lang)}');
    b.writeln();
    b.writeln('**${t.fix}:** ${m.fix.of(lang)}');
    b.writeln();
  }

  final known = r.failed.where((x) => !x.hasNew).toList();
  if (known.isNotEmpty) {
    b.writeln('<details><summary>${t.known} (${known.length})</summary>');
    b.writeln();
    for (final res in known) {
      b.writeln('- `${res.meta.id}` ${res.meta.title.of(lang)} — ${t.severity(res.severity)} · ${t.knownCount(res.findings.length)}');
    }
    b.writeln();
    b.writeln('_${t.knownHint}_');
    b.writeln();
    b.writeln('</details>');
    b.writeln();
  }
  if (r.baselineResolved.isNotEmpty) {
    b.writeln('## ✅ ${t.resolved} (${r.resolvedCount})');
    b.writeln();
    for (final e in r.baselineResolved) {
      b.writeln('- `${e.ruleId}` ${e.file == null ? '' : '`${e.file}` — '}${e.message}');
    }
    b.writeln();
    b.writeln('_${t.updateHint}_');
    b.writeln();
  }

  final passed = r.passed.toList();
  b.writeln('## ✅ ${t.passed} (${passed.length})');
  b.writeln();
  for (final res in passed) {
    b.writeln('- `${res.meta.id}` ${res.meta.passTitle.of(lang)}');
  }
  b.writeln();

  b.writeln('## ❔ ${t.manual}');
  b.writeln();
  for (final m in r.manual) {
    b.writeln('- [ ] ${m.text.of(lang)} (`${m.masvs}`)');
  }
  b.writeln();

  b.writeln('<details><summary>${t.coverage}</summary>');
  b.writeln();
  b.writeln('| Control | Status | Rules |');
  b.writeln('|---|---|---|');
  for (final c in r.coverage.controls) {
    final s = switch (c.status) {
      ControlStatus.checked => '✅',
      ControlStatus.manualOnly => '❔',
      ControlStatus.notCovered => '—',
    };
    b.writeln('| ${c.control.id} | $s | ${c.ruleIds.join(', ')} |');
  }
  b.writeln();
  b.writeln('</details>');
  b.writeln();
  b.writeln('> ${t.disclaimer}');
  if (t.ar) b.writeln('\n</div>');
  return b.toString();
}
