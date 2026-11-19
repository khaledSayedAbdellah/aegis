/// Markdown report, handy for pull-request comments and wikis.
library;

import '../l10n/messages.g.dart';
import '../engine.dart';
import '../masvs.dart';
import '../model.dart';
import '../scoring.dart';
import 'i18n.dart';
import 'probe_view.dart';
import 'ios_static_view.dart';
import 'security_view.dart';

String renderMarkdown(AuditReport r, {String lang = 'en'}) {
  final t = Strings(lang);
  final b = StringBuffer();
  if (t.ar) b.writeln('<div dir="rtl">\n');
  b.writeln('# 🛡 ${t.title}');
  b.writeln();
  b.writeln('| | |');
  b.writeln('|---|---|');
  b.writeln('| ${t.project} | ${_code(r.projectName)} |');
  b.writeln('| ${t.profile} | **${r.profile}** |');
  if (r.scannedPackages.isNotEmpty) {
    b.writeln(
        '| ${t.packages} | ${r.scannedPackages.map((x) => '`$x`').join(', ')} |');
  }
  final bin = r.binary;
  if (bin != null) {
    b.writeln(
        '| ${t.binaryKind(bin.kind)} | `${bin.file}` ${bin.packageName ?? ''} ${bin.versionName ?? ''} |');
    for (final c in bin.certificates) {
      b.writeln(
          '| ${t.signer} | ${c.commonName ?? '?'} (${c.scheme})${bin.kind == 'AAB' ? ' · ${t.uploadKey}' : ''} |');
      b.writeln('| ${t.certHash(bin.kind)} | `${c.sha256Base64}` |');
    }
  }
  b.writeln('| ${t.score} | **${r.score.value}/100 (${r.score.grade})**'
      '${r.complete ? '' : '<br>**${L10n(lang).scoreProvisional}**<br>${L10n(lang).scoreProvisionalDetail}'}'
      '${[
    t.band(r.score),
    t.bestFixes(r.score)
  ].whereType<String>().map((x) => '<br>$x').join()} |');
  b.writeln(
      '| ${t.coverage} | ${t.coverageLine(r.coverage.checked, r.coverage.inScope, r.coverage.percent)} |');
  if (r.usesBaseline) {
    b.writeln(
        '| ${t.baseline} | ${t.baselineLine(r.knownFindingCount, r.newFindingCount, r.resolvedCount)} |');
  }
  if (r.changed != null) {
    b.writeln(
        '| ${t.changedLines} | ${t.changedLinesSummary('`${r.changed!.ref}`', r.outsideChangeCount)} |');
  }
  b.writeln();

  if (r.incomplete.isNotEmpty) {
    b.writeln('## ${L10n(lang).incompleteChecks}');
    b.writeln();
    for (final res in r.incomplete) {
      b.writeln(
          '- ${res.meta.id} · ${_text(res.noteOf(lang) ?? res.meta.title.of(lang))}');
    }
    b.writeln();
  }

  if (r.score.categories.isNotEmpty) {
    b.writeln('## ${t.categories}');
    b.writeln();
    b.writeln('| | ${t.score} | ${t.rulesCol} | ${t.problemsCol} |');
    b.writeln('|---|---:|---:|---|');
    for (final c in r.score.categories.values) {
      final mark = switch (c.worst) {
        null => '✅',
        Severity.critical || Severity.high => '🔴',
        Severity.medium => '🟠',
        _ => '🟡',
      };
      b.writeln(
          '| ${masvsCategories[c.category]?.of(lang) ?? c.category} | $mark ${c.score} | '
          '${c.checked - c.failed}/${c.checked} | ${c.failedRuleIds.join(', ')} |');
    }
    b.writeln();
  }

  if (r.iosStatic != null) {
    b.write(IosStaticView(r.iosStatic!, lang).markdown());
  }
  b.write(SecurityView(r.securityEvidence, lang,
      titles: {for (final x in r.results) x.meta.id: x.meta.title}).markdown());

  final probe = ProbeView.of(r, lang);
  if (probe != null) {
    b.writeln('## 🧪 ${probe.heading}');
    b.writeln();
    if (probe.message != null) {
      b.writeln('⏸️ ${_text(probe.message!)}');
      b.writeln();
    }
    if (probe.details.isNotEmpty) {
      b.writeln('```');
      for (final d in probe.details) {
        b.writeln(d.replaceAll('```', "'''"));
      }
      b.writeln('```');
      b.writeln();
    }
    if (probe.baseline != null) {
      b.writeln(probe.baseline);
      b.writeln();
    }
    if (probe.lines.isNotEmpty) {
      b.writeln(
          '| ${t.probeCheck} | ${t.result} | ${t.probeObserved} | MASVS · MASTG | ${t.rules} |');
      b.writeln('|---|:---:|---|---|---|');
      for (final l in probe.lines) {
        final note =
            l.note == null ? '' : '<br>_${l.note!.replaceAll('|', '/')}_';
        b.writeln(
            '| ${l.title} | ${l.mark} | ${l.evidence}$note | ${l.tag} | ${l.ruleId == null ? '' : '`${l.ruleId}`'} |');
      }
      b.writeln();
    }
    for (final c in probe.caveats) {
      b.writeln('- _${c}_');
    }
    if (probe.caveats.isNotEmpty) b.writeln();
  }

  final failed = r.newFailed.toList();
  b.writeln('## ❌ ${t.failedHeading(r)} (${failed.length})');
  b.writeln();
  if (failed.isEmpty) b.writeln(t.emptyHeading(r));
  for (final res in failed) {
    final m = res.meta;
    b.writeln(
        '### `${m.id}` ${_text(m.title.of(lang))} — ${t.severity(res.newSeverity)}');
    b.writeln();
    final refs = [
      if (m.masvs.isNotEmpty) m.masvs.join(', '),
      if (m.maswe.isNotEmpty) m.maswe.join(', '),
      if (m.cwe != null) m.cwe!,
    ];
    if (refs.isNotEmpty) {
      b.writeln(refs.join(' · '));
      b.writeln();
    }
    for (final f in res.newFindings) {
      final loc = f.location.isEmpty ? '' : '${_code(f.location)} — ';
      b.writeln('- $loc${_text(f.messageOf(lang))}');
    }
    final knownCount = res.knownFindings.length;
    if (knownCount > 0) b.writeln('- _+ ${t.knownCount(knownCount)}_');
    b.writeln();
    b.writeln('**${t.why}:** ${_text(m.description.of(lang))}');
    b.writeln();
    b.writeln('**${t.fix}:** ${_text(m.fix.of(lang))}');
    b.writeln();
  }

  final known = r.failed.where((x) => !x.hasNew && x.hasKnown).toList();
  if (known.isNotEmpty) {
    b.writeln('<details><summary>${t.known} (${known.length})</summary>');
    b.writeln();
    for (final res in known) {
      b.writeln(
          '- `${res.meta.id}` ${_text(res.meta.title.of(lang))} — ${t.severity(res.severity)} · ${t.knownCount(res.knownFindings.length)}');
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
      b.writeln(
          '- ${_code(e.ruleId)} ${e.file == null ? '' : '${_code(e.file!)} — '}${_text(e.message)}');
    }
    b.writeln();
    b.writeln('_${t.updateHint}_');
    b.writeln();
  }

  final passed = r.passed.toList();
  b.writeln('## ✅ ${t.passed} (${passed.length})');
  b.writeln();
  for (final res in passed) {
    b.writeln('- `${res.meta.id}` ${_text(res.meta.passTitle.of(lang))}');
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
  b.writeln('| ${t.control} | ${t.result} | ${t.rules} |');
  b.writeln('|---|---|---|');
  for (final c in r.coverage.controls) {
    // ✅ only when every rule of the control passed; "checked" alone does
    // not mean healthy.
    final s = switch (c.status) {
      ControlStatus.checked => c.failedRuleIds.isEmpty ? '✅' : '❌',
      ControlStatus.manualOnly => '❔',
      ControlStatus.notCovered => '—',
    };
    final ids = c.ruleIds
        .map((id) => c.failedRuleIds.contains(id) ? '**$id**' : id)
        .join(', ');
    b.writeln('| ${c.control.id} | $s | $ids |');
  }
  b.writeln();
  b.writeln(t.coverageLegend);
  b.writeln();
  b.writeln('</details>');
  b.writeln();
  b.writeln('> ${t.disclaimer}');
  if (t.ar) b.writeln('\n</div>');
  return b.toString();
}

/// Text from the audited project (file names, matched values, custom rule
/// text) can't add HTML to the report: GitHub job summaries and Azure build
/// summaries render it. Markdown formatting such as `code` stays.
String _text(String s) =>
    s.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');

/// [s] as a code span that a backtick in [s] can't end.
String _code(String s) {
  final one = s.replaceAll(RegExp(r'[\r\n]+'), ' ');
  var fence = '`';
  while (one.contains(fence)) {
    fence += '`';
  }
  return fence.length == 1 ? '`$one`' : '$fence $one $fence';
}
