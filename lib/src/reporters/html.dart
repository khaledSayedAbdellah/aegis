/// Self-contained HTML report to share with people who don't use a terminal.
library;

import '../l10n/messages.g.dart';
import 'dart:convert';

import '../engine.dart';
import '../masvs.dart';
import '../model.dart';
import '../probe/probe_model.dart';
import 'i18n.dart';
import 'probe_view.dart';
import 'ios_static_view.dart';
import 'security_view.dart';

/// Escapes text for HTML. `/` is left as is so paths and Base64 hashes stay
/// readable and copyable.
String _e(String s) => const HtmlEscape(HtmlEscapeMode(
      escapeLtGt: true,
      escapeQuot: true,
      escapeApos: true,
    )).convert(s);

String _binaryHtml(AuditReport r, Strings t) {
  final pkgs = r.scannedPackages.isEmpty
      ? ''
      : '<div class="muted">${_e(t.packages)}: ${_e(r.scannedPackages.join(', '))}</div>';
  final bin = r.binary;
  if (bin == null) return pkgs;
  final b = StringBuffer('$pkgs<div class="muted">${_e(t.binaryKind(bin.kind))}: <code>${_e(bin.file)}</code> ${_e(bin.packageName ?? '')} ${_e(bin.versionName ?? '')}</div>');
  for (final c in bin.certificates) {
    b.write('<div class="muted">${_e(t.signer)}: ${_e(c.commonName ?? '?')} (${c.scheme})${bin.kind == 'AAB' ? ' · ${_e(t.uploadKey)}' : ''}<br>${_e(t.certHash(bin.kind))}: <code>${_e(c.sha256Base64)}</code></div>');
  }
  return b.toString();
}

String renderHtml(AuditReport r, {String lang = 'en'}) {
  final t = Strings(lang);
  final dir = t.ar ? 'rtl' : 'ltr';
  // Coloured like the band, as the categories are.
  final scoreColor = switch (r.score.worst) {
    null || Severity.low || Severity.info => 'var(--ok)',
    Severity.medium => 'var(--warn)',
    _ => 'var(--bad)',
  };

  String sevClass(Severity s) => 'sev sev-${s.name}';

  String findingLi(Finding f) =>
      '<li${f.baselined ? ' class="known"' : ''}>${f.location.isEmpty ? '' : '<code>${_e(f.location)}</code> '}${_e(f.messageOf(lang))}'
      '${f.baselined ? ' <span class="tag">${_e(t.isKnown)}</span>' : ''}'
      '${f.snippet == null ? '' : '<pre>${_e(f.snippetOf(lang)!)}</pre>'}</li>';

  final newFailed = r.newFailed.toList();
  final knownOnly = r.failed.where((x) => !x.hasNew).toList();
  final failed = StringBuffer();
  for (final res in [...newFailed, ...knownOnly]) {
    final m = res.meta;
    if (knownOnly.isNotEmpty && identical(res, knownOnly.first)) {
      failed.writeln('<h2>≈ ${_e(t.known)} (${knownOnly.length})</h2><p class="muted">${_e(t.knownHint)}</p>');
    }
    failed.writeln('<details class="card${res.hasNew ? '' : ' known'}"${res.hasNew ? ' open' : ''}>');
    failed.writeln('<summary><span class="${sevClass(res.severity)}">${_e(t.severity(res.severity))}</span> '
        '<strong>${_e(m.title.of(lang))}</strong> <code>${m.id}</code></summary>');
    failed.writeln('<p class="muted">${_e([...m.masvs, ...m.maswe, if (m.cwe != null) m.cwe!].join(' · '))}</p>');
    failed.writeln('<ul>');
    // New findings first.
    for (final f in [...res.newFindings, ...res.knownFindings]) {
      failed.writeln(findingLi(f));
    }
    failed.writeln('</ul>');
    failed.writeln('<p><b>${_e(t.why)}:</b> ${_e(m.description.of(lang))}</p>');
    failed.writeln('<p class="fix"><b>${_e(t.fix)}:</b> ${_e(m.fix.of(lang))}</p>');
    failed.writeln('</details>');
  }

  final cats = StringBuffer();
  for (final c in r.score.categories.values) {
    // Coloured by the worst open problem: a category at 80 with a high
    // finding is red, not green.
    final color = switch (c.worst) {
      null || Severity.low || Severity.info => 'var(--ok)',
      Severity.medium => 'var(--warn)',
      _ => 'var(--bad)',
    };
    final open = c.failedRuleIds.isEmpty ? '' : '<small class="muted">${_e(c.failedRuleIds.join(' · '))}</small>';
    cats.writeln('<div class="cat"><span>${_e(masvsCategories[c.category]?.of(lang) ?? c.category)}$open</span>'
        '<div class="bar"><i style="width:${c.score}%;background:$color"></i></div><b style="color:$color">${c.score}</b></div>');
  }

  final resolved = r.baselineResolved.isEmpty
      ? ''
      : '<h2>↓ ${_e(t.resolved)} (${r.resolvedCount})</h2><ul>'
          '${r.baselineResolved.map((e) => '<li>✓ <code>${_e(e.ruleId)}</code> ${e.file == null ? '' : '<code>${_e(e.file!)}</code> '}${_e(e.message)}</li>').join()}'
          '</ul><p class="muted">${_e(t.updateHint)}</p>';
  final baselineLine = r.usesBaseline
      ? '<div class="muted">${_e(t.baseline)}: <b>${_e(t.baselineLine(r.knownFindingCount, r.newFindingCount, r.resolvedCount))}</b></div>'
      : '';
  final failedTitle = r.usesBaseline ? t.newIssues : t.failed;
  final emptyText = r.usesBaseline ? t.noNewIssues : t.noIssues;

  final probeView = ProbeView.of(r, lang);
  final probe = StringBuffer();
  if (probeView != null) {
    probe.writeln('<h2>🧪 ${_e(probeView.heading)}</h2><section class="card">');
    if (probeView.message != null) probe.writeln('<p>⏸️ ${_e(probeView.message!)}</p>');
    if (probeView.details.isNotEmpty) probe.writeln('<pre>${_e(probeView.details.join('\n'))}</pre>');
    if (probeView.baseline != null) probe.writeln('<p>${_e(probeView.baseline!)}</p>');
    if (probeView.lines.isNotEmpty) {
      probe.writeln('<table class="probe"><tr><th>${_e(t.probeCheck)}</th><th>${_e(t.result)}</th>'
          '<th>${_e(t.probeObserved)}</th><th>MASVS · MASTG</th><th>${_e(t.rules)}</th></tr>');
      for (final l in probeView.lines) {
        final color = switch (l.status) {
          ProbeStatus.blocked => 'var(--ok)',
          ProbeStatus.notBlocked => 'var(--bad)',
          ProbeStatus.inconclusive => 'var(--warn)',
        };
        probe.writeln('<tr><td>${_e(l.title)}</td><td style="color:$color;text-align:center">${_e(l.mark)}</td>'
            '<td>${_e(l.evidence)}${l.note == null ? '' : '<div class="muted">${_e(l.note!)}</div>'}</td>'
            '<td class="muted">${_e(l.tag)}</td><td><code>${_e(l.ruleId ?? '')}</code></td></tr>');
      }
      probe.writeln('</table>');
    }
    if (probeView.caveats.isNotEmpty) {
      probe.writeln('<ul class="muted">${probeView.caveats.map((c) => '<li>${_e(c)}</li>').join()}</ul>');
    }
    probe.writeln('</section>');
  }

  final passed = r.passed.map((x) => '<li>✓ ${_e(x.meta.passTitle.of(lang))} <code>${x.meta.id}</code></li>').join();
  final manual = r.manual.map((m) => '<li>${_e(m.text.of(lang))} <code>${m.masvs}</code></li>').join();

  final incomplete = r.incomplete.isEmpty ? '' : '<h2>${L10n(lang).incompleteChecks}</h2><ul>'
      '${r.incomplete.map((res) => '<li>${_e(res.meta.id)} · ${_e(res.noteOf(lang) ?? res.meta.title.of(lang))}</li>').join()}</ul>';
  return '''<!doctype html>
<html lang="$lang" dir="$dir">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${_e(t.title)} – ${_e(r.projectName)}</title>
<style>
:root{--bg:#f7f8fa;--fg:#1c2330;--muted:#667085;--card:#fff;--line:#e4e7ec;--ok:#12b76a;--warn:#f79009;--bad:#f04438;--accent:#3e63dd}
@media (prefers-color-scheme:dark){:root{--bg:#0f1218;--fg:#e6e9ef;--muted:#98a2b3;--card:#171b24;--line:#2a3140}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Tahoma,sans-serif}
main{max-width:920px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:32px 0 12px}
.muted{color:var(--muted)}.hero{display:flex;gap:24px;align-items:center;flex-wrap:wrap;background:var(--card);border:1px solid var(--line);border-radius:14px;padding:20px;margin-top:16px}
.ring{width:120px;height:120px;border-radius:50%;display:grid;place-items:center;background:conic-gradient($scoreColor ${r.score.value * 3.6}deg,var(--line) 0)}
.ring div{width:96px;height:96px;border-radius:50%;background:var(--card);display:grid;place-items:center;text-align:center}
.ring b{font-size:30px;line-height:1}.cat{display:grid;grid-template-columns:170px 1fr 36px;gap:10px;align-items:center;margin:6px 0}.cat small{display:block;font-size:11.5px}
.bar{height:8px;background:var(--line);border-radius:6px;overflow:hidden}.bar i{display:block;height:100%}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:12px 16px;margin:10px 0}
summary{cursor:pointer}pre{white-space:pre-wrap;background:var(--bg);padding:6px 8px;border-radius:6px;margin:4px 0;font-size:13px}
code{font-size:12.5px;color:var(--muted)}.fix{border-inline-start:3px solid var(--ok);padding-inline-start:10px}
.sev{font-size:11.5px;font-weight:700;padding:2px 8px;border-radius:20px;color:#fff}
.sev-critical{background:#b42318}.sev-high{background:var(--bad)}.sev-medium{background:var(--warn)}.sev-low{background:var(--accent)}.sev-info{background:var(--muted)}
ul{padding-inline-start:20px}.known{opacity:.7}.tag{font-size:11px;border:1px solid var(--line);border-radius:10px;padding:0 6px;color:var(--muted)}.note{font-size:13px;color:var(--muted);margin-top:32px}
.probe{width:100%;border-collapse:collapse;font-size:14px}.probe th,.probe td{border-bottom:1px solid var(--line);padding:6px 8px;text-align:start;vertical-align:top}
</style>
</head>
<body><main>
<h1>🛡 ${_e(t.title)}</h1>
<div class="muted">${_e(r.projectName)} · ${_e(t.profile)}: <b>${r.profile}</b> · aegis ${r.version} · ${r.generatedAt.toIso8601String().substring(0, 16).replaceFirst('T', ' ')}</div>
<section class="hero">
<div class="ring"><div><span><b>${r.score.value}</b><br><span class="muted">${r.score.grade}</span></span></div></div>
<div style="flex:1;min-width:240px">
<div><b>${_e(t.score)}</b>${[t.band(r.score), t.bestFixes(r.score)].whereType<String>().map((x) => '<div class="muted">${_e(x)}</div>').join()}</div>
<div class="muted">${_e(t.coverage)}: ${_e(t.coverageLine(r.coverage.checked, r.coverage.inScope, r.coverage.percent))}</div>
${_binaryHtml(r, t)}
$baselineLine
${cats.toString()}
</div>
</section>
${probe.toString()}
${r.iosStatic == null ? '' : IosStaticView(r.iosStatic!, lang).html()}
${SecurityView(r.securityEvidence, lang).html()}
$incomplete
<h2>✗ ${_e(failedTitle)} (${newFailed.length})</h2>
${newFailed.isEmpty ? '<p>${_e(emptyText)}</p>' : ''}${failed.toString()}
$resolved
<h2>✓ ${_e(t.passed)} (${r.passed.length})</h2>
<ul>$passed</ul>
<h2>? ${_e(t.manual)}</h2>
<ul>$manual</ul>
<p class="note">${_e(t.disclaimer)}</p>
</main></body></html>
''';
}
