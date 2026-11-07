/// Self-contained HTML report to share with people who don't use a terminal.
library;

import 'dart:convert';

import '../engine.dart';
import '../masvs.dart';
import '../model.dart';
import 'i18n.dart';

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
  final b = StringBuffer('$pkgs<div class="muted">${_e(t.binary)}: <code>${_e(bin.file)}</code> ${_e(bin.packageName ?? '')} ${_e(bin.versionName ?? '')}</div>');
  for (final c in bin.certificates) {
    b.write('<div class="muted">${_e(t.signer)}: ${_e(c.commonName ?? '?')} (${c.scheme})<br>${_e(t.certHash)}: <code>${_e(c.sha256Base64)}</code></div>');
  }
  return b.toString();
}

String renderHtml(AuditReport r, {String lang = 'en'}) {
  final t = Strings(lang);
  final dir = t.ar ? 'rtl' : 'ltr';
  final scoreColor = r.score.value >= 80
      ? 'var(--ok)'
      : r.score.value >= 60
          ? 'var(--warn)'
          : 'var(--bad)';

  String sevClass(Severity s) => 'sev sev-${s.name}';

  final failed = StringBuffer();
  for (final res in r.failed) {
    final m = res.meta;
    failed.writeln('<details class="card" open>');
    failed.writeln('<summary><span class="${sevClass(res.severity)}">${_e(t.severity(res.severity))}</span> '
        '<strong>${_e(m.title.of(lang))}</strong> <code>${m.id}</code></summary>');
    failed.writeln('<p class="muted">${_e([...m.masvs, ...m.maswe, if (m.cwe != null) m.cwe!].join(' · '))}</p>');
    failed.writeln('<ul>');
    for (final f in res.findings) {
      failed.writeln('<li>${f.location.isEmpty ? '' : '<code>${_e(f.location)}</code> '}${_e(f.messageOf(lang))}'
          '${f.snippet == null ? '' : '<pre>${_e(f.snippet!)}</pre>'}</li>');
    }
    failed.writeln('</ul>');
    failed.writeln('<p><b>${_e(t.why)}:</b> ${_e(m.description.of(lang))}</p>');
    failed.writeln('<p class="fix"><b>${_e(t.fix)}:</b> ${_e(m.fix.of(lang))}</p>');
    failed.writeln('</details>');
  }

  final cats = StringBuffer();
  for (final c in r.score.categories.values) {
    final color = c.score >= 80 ? 'var(--ok)' : c.score >= 60 ? 'var(--warn)' : 'var(--bad)';
    cats.writeln('<div class="cat"><span>${_e(masvsCategories[c.category]?.of(lang) ?? c.category)}</span>'
        '<div class="bar"><i style="width:${c.score}%;background:$color"></i></div><b>${c.score}</b></div>');
  }

  final passed = r.passed.map((x) => '<li>✓ ${_e(x.meta.passTitle.of(lang))} <code>${x.meta.id}</code></li>').join();
  final manual = r.manual.map((m) => '<li>${_e(m.text.of(lang))} <code>${m.masvs}</code></li>').join();

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
.ring b{font-size:30px;line-height:1}.cat{display:grid;grid-template-columns:150px 1fr 36px;gap:10px;align-items:center;margin:6px 0}
.bar{height:8px;background:var(--line);border-radius:6px;overflow:hidden}.bar i{display:block;height:100%}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:12px 16px;margin:10px 0}
summary{cursor:pointer}pre{white-space:pre-wrap;background:var(--bg);padding:6px 8px;border-radius:6px;margin:4px 0;font-size:13px}
code{font-size:12.5px;color:var(--muted)}.fix{border-inline-start:3px solid var(--ok);padding-inline-start:10px}
.sev{font-size:11.5px;font-weight:700;padding:2px 8px;border-radius:20px;color:#fff}
.sev-critical{background:#b42318}.sev-high{background:var(--bad)}.sev-medium{background:var(--warn)}.sev-low{background:var(--accent)}.sev-info{background:var(--muted)}
ul{padding-inline-start:20px}.note{font-size:13px;color:var(--muted);margin-top:32px}
</style>
</head>
<body><main>
<h1>🛡 ${_e(t.title)}</h1>
<div class="muted">${_e(r.projectName)} · ${_e(t.profile)}: <b>${r.profile}</b> · aegis ${r.version} · ${r.generatedAt.toIso8601String().substring(0, 16).replaceFirst('T', ' ')}</div>
<section class="hero">
<div class="ring"><div><span><b>${r.score.value}</b><br><span class="muted">${r.score.grade}</span></span></div></div>
<div style="flex:1;min-width:240px">
<div><b>${_e(t.score)}</b>${r.score.capReason == null ? '' : ' <span class="muted">(${_e(t.capped(t.severity(r.score.capReason == 'critical' ? Severity.critical : Severity.high)))})</span>'}</div>
<div class="muted">${_e(t.coverage)}: ${_e(t.coverageLine(r.coverage.checked, r.coverage.inScope, r.coverage.percent))}</div>
${_binaryHtml(r, t)}
${cats.toString()}
</div>
</section>
<h2>✗ ${_e(t.failed)} (${r.failed.length})</h2>
${r.failed.isEmpty ? '<p>${_e(t.noIssues)}</p>' : failed.toString()}
<h2>✓ ${_e(t.passed)} (${r.passed.length})</h2>
<ul>$passed</ul>
<h2>? ${_e(t.manual)}</h2>
<ul>$manual</ul>
<p class="note">${_e(t.disclaimer)}</p>
</main></body></html>
''';
}
