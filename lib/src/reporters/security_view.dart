import 'dart:convert';
import '../security/evidence.dart';
import '../security/metadata.dart';
import '../l10n/messages.g.dart';

class SecurityView {
  SecurityView(this.evidence, this.lang);
  final List<SecurityEvidence> evidence;
  final String lang;
  L10n get t => L10n(lang);
  String status(SecurityEvidence e) => switch (e.status) {
        'unavailable' => t.extUnavailable,
        'facts' => t.extFacts,
        _ => t.extObserved,
      };
  String safe(String s) => s.replaceAll(RegExp(r'[\x00-\x1f\x7f-\x9f]'), ' ');
  String console() => evidence.isEmpty
      ? ''
      : '\n${t.extEvidenceHeading}\n${t.extEvidenceScope}\n${evidence.map((e) => '  ${e.ruleId} ${status(e)}: ${safe(e.file)}\n    ${safe(e.detail.of(lang))}').join('\n')}\n';
  String html() {
    if (evidence.isEmpty) return '';
    final esc = const HtmlEscape().convert;
    return '<section><h2>${esc(t.extEvidenceHeading)}</h2><p>${esc(t.extEvidenceScope)}</p>${evidence.map((e) => '<details class="card"><summary>${esc(e.ruleId)} · ${esc(extendedMeta(e.ruleId).title.of(lang))} · ${esc(status(e))}</summary><p>${esc(e.file)}</p><pre>${esc(e.detail.of(lang))}</pre></details>').join()}</section>';
  }

  String markdown() {
    if (evidence.isEmpty) return '';
    String esc(String s) => safe(s).replaceAllMapped(
        RegExp(r'([\\`*_{}\[\]()#+.!|<>])'), (m) => '\\${m[0]}');
    return '\n## ${t.extEvidenceHeading}\n\n${t.extEvidenceScope}\n\n${evidence.map((e) => '- ${e.ruleId} · ${status(e)} · ${esc(e.file)}: ${esc(e.detail.of(lang))}').join('\n')}\n\n';
  }
}
