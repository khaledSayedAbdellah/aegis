import 'dart:convert';
import '../model.dart';
import '../security/evidence.dart';
import '../security/metadata.dart';
import '../l10n/messages.g.dart';

class SecurityView {
  SecurityView(this.evidence, this.lang, {this.titles = const {}});
  final List<SecurityEvidence> evidence;
  final String lang;

  /// Titles of the rules that ran, by id: evidence can come from any rule.
  final Map<String, Bilingual> titles;
  L10n get t => L10n(lang);
  String status(SecurityEvidence e) => switch (e.status) {
        'unavailable' => t.extUnavailable,
        'facts' => t.extFacts,
        _ => t.extObserved,
      };
  String title(String id) {
    if (id == 'AEG-P01') return t.raspEvidenceTitle;
    final known = titles[id];
    if (known != null) return known.of(lang);
    try {
      return extendedMeta(id).title.of(lang);
    } on ArgumentError {
      return id;
    }
  }

  String safe(String s) => s.replaceAll(RegExp(r'[\x00-\x1f\x7f-\x9f]'), ' ');
  String console() => evidence.isEmpty
      ? ''
      : '\n${t.extEvidenceHeading}\n${t.extEvidenceScope}\n${evidence.map((e) => '  ${e.ruleId} ${status(e)}: ${safe(e.file)}\n    ${safe(e.detail.of(lang))}').join('\n')}\n';

  // Group presentation only: preserve every observation, its status and source.
  // A group has no aggregate verdict; evidence is not a pass/fail result.
  Map<String, List<SecurityEvidence>> get _groups {
    final groups = <String, List<SecurityEvidence>>{};
    for (final item in evidence) {
      (groups[item.ruleId] ??= []).add(item);
    }
    return groups;
  }

  String html() {
    if (evidence.isEmpty) return '';
    final esc = const HtmlEscape().convert;
    final out = StringBuffer(
        '<section><h2>${esc(t.extEvidenceHeading)}</h2><p>${esc(t.extEvidenceScope)}</p>');
    for (final group in _groups.entries) {
      out.write('<details class="card evidence-group"><summary>'
          '<bdi dir="ltr">${esc(group.key)}</bdi> · '
          '${esc(title(group.key))} · '
          '${esc(t.extEvidenceCount(count: group.value.length))}'
          '</summary><ul class="evidence-items">');
      for (final item in group.value) {
        out.write(
            '<li class="evidence-item"><p><strong>${esc(status(item))}</strong>'
            ' · <bdi>${esc(item.file)}</bdi></p>'
            '<pre>${esc(item.detail.of(lang))}</pre></li>');
      }
      out.write('</ul></details>');
    }
    out.write('</section>');
    return out.toString();
  }

  String markdown() {
    if (evidence.isEmpty) return '';
    String esc(String s) => safe(s).replaceAllMapped(
        RegExp(r'([\\`*_{}\[\]()#+.!|<>])'), (m) => '\\${m[0]}');
    final out =
        StringBuffer('\n## ${t.extEvidenceHeading}\n\n${t.extEvidenceScope}\n');
    for (final group in _groups.entries) {
      out.writeln(
          '\n### ${esc(group.key)} · ${esc(title(group.key))} · ${esc(t.extEvidenceCount(count: group.value.length))}\n');
      for (final item in group.value) {
        out.writeln(
            '- ${status(item)} · ${esc(item.file)}: ${esc(item.detail.of(lang))}');
      }
    }
    return '$out\n';
  }
}
