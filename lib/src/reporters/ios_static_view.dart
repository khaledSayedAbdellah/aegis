/// Shared localized presentation of static IPA evidence. Never uses probe marks.
library;

import 'dart:convert';

import '../binary/ios_static.dart';
import '../l10n/messages.g.dart';

class IosStaticView {
  IosStaticView(this.analysis, String lang) : t = L10n(lang);
  final IosStaticAnalysis analysis;
  final L10n t;
  String get heading => t.iosStaticHeading;
  List<String> get notes => [
        t.iosStaticScope,
        t.iosStaticCaveat,
        t.iosStaticSignatureCaveat,
        t.iosMetadataScope,
        if (analysis.limited) t.iosStaticLimited
      ];
  String _bool(bool value) => value ? t.iosStaticYes : t.iosStaticNo;
  String _title(String id) => switch (id) {
        'jailbreak' => t.iosStaticJailbreak,
        'debugger' => t.iosStaticDebugger,
        'hooking' => t.iosStaticHooking,
        'signing' => t.iosStaticSigning,
        'stack_canary' => t.iosStaticCanary,
        'arc' => t.iosStaticArc,
        _ => id,
      };
  Iterable<(String, String, List<String>)> get signals sync* {
    for (final signal in analysis.signals) {
      final status = switch (signal.status) {
        'observed' => t.iosStaticObserved,
        'not_observed' => t.iosStaticNotObserved,
        _ => t.iosStaticUnavailable,
      };
      yield (
        _title(signal.id),
        status,
        [
          for (final e in signal.evidence.take(12))
            '${e.file} [${e.architecture}] · ${_source(e.source)}: ${e.owner == null ? '' : '${e.owner}. '}${e.value ?? e.token}',
          if (signal.evidence.length > 12)
            t.iosStaticMore(count: signal.evidence.length - 12),
        ]
      );
    }
  }

  String _source(String source) => switch (source) {
        'symbol' => t.iosMetadataSourceSymbol,
        'string' => t.iosMetadataSourceString,
        _ => source,
      };
  String _limitation(String code) => switch (code) {
        'encrypted' => t.iosMetadataEncrypted,
        'budget' => t.iosMetadataBudget,
        'fixups' => t.iosMetadataFixups,
        'swift-mangling' => t.iosMetadataMangling,
        'swift-symbolic-reference' => t.iosMetadataSymbolic,
        _ => t.iosMetadataUnresolved,
      };

  Iterable<(String, String)> get binaries sync* {
    for (final b in analysis.binaries) {
      if (b.issue != null) yield (b.path, t.iosStaticUnreadable);
      for (final s in b.slices) {
        final entries = s.metadata.entries;
        int count(bool Function(String) match) =>
            entries.where((e) => match(e.kind)).length;
        final metadata = t.iosMetadataCounts(
          classes: count((k) => k == 'objc-class'),
          methods: count((k) =>
              k == 'objc-instance-method' ||
              k == 'objc-class-method' ||
              k == 'objc-instance-requirement' ||
              k == 'objc-class-requirement'),
          protocols:
              count((k) => k == 'objc-protocol' || k == 'swift-protocol'),
          types: count(
              (k) => {'swift-class', 'swift-struct', 'swift-enum'}.contains(k)),
          references: count(
              (k) => k.endsWith('reference') || k == 'swift-nominal-symbol'),
        );
        yield (
          '${b.path} [${s.architecture}]',
          '${t.iosStaticFactsLine(pie: s.fileType == 2 ? _bool(s.pie) : t.iosStaticNa, stack: _bool(s.executableStackRequested), wx: s.writableExecutableSegments.length, signature: _bool(s.signatureBlob), encrypted: _bool(s.encrypted), debug: s.symbolTable ? s.debugSymbols : t.iosStaticUnavailable)} $metadata ${s.metadata.limitations.map(_limitation).join(' ')}'
        );
      }
    }
  }

  String _terminalSafe(String value) =>
      value.replaceAll(RegExp(r'[\x00-\x1f\x7f-\x9f]'), '?');

  String console() {
    final b = StringBuffer('\n$heading\n');
    for (final note in notes) {
      b.writeln('  $note');
    }
    for (final (title, status, evidence) in signals) {
      b.writeln('  $title: $status');
      for (final e in evidence) {
        b.writeln('    ${_terminalSafe(e)}');
      }
    }
    for (final (path, facts) in binaries) {
      b.writeln('  ${_terminalSafe(path)}\n    $facts');
    }
    return b.toString();
  }

  String html() {
    final e = const HtmlEscape().convert;
    final b = StringBuffer('<section><h2>${e(heading)}</h2>');
    for (final note in notes) {
      b.write('<p class="muted">${e(note)}</p>');
    }
    for (final (title, status, evidence) in signals) {
      b.write(
          '<details class="card"><summary>${e(title)}: ${e(status)}</summary><ul>');
      for (final value in evidence) {
        b.write('<li><code>${e(value)}</code></li>');
      }
      b.write('</ul></details>');
    }
    b.write(
        '<details class="card"><summary>${e(t.iosStaticFacts)}</summary><table class="probe"><thead><tr><th>${e(t.iosStaticBinary)}</th><th>${e(t.iosStaticFacts)}</th></tr></thead><tbody>');
    for (final (path, facts) in binaries) {
      b.write('<tr><td><code>${e(path)}</code></td><td>${e(facts)}</td></tr>');
    }
    b.write('</tbody></table></details></section>');
    return b.toString();
  }

  String markdown() {
    // Escape artifact-controlled text before embedding in Markdown/HTML.
    String escape(String s) => const HtmlEscape()
        .convert(s)
        .replaceAll('\\', '\\\\')
        .replaceAll('`', '\\`')
        .replaceAll('*', '\\*')
        .replaceAll('_', '\\_')
        .replaceAll('[', '\\[')
        .replaceAll(']', '\\]')
        .replaceAll('|', '\\|')
        .replaceAll('\n', ' ')
        .replaceAll('\r', ' ');
    final b = StringBuffer('\n## ${escape(heading)}\n\n');
    for (final note in notes) {
      b.writeln('${escape(note)}\n');
    }
    for (final (title, status, evidence) in signals) {
      b.writeln('### ${escape(title)}: ${escape(status)}\n');
      for (final e in evidence) {
        b.writeln('- ${escape(e)}');
      }
      b.writeln();
    }
    b.writeln(
        '| ${escape(t.iosStaticBinary)} | ${escape(t.iosStaticFacts)} |\n|---|---|');
    for (final (path, facts) in binaries) {
      b.writeln('| ${escape(path)} | ${escape(facts)} |');
    }
    b.writeln();
    return b.toString();
  }
}
