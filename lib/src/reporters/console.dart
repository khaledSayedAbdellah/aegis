/// Human-readable terminal report.
library;

import '../l10n/messages.g.dart';
import '../engine.dart';
import '../masvs.dart';
import '../model.dart';
import '../probe/probe_model.dart';
import '../scoring.dart';
import 'i18n.dart';
import 'probe_view.dart';
import 'ios_static_view.dart';
import 'security_view.dart';

class ConsoleReporter {
  ConsoleReporter({this.lang = 'en', this.color = true, this.verbose = false});

  final String lang;
  final bool color;

  /// Also list passed and not-applicable rules.
  final bool verbose;

  String _c(String code, String s) => color ? '\x1B[${code}m$s\x1B[0m' : s;
  String _bold(String s) => _c('1', s);
  String _dim(String s) => _c('2', s);
  String _red(String s) => _c('31', s);
  String _green(String s) => _c('32', s);
  String _yellow(String s) => _c('33', s);
  String _cyan(String s) => _c('36', s);

  String _sev(Severity s, String text) {
    switch (s) {
      case Severity.critical:
        return _c('1;41;97', ' $text ');
      case Severity.high:
        return _c('1;31', text);
      case Severity.medium:
        return _c('33', text);
      case Severity.low:
        return _c('36', text);
      case Severity.info:
        return _dim(text);
    }
  }

  /// Coloured like the band: green up to low problems, yellow for medium,
  /// red for high and critical.
  String _gradeColor(Score s, String text, {bool provisional = false}) => switch (s.worst) {
        null || Severity.low || Severity.info => _c(provisional ? '1;33' : '1;32', text),
        Severity.medium => _c('1;33', text),
        _ => _c('1;31', text),
      };

  String render(AuditReport r) {
    final t = Strings(lang);
    final b = StringBuffer();
    final line = _dim('─' * 64);

    b.writeln();
    b.writeln(_bold('🛡  ${t.title}  ·  aegis ${r.version}'));
    b.writeln(line);
    b.writeln('${t.project}: ${_bold(r.projectName)}');
    b.writeln('${t.profile}: ${_bold(r.profile.toString())}');
    if (r.scannedPackages.isNotEmpty) {
      b.writeln('${t.packages}: ${r.scannedPackages.join(', ')}');
    }
    final bin = r.binary;
    if (bin != null) {
      final ver = [bin.versionName, if (bin.versionCode != null) '(${bin.versionCode})'].whereType<String>().join(' ');
      b.writeln('${t.binaryKind(bin.kind)}: ${_bold(bin.file)}  ${_dim([bin.packageName, ver, if (bin.abis.isNotEmpty) bin.abis.join('/')].whereType<String>().where((x) => x.isNotEmpty).join(' · '))}');
      for (final c in bin.certificates) {
        b.writeln('${t.signer}: ${c.commonName ?? '?'} ${_dim('(${c.scheme})')}');
        if (bin.kind == 'AAB') b.writeln(_dim('  ↳ ${t.uploadKey}'));
        b.writeln('  ${t.certHash(bin.kind)}: ${_cyan(c.sha256Base64)}');
      }
    }
    b.writeln();

    final bar = _scoreBar(r.score, provisional: !r.complete);
    b.writeln('${t.score}: ${_gradeColor(r.score, '${r.score.value}/100 (${r.score.grade})', provisional: !r.complete)}  $bar');
    if (!r.complete) {
      b.writeln(_yellow('  ${L10n(lang).scoreProvisional}'));
      b.writeln('  ${L10n(lang).scoreProvisionalDetail}');
    }
    final band = t.band(r.score);
    if (band != null) b.writeln(_dim('  ↳ $band'));
    final fixes = t.bestFixes(r.score);
    if (fixes != null) b.writeln(_dim('  ↳ $fixes'));
    b.writeln('${t.coverage}: ${t.coverageLine(r.coverage.checked, r.coverage.inScope, r.coverage.percent)}');
    b.writeln();

    if (r.score.categories.isNotEmpty) {
      b.writeln(_bold(t.categories));
      final cats = r.score.categories.values.toList()
        ..sort((x, y) => x.score.compareTo(y.score));
      for (final c in cats) {
        final name = (masvsCategories[c.category]?.of(lang) ?? c.category).padRight(22);
        final s = '${c.score}'.padLeft(3);
        // Coloured by the worst open problem, not by the number: a category
        // at 80 with a high finding is not healthy.
        final colored = switch (c.worst) {
          null => _green(s),
          Severity.critical || Severity.high => _red(s),
          Severity.medium => _yellow(s),
          _ => _cyan(s),
        };
        final open = c.failedRuleIds.isEmpty ? '' : '  ${c.failedRuleIds.join(', ')}';
        b.writeln('  $name $colored  ${_dim('${c.checked - c.failed}/${c.checked}$open')}');
      }
      b.writeln();
    }

    if (r.iosStatic != null) b.write(IosStaticView(r.iosStatic!, lang).console());
  b.write(SecurityView(r.securityEvidence, lang).console());

    final probe = ProbeView.of(r, lang);
    if (probe != null) {
      b.writeln(_bold(probe.heading));
      if (probe.message != null) b.writeln('  ⏸️  ${probe.message}');
      for (final d in probe.details) {
        b.writeln(_dim('     $d'));
      }
      if (probe.baseline != null) b.writeln('  ${probe.baseline}');
      final w = probe.lines.map((l) => l.title.length).fold(0, (a, x) => a > x ? a : x);
      for (final l in probe.lines) {
        final mark = switch (l.status) {
          ProbeStatus.blocked => _green(l.mark),
          ProbeStatus.notBlocked => _red(l.mark),
          ProbeStatus.inconclusive => _yellow(l.mark),
        };
        b.writeln('  $mark ${l.title.padRight(w)}  ${l.evidence}  ${_dim('${l.tag}${l.ruleId == null ? '' : ' · ${l.ruleId}'}')}');
        if (l.note != null) b.writeln(_dim('       ${l.note}'));
      }
      for (final c in probe.caveats) {
        b.writeln(_dim('  • $c'));
      }
      b.writeln();
    }

    if (r.usesBaseline) {
      b.writeln('${t.baseline}: ${t.baselineLine(r.knownFindingCount, r.newFindingCount, r.resolvedCount)}  ${_dim(r.baselinePath!)}');
      b.writeln();
    }

    final failed = r.newFailed.toList();
    final heading = r.usesBaseline ? t.newIssues : t.failed;
    b.writeln(_bold('${_red('✗')} $heading (${failed.length})'));
    b.writeln(line);
    if (failed.isEmpty) b.writeln(_green('  ${r.usesBaseline ? t.noNewIssues : t.noIssues}'));
    var n = 0;
    for (final res in failed) {
      n++;
      final m = res.meta;
      final fresh = res.newFindings;
      final knownCount = res.findings.length - fresh.length;
      b.writeln('${_bold('[$n]')} ${_sev(res.severity, t.severity(res.severity))} '
          '${_bold(m.title.of(lang))} ${_dim('${m.id} · ${m.masvs.join(', ')}')}');
      for (final f in fresh.take(verbose ? 1000 : 5)) {
        final loc = f.location.isEmpty ? '' : _cyan(f.location);
        b.writeln('    • ${loc.isEmpty ? '' : '$loc  '}${f.messageOf(lang)}');
        if (f.snippet != null && f.snippet!.isNotEmpty) {
          b.writeln(_dim('      ${f.snippetOf(lang)}'));
        }
      }
      if (!verbose && fresh.length > 5) {
        b.writeln(_dim('    … +${fresh.length - 5} (--verbose)'));
      }
      if (knownCount > 0) b.writeln(_dim('    + ${t.knownCount(knownCount)}'));
      b.writeln('    ${_yellow('${t.why}:')} ${m.description.of(lang)}');
      b.writeln('    ${_green('${t.fix}:')} ${m.fix.of(lang)}');
      if (res.suppressed > 0) {
        b.writeln(_dim('    (${res.suppressed} ${t.suppressed})'));
      }
      b.writeln();
    }

    final known = r.failed.where((x) => !x.hasNew).toList();
    if (known.isNotEmpty) {
      b.writeln(_bold('${_dim('≈')} ${t.known} (${known.length})'));
      b.writeln(line);
      for (final res in known) {
        b.writeln('  ${_sev(res.severity, t.severity(res.severity))} ${res.meta.title.of(lang)} '
            '${_dim('${res.meta.id} · ${t.knownCount(res.findings.length)}')}');
        if (verbose) {
          for (final f in res.findings) {
            b.writeln(_dim('      • ${f.location.isEmpty ? '' : '${f.location}  '}${f.messageOf(lang)}'));
          }
        }
      }
      b.writeln(_dim('  ${t.knownHint}'));
      b.writeln();
    }

    if (r.baselineResolved.isNotEmpty) {
      b.writeln(_bold('${_green('↓')} ${t.resolved} (${r.resolvedCount})'));
      b.writeln(line);
      for (final e in r.baselineResolved.take(verbose ? 1000 : 10)) {
        b.writeln('  ${_green('✓')} ${_dim(e.ruleId)} ${e.file == null ? '' : '${_cyan(e.file!)}  '}${e.message}');
      }
      if (!verbose && r.baselineResolved.length > 10) {
        b.writeln(_dim('  … +${r.baselineResolved.length - 10} (--verbose)'));
      }
      b.writeln(_dim('  ${t.updateHint}'));
      b.writeln();
    }

    final passed = r.passed.toList();
    b.writeln(_bold('${_green('✓')} ${t.passed} (${passed.length})'));
    b.writeln(line);
    for (final res in passed) {
      b.writeln('  ${_green('✓')} ${res.meta.passTitle.of(lang)} ${_dim(res.meta.id)}');
    }
    b.writeln();

    if (r.incomplete.isNotEmpty) {
      b.writeln(_bold(L10n(lang).incompleteChecks));
      for (final res in r.incomplete) {
        b.writeln('  ? ${res.meta.id} · ${res.noteOf(lang) ?? res.meta.title.of(lang)}');
      }
      b.writeln();
    }

    if (r.evidenceOnly.isNotEmpty) {
      b.writeln(_bold('${t.evidenceOnly} (${r.evidenceOnly.length})'));
      for (final res in r.evidenceOnly) {
        b.writeln('  · ${res.meta.id} · ${res.meta.title.of(lang)}');
      }
      b.writeln();
    }

    if (verbose) {
      final na = r.notApplicable.toList();
      b.writeln(_bold('– ${t.notApplicable} (${na.length})'));
      b.writeln(line);
      for (final res in na) {
        b.writeln('  – ${res.meta.title.of(lang)} ${_dim('${res.meta.id}${res.note == null ? '' : ' · ${res.noteOf(lang)}'}')}');
      }
      b.writeln();
    }

    b.writeln(_bold('${_yellow('?')} ${t.manual}'));
    b.writeln(line);
    for (final m in r.manual) {
      b.writeln('  ? ${m.text.of(lang)} ${_dim('${m.id} · ${m.masvs}')}');
    }
    b.writeln();
    if (r.suppressed > 0) {
      b.writeln(_dim('${r.suppressed} ${t.suppressed}'));
    }
    b.writeln(_dim(t.disclaimer));
    b.writeln();
    return b.toString();
  }

  String _scoreBar(Score s, {bool provisional = false}) {
    final filled = (s.value / 5).round();
    return _gradeColor(s, '█' * filled + '░' * (20 - filled), provisional: provisional);
  }
}
