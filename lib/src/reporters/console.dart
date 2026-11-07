/// Human-readable terminal report.
library;

import '../engine.dart';
import '../masvs.dart';
import '../model.dart';
import '../scoring.dart';
import 'i18n.dart';

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

  String _gradeColor(Score s, String text) {
    if (s.value >= 80) return _c('1;32', text);
    if (s.value >= 60) return _c('1;33', text);
    return _c('1;31', text);
  }

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
      b.writeln('${t.binary}: ${_bold(bin.file)}  ${_dim([bin.packageName, ver, if (bin.abis.isNotEmpty) bin.abis.join('/')].whereType<String>().where((x) => x.isNotEmpty).join(' · '))}');
      for (final c in bin.certificates) {
        b.writeln('${t.signer}: ${c.commonName ?? '?'} ${_dim('(${c.scheme})')}');
        b.writeln('  ${t.certHash}: ${_cyan(c.sha256Base64)}');
      }
    }
    b.writeln();

    final bar = _scoreBar(r.score.value);
    b.writeln('${t.score}: ${_gradeColor(r.score, '${r.score.value}/100 (${r.score.grade})')}  $bar');
    if (r.score.capReason != null) {
      b.writeln(_dim('  ↳ ${t.capped(t.severity(r.score.capReason == 'critical' ? Severity.critical : Severity.high))}'));
    }
    b.writeln('${t.coverage}: ${t.coverageLine(r.coverage.checked, r.coverage.inScope, r.coverage.percent)}');
    b.writeln();

    if (r.score.categories.isNotEmpty) {
      b.writeln(_bold(t.categories));
      final cats = r.score.categories.values.toList()
        ..sort((x, y) => x.score.compareTo(y.score));
      for (final c in cats) {
        final name = (masvsCategories[c.category]?.of(lang) ?? c.category).padRight(22);
        final s = '${c.score}'.padLeft(3);
        b.writeln('  $name ${_gradeColor(Score(c.score, const {}), s)}  ${_dim('${c.checked - c.failed}/${c.checked}')}');
      }
      b.writeln();
    }

    final failed = r.failed.toList();
    b.writeln(_bold('${_red('✗')} ${t.failed} (${failed.length})'));
    b.writeln(line);
    if (failed.isEmpty) b.writeln(_green('  ${t.noIssues}'));
    var n = 0;
    for (final res in failed) {
      n++;
      final m = res.meta;
      b.writeln('${_bold('[$n]')} ${_sev(res.severity, t.severity(res.severity))} '
          '${_bold(m.title.of(lang))} ${_dim('${m.id} · ${m.masvs.join(', ')}')}');
      for (final f in res.findings.take(verbose ? 1000 : 5)) {
        final loc = f.location.isEmpty ? '' : _cyan(f.location);
        b.writeln('    • ${loc.isEmpty ? '' : '$loc  '}${f.messageOf(lang)}');
        if (f.snippet != null && f.snippet!.isNotEmpty) {
          b.writeln(_dim('      ${f.snippet}'));
        }
      }
      if (!verbose && res.findings.length > 5) {
        b.writeln(_dim('    … +${res.findings.length - 5} (--verbose)'));
      }
      b.writeln('    ${_yellow('${t.why}:')} ${m.description.of(lang)}');
      b.writeln('    ${_green('${t.fix}:')} ${m.fix.of(lang)}');
      if (res.suppressed > 0) {
        b.writeln(_dim('    (${res.suppressed} ${t.suppressed})'));
      }
      b.writeln();
    }

    final passed = r.passed.toList();
    b.writeln(_bold('${_green('✓')} ${t.passed} (${passed.length})'));
    b.writeln(line);
    for (final res in passed) {
      b.writeln('  ${_green('✓')} ${res.meta.passTitle.of(lang)} ${_dim(res.meta.id)}');
    }
    b.writeln();

    if (verbose) {
      final na = r.notApplicable.toList();
      b.writeln(_bold('– ${t.notApplicable} (${na.length})'));
      b.writeln(line);
      for (final res in na) {
        b.writeln('  – ${res.meta.title.of(lang)} ${_dim('${res.meta.id}${res.note == null ? '' : ' · ${res.note}'}')}');
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

  String _scoreBar(int v) {
    final filled = (v / 5).round();
    final bar = '█' * filled + '░' * (20 - filled);
    if (v >= 80) return _green(bar);
    if (v >= 60) return _yellow(bar);
    return _red(bar);
  }
}
