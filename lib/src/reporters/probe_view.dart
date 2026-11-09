/// The resilience-probe section shared by the report formats: what ran, what
/// each check observed, and why something could not be judged.
library;

import '../engine.dart';
import '../probe/probe_model.dart';
import '../probe/probe_report.dart';

/// The rule that reports each probe check.
const probeRuleIds = {
  'root': 'AEG-R01',
  'hooking': 'AEG-R02',
  'debugger': 'AEG-R03',
  'repackage': 'AEG-R04',
};

class ProbeLine {
  ProbeLine(this.status, this.mark, this.title, this.evidence, this.tag, this.ruleId,
      {this.note});
  final ProbeStatus status;
  final String mark;
  final String title;
  final String evidence;

  /// `MASVS-RESILIENCE-1 · MASTG-TEST-0048`.
  final String tag;
  final String? ruleId;
  final String? note;
}

class ProbeView {
  ProbeView({
    required this.heading,
    required this.lines,
    required this.caveats,
    this.message,
    this.details = const [],
    this.baseline,
  });

  final String heading;

  /// Set when nothing could be judged (skipped, emulator error, the app did
  /// not stay alive on a clean emulator); [lines] is then empty.
  final String? message;

  /// Extra lines under [message] (the last logcat lines of a dead baseline).
  final List<String> details;

  /// The baseline line when the probe ran.
  final String? baseline;
  final List<ProbeLine> lines;
  final List<String> caveats;

  /// Null when the run did not try the probe.
  static ProbeView? of(AuditReport r, String lang) {
    final o = r.probe;
    if (o == null) return null;
    String t(String en, String ar) => lang == 'ar' ? ar : en;
    final caveats = [
      t('Automatic observations cover process behavior. App events describe the tested operation.',
          'الفحص التلقائي بيرصد حالة العملية، وإشارات التطبيق بتوضح نتيجة الإجراء المختبَر.'),
      t('This shows what happened on this emulator with this build, not a proof of security.',
          'ده اللي حصل على الإيموليتر ده بالنسخة دي، مش إثبات أمان.'),
    ];
    final report = o.report;
    final heading = t('Resilience probe (emulator)', 'اختبار الحماية على الإيموليتر') +
        (report == null ? '' : ' — ${report.app.split(RegExp(r'[\\/]')).last}');
    if (report == null) {
      return ProbeView(
          heading: heading,
          lines: const [],
          caveats: const [],
          message: t('Skipped: ${o.skipped}', 'اتخطّى: ${o.skipped}'));
    }
    if (report.emulatorError != null) {
      return ProbeView(
          heading: heading,
          lines: const [],
          caveats: const [],
          details: probeApkIdentityLines(report, lang),
          message: t('Could not run: ${report.emulatorError}',
              'مقدرش يشتغل: ${report.emulatorError}'));
    }
    if (!report.baselineAlive) {
      return ProbeView(
        heading: heading,
        lines: const [],
        caveats: caveats,
        message: t(
            'The app did not stay alive on a clean emulator, so no check could be judged (emulator detection, a crash or a slow first launch).',
            'التطبيق مكمّلش شغّال على إيموليتر نضيف، فمفيش فحص اتحكم عليه (كشف إيموليتر أو كراش أو تشغيل أول بطيء).'),
        details: [
          ...probeApkIdentityLines(report, lang),
          for (final l in (report.baselineNote ?? '').split('\n'))
            if (l.trim().isNotEmpty) l.trimRight(),
        ],
      );
    }
    ProbeResult? base;
    for (final x in report.results) {
      if (x.check.id == 'baseline') base = x;
    }
    return ProbeView(
      heading: heading,
      caveats: caveats,
      details: probeApkIdentityLines(report, lang),
      baseline: base == null
          ? null
          : '✅ ${probeCheckTitle(base.check, lang)}: ${probeEvidence(base, lang)}${base.note == null ? '' : ' · ${base.note}'}',
      lines: [
        for (final x in report.scored)
          ProbeLine(
            x.status,
            probeMark(x.status).trim(),
            probeCheckTitle(x.check, lang),
            probeEvidence(x, lang),
            [x.check.masvs, x.check.mastg].whereType<String>().join(' · '),
            probeRuleIds[x.check.id],
            note: x.note,
          ),
      ],
    );
  }
}
