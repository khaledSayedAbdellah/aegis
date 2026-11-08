/// Renders a [ProbeReport] for the console, en/ar (docs/plans/probe.md §3).
library;

import 'probe_model.dart';

String _t(String lang, String en, String ar) => lang == 'ar' ? ar : en;

String _mark(ProbeStatus s) => switch (s) {
      ProbeStatus.blocked => '✅',
      ProbeStatus.notBlocked => '❌',
      ProbeStatus.inconclusive => '⏸️ ',
    };

String _title(ProbeCheck c, String lang) {
  if (lang != 'ar') return c.title;
  return switch (c.id) {
    'baseline' => 'التشغيل الأساسي',
    'root' => 'كشف الـ root',
    'debugger' => 'كشف الـ debugger',
    'hooking' => 'كشف الـ instrumentation‏ (Frida)',
    'repackage' => 'كشف إعادة التحزيم / العبث',
    _ => c.title,
  };
}

String _evidence(ProbeResult r, String lang) {
  if (lang != 'ar') return r.evidence;
  return switch (r.status) {
    ProbeStatus.blocked => 'التطبيق صدّ الحالة',
    ProbeStatus.notBlocked => 'التطبيق فضل شغّال عادي',
    ProbeStatus.inconclusive => 'مش قادر يحدد',
  };
}

/// [resilienceProfile] is whether the active profile includes MAS-R; when it
/// doesn't, a gap is informational rather than a failure.
String renderProbe(ProbeReport r,
    {String lang = 'en', required bool resilienceProfile}) {
  final b = StringBuffer();
  final appName = r.app.split(RegExp(r'[\\/]')).last;
  b.writeln(_t(lang, 'Resilience probe — $appName', 'اختبار الحماية — $appName'));

  if (r.emulatorError != null) {
    b.writeln('  ⏸️  ${_t(lang, 'The emulator or tools could not run.', 'الإيموليتر أو الأدوات مقدرتش تشتغل.')}');
    b.writeln('     ${r.emulatorError}');
    b.writeln('');
    b.writeln(_t(lang,
        'Nothing was probed. Check that "aegis setup" finished, then make sure the aegis-probe emulator boots (you can run it once from Android Studio\'s Device Manager).',
        'مفيش حاجة اتفحصت. اتأكد إن "aegis setup" خلص، وإن إيموليتر aegis-probe بيقلّع (جرّبه مرة من Device Manager في Android Studio).'));
    return b.toString();
  }

  final baseline = r.results.firstWhere((x) => x.check.id == 'baseline',
      orElse: () => ProbeResult(checkById('baseline'), ProbeStatus.inconclusive));
  if (!r.baselineAlive) {
    b.writeln('  ⏸️  ${_t(lang, 'Baseline: the app did not stay alive on a clean emulator.', 'الأساس: التطبيق مكملش شغّال على إيموليتر نضيف.')}');
    if (r.baselineNote != null && r.baselineNote!.trim().isNotEmpty) {
      b.writeln(_t(lang, '     last logcat lines:', '     آخر سطور logcat:'));
      for (final line in r.baselineNote!.split('\n')) {
        b.writeln('       $line');
      }
    }
    for (final x in r.scored) {
      b.writeln('  ⏸️  ${_title(x.check, lang)} — ${x.note ?? _evidence(x, lang)}');
    }
    b.writeln('');
    b.writeln(_t(lang,
        'Inconclusive: a RASP that refuses to run on an emulator cannot be probed this way. Try a physical device, or a build without emulator-blocking.',
        'غير حاسم: حماية بترفض تشتغل على إيموليتر مش ممكن تختبرها بالطريقة دي. جرّب جهاز حقيقي، أو نسخة من غير منع الإيموليتر.'));
    return b.toString();
  }

  b.writeln('  ✅ ${_title(baseline.check, lang)}  ${_evidence(baseline, lang)}');
  final w = r.scored
      .map((x) => _title(x.check, lang).length)
      .fold(0, (a, b) => a > b ? a : b);
  for (final x in r.scored) {
    final tag = '${x.check.masvs} · ${x.check.mastg}';
    b.writeln('  ${_mark(x.status)} ${_title(x.check, lang).padRight(w)}  ${_evidence(x, lang).padRight(26)}  $tag');
    if (x.note != null) b.writeln('       ${x.note}');
  }

  b.writeln('');
  final reacted = r.blocked.length;
  final gaps = r.notBlocked.length;
  final unknown = r.inconclusive.length;
  b.writeln(_t(lang,
      'Reacted: $reacted   No reaction: $gaps   Inconclusive: $unknown',
      'صدّ: $reacted   مصدّش: $gaps   غير حاسم: $unknown'));

  if (gaps > 0) {
    b.writeln(resilienceProfile
        ? _t(lang,
            '❌ The protection did not react to $gaps condition(s). For a resilience profile this is a finding.',
            '❌ الحماية مردتش على $gaps حالة. ده يُعدّ مشكلة في profile المقاومة.')
        : _t(lang,
            'ℹ️  The protection did not react to $gaps condition(s). Informational: this profile does not require MAS-R.',
            'ℹ️  الحماية مردتش على $gaps حالة. للعلم بس: الـ profile ده مش مطالب بـ MAS-R.'));
  }

  b.writeln('');
  b.writeln(_t(lang, 'Notes:', 'ملاحظات:'));
  b.writeln(_t(lang,
      '• A report-only RASP (one that silently logs to a backend and keeps running) cannot be seen from the device; it shows as no reaction.',
      '• الحماية اللي بتبلّغ السيرفر بصمت وتفضل شغّالة مش بتبان من الجهاز؛ بتظهر كأنها مردتش.'));
  b.writeln(_t(lang,
      '• This shows what happened on this emulator and this build, not a proof of security.',
      '• ده بيوضّح اللي حصل على الإيموليتر ده والنسخة دي، مش إثبات أمان.'));
  return b.toString();
}

/// Exit code: 2 when nothing could be observed, 1 when a resilience profile
/// has a real gap, else 0.
int probeExitCode(ProbeReport r, {required bool resilienceProfile}) {
  if (r.emulatorError != null) return 2;
  if (!r.baselineAlive) return 2;
  if (r.scored.every((x) => x.status == ProbeStatus.inconclusive)) return 2;
  if (resilienceProfile && r.notBlocked.isNotEmpty) return 1;
  return 0;
}
