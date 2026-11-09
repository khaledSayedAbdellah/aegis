/// Renders a [ProbeReport] for the console, en/ar (docs/plans/probe.md §3).
library;

import 'probe_model.dart';

String _t(String lang, String en, String ar) => lang == 'ar' ? ar : en;

List<String> probeApkIdentityLines(ProbeReport report, String lang) {
  final identity = report.apkIdentity;
  if (identity == null) return const [];
  final signers = identity.signerSha256.join(', ');
  return [
    _t(lang, 'Verified APK signer SHA-256: $signers', 'بصمة SHA-256 لموقّع الـAPK المتحقق منه: $signers'),
    if (identity.controlApks.isNotEmpty)
      _t(lang, 'Control APKs: ${identity.controlApks.join(', ')}',
          'ملفات APK للتحكّم: ${identity.controlApks.join(', ')}'),
    if (identity.rootedApks.isNotEmpty)
      _t(lang, 'Rooted APKs: ${identity.rootedApks.join(', ')}',
          'ملفات APK للروت: ${identity.rootedApks.join(', ')}'),
    if (identity.expectedSignerSha256 != null)
      _t(lang, 'The signer matched the expected fingerprint.', 'بصمة الموقّع طابقت البصمة المتوقعة.')
    else
      _t(lang, 'No expected signer fingerprint was supplied.', 'لم يتم تحديد بصمة موقّع متوقعة.'),
    _t(lang, 'The installable files were supplied for this AAB. Their build provenance is user-supplied.',
        'ملفات التثبيت دي اتوفرت للفحص مع الـAAB. ارتباطهم بنفس الـbuild بيعتمد على مصدر الملفات.'),
  ];
}

/// Marks for operation outcomes, process observations and inconclusive checks.
String probeMark(ProbeStatus s) => switch (s) {
      ProbeStatus.blocked => '✅',
      ProbeStatus.notBlocked => '❌',
      ProbeStatus.inconclusive => '⏸️ ',
    };

/// The check's title in [lang].
String probeCheckTitle(ProbeCheck c, String lang) {
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

/// What was observed, in [lang].
String probeEvidence(ProbeResult r, String lang) {
  if (lang != 'ar') return r.evidence;
  if (r.processOnly) {
    return r.status == ProbeStatus.blocked
        ? 'Android سجّل إن عملية التطبيق خرجت بنفسها بعد تطبيق الشرط'
        : 'نفس عملية التطبيق فضلت شغّالة بعد التحقق من الشرط';
  }
  return switch (r.status) {
    ProbeStatus.blocked => 'التطبيق صدّ الحالة',
    ProbeStatus.notBlocked => r.check.id == 'baseline' ? 'التطبيق فضل شغّال' : 'التطبيق سجّل إن الإجراء كمل',
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
  for (final line in probeApkIdentityLines(r, lang)) {
    b.writeln('  $line');
  }

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
      b.writeln('  ⏸️  ${probeCheckTitle(x.check, lang)} — ${x.note ?? probeEvidence(x, lang)}');
    }
    b.writeln('');
    b.writeln(_t(lang,
        'Inconclusive: a RASP that refuses to run on an emulator cannot be probed this way. Try a physical device, or a build without emulator-blocking.',
        'غير حاسم: حماية بترفض تشتغل على إيموليتر مش ممكن تختبرها بالطريقة دي. جرّب جهاز حقيقي، أو نسخة من غير منع الإيموليتر.'));
    return b.toString();
  }

  b.writeln('  ✅ ${probeCheckTitle(baseline.check, lang)}  ${probeEvidence(baseline, lang)}');
  if (baseline.note != null) b.writeln('       ${baseline.note}');
  final w = r.scored
      .map((x) => probeCheckTitle(x.check, lang).length)
      .fold(0, (a, b) => a > b ? a : b);
  for (final x in r.scored) {
    final tag = [x.check.masvs, x.check.mastg].whereType<String>().join(' · ');
    b.writeln('  ${probeMark(x.status)} ${probeCheckTitle(x.check, lang).padRight(w)}  ${probeEvidence(x, lang).padRight(26)}  $tag');
    if (x.note != null) b.writeln('       ${x.note}');
  }

  b.writeln('');
  final reacted = r.blocked.length;
  final gaps = r.notBlocked.length;
  final unknown = r.inconclusive.length;
  b.writeln(_t(lang,
      'Reacted: $reacted   No block observed: $gaps   Inconclusive: $unknown',
      'صدّ: $reacted   مصدّش: $gaps   غير حاسم: $unknown'));
  if (gaps > 0) {
    b.writeln(resilienceProfile
        ? _t(lang,
            '❌ The probe observed continued execution in $gaps condition(s). For a resilience profile this is a finding.',
            '❌ الفحص رصد استمرار التشغيل في $gaps حالة. ده يُعدّ مشكلة في profile المقاومة.')
        : _t(lang,
            'ℹ️  The probe observed continued execution in $gaps condition(s). Informational outside MAS-R.',
            'ℹ️  الفحص رصد استمرار التشغيل في $gaps حالة. النتيجة للعلم خارج MAS-R.'));
  }

  b.writeln('');
  b.writeln(_t(lang, 'Notes:', 'ملاحظات:'));
  b.writeln(_t(lang,
      '• Automatic observations cover process behavior. App events describe the tested operation.',
      '• الفحص التلقائي بيرصد حالة العملية، وإشارات التطبيق بتوضح نتيجة الإجراء المختبَر.'));
  b.writeln(_t(lang,
      '• This shows what happened on this emulator and this build, not a proof of security.',
      '• ده بيوضّح اللي حصل على الإيموليتر ده والنسخة دي، مش إثبات أمان.'));
  return b.toString();
}

/// Exit code 2 when an applicable check is incomplete, 1 when a resilience profile
/// has a real gap, else 0.
int probeExitCode(ProbeReport r, {required bool resilienceProfile}) {
  if (r.emulatorError != null) return 2;
  if (!r.baselineAlive) return 2;
  if (r.scored.any((x) => x.applicable && x.status == ProbeStatus.inconclusive) ||
      r.scored.every((x) => !x.applicable)) {
    return 2;
  }
  if (resilienceProfile && r.notBlocked.isNotEmpty) return 1;
  return 0;
}
