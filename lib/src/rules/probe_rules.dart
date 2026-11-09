/// AEG-R01..R04: the resilience probe's results as ordinary rules, so they
/// count in the score, the baseline and fail_on like any other finding.
///
/// These rules do not inspect files. `aegis run --mode apk|aab|all` runs the
/// probe on the emulator first and hands its outcome to the audit
/// ([Project.probe]); each rule reads its own check from it. They only exist
/// in a run that tried the probe, and only count under a profile with MAS-R.
library;

import 'package:path/path.dart' as p;

import '../model.dart';
import '../probe/probe_model.dart';
import '../project.dart';
import 'rule.dart';

const _r = {MasProfile.r};

const _fix = Bilingual(
    'Add runtime protection (RASP) that reacts to this condition — freeRASP or a commercial product — and set it to stop or restrict the app, not only to report. Then run aegis run --mode apk again to confirm it reacts.',
    'ضيف حماية وقت التشغيل (RASP) بترد على الحالة دي — freeRASP أو منتج تجاري — وخليها توقف التطبيق أو تقيّده، مش تبلّغ بس. وبعدين شغّل aegis run --mode apk تاني عشان تتأكد إنها بترد.');

const _processFinding = Bilingual(
    'No process-level block was observed under the verified condition.',
    'الفحص ما رصدش إيقاف لعملية التطبيق بعد التحقق من الشرط.');

/// One probe check as a rule.
class ProbeRule extends Rule {
  const ProbeRule(this.checkId, this.meta, this.message);

  /// The [ProbeCheck.id] this rule reports: root, hooking, debugger, repackage.
  final String checkId;

  @override
  final RuleMeta meta;

  /// The finding text when the app did not react. Kept free of timings and
  /// pids so its baseline fingerprint is stable.
  final Bilingual message;

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final outcome = project.probe;
    if (outcome == null) {
      return RuleCheck.notApplicable('The resilience probe did not run.');
    }
    final report = outcome.report;
    if (report == null) {
      final note = 'Probe skipped: ${outcome.skipped}';
      return outcome.requested ? RuleCheck.incomplete(note) : RuleCheck.notApplicable(note);
    }
    if (report.emulatorError != null) {
      return RuleCheck.incomplete('The probe could not run: ${report.emulatorError}');
    }
    if (!report.baselineAlive) {
      return RuleCheck.incomplete('The app did not stay alive during the control launch.');
    }
    ProbeResult? result;
    for (final r in report.results) {
      if (r.check.id == checkId) result = r;
    }
    if (result == null) {
      return RuleCheck.notApplicable('Not part of this probe run (--only).');
    }
    final r = result;
    if (!r.applicable) return RuleCheck.notApplicable(r.note);
    return switch (r.status) {
      ProbeStatus.blocked => RuleCheck(const []),
      ProbeStatus.inconclusive => RuleCheck.incomplete(
          'Inconclusive${r.note == null ? '' : ': ${r.note}'}'),
      // "<file>!/runtime": the baseline normalises the APK/AAB file name, so a
      // new build with another version in its name still matches.
      ProbeStatus.notBlocked => RuleCheck([
          inFile('${p.basename(report.app)}!/runtime', null,
              r.processOnly ? _processFinding.en : message.en,
              messageAr: r.processOnly ? _processFinding.ar : message.ar,
              snippet: r.evidence),
        ]),
    };
  }
}

const probeRules = <Rule>[
  ProbeRule(
    'root',
    RuleMeta(
      id: 'AEG-R01',
      title: Bilingual('The app continues under root',
          'التطبيق بيكمّل شغله عادي على جهاز متعمله root'),
      passTitleText: Bilingual('The app reacted on a rooted device',
          'التطبيق ردّ على الجهاز اللي متعمله root'),
      description: Bilingual(
          'aegis tested the app under verified root availability and observed continued execution. On a rooted device an attacker can read the app\'s files and memory and change its behaviour; MASVS-RESILIENCE-1 expects the app to notice and react.',
          'aegis اختبر التطبيق بعد التحقق من توفر الـroot ورصد استمرار التشغيل. على جهاز متعمله root أي حد يقدر يقرا ملفات التطبيق وذاكرته ويغيّر سلوكه، وMASVS-RESILIENCE-1 بيطلب إن التطبيق ياخد باله ويرد.'),
      fix: _fix,
      severity: Severity.high,
      masvs: ['MASVS-RESILIENCE-1'],
      profiles: _r,
    ),
    Bilingual('The app reported that the tested operation proceeded on the rooted emulator.',
        'التطبيق سجّل إن الإجراء اللي اتفحص كمل على الإيموليتر المتعمله root.'),
  ),
  ProbeRule(
    'hooking',
    RuleMeta(
      id: 'AEG-R02',
      title: Bilingual('The app continues after Frida attaches',
          'التطبيق بيستمر بعد اتصال Frida'),
      passTitleText: Bilingual('The app reacted to Frida', 'التطبيق ردّ على Frida'),
      description: Bilingual(
          'aegis attached Frida to the running app and observed continued execution. Instrumentation lets an attacker read and change the app\'s logic while it runs; MASVS-RESILIENCE-4 expects the app to detect it.',
          'aegis وصّل Frida بالتطبيق وهو شغّال ورصد استمرار التشغيل. الأدوات دي بتخلّي أي حد يقرا منطق التطبيق ويغيّره وهو شغّال، وMASVS-RESILIENCE-4 بيطلب إن التطبيق يكتشفها.'),
      fix: _fix,
      severity: Severity.high,
      masvs: ['MASVS-RESILIENCE-4'],
      profiles: _r,
    ),
    Bilingual('The app reported that the tested operation proceeded with Frida attached.',
        'التطبيق سجّل إن الإجراء اللي اتفحص كمل وFrida متوصّل.'),
  ),
  ProbeRule(
    'debugger',
    RuleMeta(
      id: 'AEG-R03',
      title: Bilingual('The app continues with a debugger attached',
          'التطبيق بيستمر بعد اتصال الـ debugger'),
      passTitleText: Bilingual('The app reacted to a debugger', 'التطبيق ردّ على الـ debugger'),
      description: Bilingual(
          'aegis attached a debugger and observed continued execution. MASVS-RESILIENCE-4 expects the app to notice a debugger. Release builds are usually not debuggable, so this check is often not applicable.',
          'aegis وصّل debugger ورصد استمرار التشغيل. MASVS-RESILIENCE-4 بيطلب إن التطبيق ياخد باله من الـ debugger. نسخ الـ release غالبًا مش debuggable، فالفحص ده كتير بيطلع مش منطبق.'),
      fix: _fix,
      severity: Severity.medium,
      masvs: ['MASVS-RESILIENCE-4'],
      profiles: _r,
    ),
    Bilingual('The app reported that the tested operation proceeded with a debugger attached.',
        'التطبيق سجّل إن الإجراء اللي اتفحص كمل والـ debugger متوصّل.'),
  ),
  ProbeRule(
    'repackage',
    RuleMeta(
      id: 'AEG-R04',
      title: Bilingual('A re-signed copy of the app continues running',
          'نسخة من التطبيق معاد توقيعها بتشتغل عادي'),
      passTitleText: Bilingual('A re-signed copy of the app was rejected',
          'النسخة المعاد توقيعها من التطبيق اترفضت'),
      description: Bilingual(
          'aegis installed a copy signed with a different key and observed continued execution. MASVS-RESILIENCE-2 expects the app to check its own signature or integrity.',
          'aegis ركّب نسخة متوقّعة بمفتاح تاني ورصد استمرار التشغيل، وMASVS-RESILIENCE-2 بيطلب إن التطبيق يتأكد من توقيعه أو سلامته.'),
      fix: _fix,
      severity: Severity.high,
      masvs: ['MASVS-RESILIENCE-2'],
      profiles: _r,
    ),
    Bilingual("A copy re-signed with another key ran normally: nothing checked the app's signature.",
        'نسخة متوقّعة بمفتاح تاني اشتغلت عادي: مفيش حاجة اتأكدت من توقيع التطبيق.'),
  ),
];
