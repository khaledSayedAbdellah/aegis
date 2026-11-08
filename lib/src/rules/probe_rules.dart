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
      return RuleCheck.notApplicable('Probe skipped: ${outcome.skipped}');
    }
    if (report.emulatorError != null) {
      return RuleCheck.notApplicable('The probe could not run: ${report.emulatorError}');
    }
    if (!report.baselineAlive) {
      return RuleCheck.notApplicable(
          'The app did not stay alive on a clean emulator, so this could not be judged.');
    }
    ProbeResult? result;
    for (final r in report.results) {
      if (r.check.id == checkId) result = r;
    }
    if (result == null) {
      return RuleCheck.notApplicable('Not part of this probe run (--only).');
    }
    final r = result;
    return switch (r.status) {
      ProbeStatus.blocked => RuleCheck(const []),
      ProbeStatus.inconclusive => RuleCheck.notApplicable(
          'Inconclusive${r.note == null ? '' : ': ${r.note}'}'),
      // "<file>!/runtime": the baseline normalises the APK/AAB file name, so a
      // new build with another version in its name still matches.
      ProbeStatus.notBlocked => RuleCheck([
          inFile('${p.basename(report.app)}!/runtime', null, message.en,
              messageAr: message.ar, snippet: r.evidence),
        ]),
    };
  }
}

const probeRules = <Rule>[
  ProbeRule(
    'root',
    RuleMeta(
      id: 'AEG-R01',
      title: Bilingual('The app keeps running on a rooted device',
          'التطبيق بيكمّل شغله عادي على جهاز متعمله root'),
      passTitleText: Bilingual('The app reacted on a rooted device',
          'التطبيق ردّ على الجهاز اللي متعمله root'),
      description: Bilingual(
          'aegis ran the app on its rooted emulator and the app kept working normally. On a rooted device an attacker can read the app\'s files and memory and change its behaviour; MASVS-RESILIENCE-1 expects the app to notice and react.',
          'aegis شغّل التطبيق على الإيموليتر المتعمله root والتطبيق كمّل شغله عادي. على جهاز متعمله root أي حد يقدر يقرا ملفات التطبيق وذاكرته ويغيّر سلوكه، وMASVS-RESILIENCE-1 بيطلب إن التطبيق ياخد باله ويرد.'),
      fix: _fix,
      severity: Severity.high,
      masvs: ['MASVS-RESILIENCE-1'],
      profiles: _r,
    ),
    Bilingual('On a rooted emulator the app kept running normally: nothing detected root.',
        'على إيموليتر متعمله root التطبيق كمّل شغله عادي: مفيش حاجة اكتشفت الـ root.'),
  ),
  ProbeRule(
    'hooking',
    RuleMeta(
      id: 'AEG-R02',
      title: Bilingual('The app does not react to Frida',
          'التطبيق مبيردش على Frida'),
      passTitleText: Bilingual('The app reacted to Frida', 'التطبيق ردّ على Frida'),
      description: Bilingual(
          'aegis attached Frida to the running app and it kept working normally. Instrumentation lets an attacker read and change the app\'s logic while it runs; MASVS-RESILIENCE-4 expects the app to detect it.',
          'aegis وصّل Frida بالتطبيق وهو شغّال والتطبيق كمّل عادي. الأدوات دي بتخلّي أي حد يقرا منطق التطبيق ويغيّره وهو شغّال، وMASVS-RESILIENCE-4 بيطلب إن التطبيق يكتشفها.'),
      fix: _fix,
      severity: Severity.high,
      masvs: ['MASVS-RESILIENCE-4'],
      profiles: _r,
    ),
    Bilingual('With Frida attached the app kept running normally: nothing detected the instrumentation.',
        'وFrida متوصّل بيه التطبيق كمّل شغله عادي: مفيش حاجة اكتشفت ده.'),
  ),
  ProbeRule(
    'debugger',
    RuleMeta(
      id: 'AEG-R03',
      title: Bilingual('The app does not react to a debugger',
          'التطبيق مبيردش على الـ debugger'),
      passTitleText: Bilingual('The app reacted to a debugger', 'التطبيق ردّ على الـ debugger'),
      description: Bilingual(
          'aegis attached a debugger and the app kept working normally. MASVS-RESILIENCE-4 expects the app to notice a debugger. Release builds are usually not debuggable, so this check is often not applicable.',
          'aegis وصّل debugger والتطبيق كمّل عادي. MASVS-RESILIENCE-4 بيطلب إن التطبيق ياخد باله من الـ debugger. نسخ الـ release غالبًا مش debuggable، فالفحص ده كتير بيطلع مش منطبق.'),
      fix: _fix,
      severity: Severity.medium,
      masvs: ['MASVS-RESILIENCE-4'],
      profiles: _r,
    ),
    Bilingual('With a debugger attached the app kept running normally.',
        'والـ debugger متوصّل التطبيق كمّل شغله عادي.'),
  ),
  ProbeRule(
    'repackage',
    RuleMeta(
      id: 'AEG-R04',
      title: Bilingual('A re-signed copy of the app runs normally',
          'نسخة من التطبيق معاد توقيعها بتشتغل عادي'),
      passTitleText: Bilingual('A re-signed copy of the app was rejected',
          'النسخة المعاد توقيعها من التطبيق اترفضت'),
      description: Bilingual(
          'aegis signed the app with a different key, installed that copy and it ran normally. A modified, redistributed copy of the app would work the same way; MASVS-RESILIENCE-2 expects the app to check its own signature or integrity.',
          'aegis وقّع التطبيق بمفتاح تاني وركّب النسخة دي واشتغلت عادي. يعني نسخة متعدّلة ومتوزّعة من التطبيق هتشتغل بنفس الشكل، وMASVS-RESILIENCE-2 بيطلب إن التطبيق يتأكد من توقيعه أو سلامته.'),
      fix: _fix,
      severity: Severity.high,
      masvs: ['MASVS-RESILIENCE-2'],
      profiles: _r,
    ),
    Bilingual("A copy re-signed with another key ran normally: nothing checked the app's signature.",
        'نسخة متوقّعة بمفتاح تاني اشتغلت عادي: مفيش حاجة اتأكدت من توقيع التطبيق.'),
  ),
];
