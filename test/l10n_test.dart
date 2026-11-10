import 'dart:convert';
import 'dart:io';

import 'package:aegis/aegis.dart';
import 'package:aegis/src/l10n/messages.g.dart';
import 'package:aegis/src/probe/ios_runner.dart';
import 'package:aegis/src/probe/probe_runner.dart';
import 'package:aegis/src/probe/probe_model.dart' show checkById;
import 'package:aegis/src/probe/probe_report.dart';
import 'package:test/test.dart';

import '../tool/generate_l10n.dart' as generator;
import 'ipa_test.dart' show fixture;
import 'probe_runner_test.dart' show FakeDevice;

void main() {
  test('ARB catalogs have matching keys, placeholders and compiled output', () {
    final en = jsonDecode(File('lib/src/l10n/app_en.arb').readAsStringSync())
        as Map<String, dynamic>;
    final ar = jsonDecode(File('lib/src/l10n/app_ar.arb').readAsStringSync())
        as Map<String, dynamic>;
    expect(generator.generate(en, ar),
        File('lib/src/l10n/messages.g.dart').readAsStringSync());
    expect(en.keys.where((k) => !k.startsWith('@')).length, greaterThan(500));
  });

  test(
      'generator rejects missing translations, placeholders and unsupported ICU',
      () {
    final en = <String, dynamic>{
      '@@locale': 'en',
      'hello': 'Hello {name}',
      '@hello': {
        'description': 'Greeting',
        'placeholders': {
          'name': {'type': 'Object'}
        }
      }
    };
    final ar = <String, dynamic>{'@@locale': 'ar', 'hello': 'أهلًا {name}'};
    expect(() => generator.generate(en, {...ar}..remove('hello')),
        throwsFormatException);
    expect(() => generator.generate(en, {...ar, 'hello': 'أهلًا'}),
        throwsFormatException);
    expect(
        () => generator
            .generate(en, {...ar, 'hello': '{name, select, other {Hello}}'}),
        throwsFormatException);
    expect(() => generator.generate(en, {...ar, 'hello': ''}),
        throwsFormatException);
  });

  test('placeholder values stay literal and locale fallback is deterministic',
      () {
    const value = r'{seconds} $HOME <script> & "quote"';
    expect(const L10n('ar-EG').iosAlive(seconds: value),
        Ar.iosAlive(seconds: value));
    expect(
        const L10n('fr').iosAlive(seconds: value), En.iosAlive(seconds: value));
    expect(Ar.iosAlive(seconds: value), contains(value));
  });

  test(
      'Arabic report translates iOS evidence, finding excerpts and incomplete reasons',
      () async {
    final work = Directory.systemTemp.createTempSync('aegis-l10n-test-');
    addTearDown(() => work.deleteSync(recursive: true));
    final ipa = fixture(work);
    final debug = iosProbeChecks.singleWhere((c) => c.id == 'ios-debugger');
    final jailbreak = iosProbeChecks.singleWhere((c) => c.id == 'jailbreak');
    final evidence = En.iosContinued(condition: En.iosDebuggerVerified);
    final evidenceAr = Ar.iosContinued(condition: Ar.iosDebuggerVerified);
    final runtime = ProbeReport(
        app: 'Simulator.app',
        platform: 'ios-simulator',
        baselineAlive: true,
        results: [
          ProbeResult(checkById('baseline'), ProbeStatus.notBlocked,
              evidence: En.iosAlive(seconds: 8),
              evidenceAr: Ar.iosAlive(seconds: 8),
              note: En.iosSimulatorBuild,
              noteAr: Ar.iosSimulatorBuild),
          ProbeResult(debug, ProbeStatus.notBlocked,
              processOnly: true, evidence: evidence, evidenceAr: evidenceAr),
          ProbeResult.partial(jailbreak,
              observation: ProbeStatus.notBlocked,
              evidence: En.iosNoIndicatorQuery,
              evidenceAr: Ar.iosNoIndicatorQuery,
              note: En.jailbreakLimit,
              noteAr: Ar.jailbreakLimit),
        ]);
    final report = await runAudit(work.path,
        ipaPath: ipa.path,
        offline: true,
        config: AegisConfig(profile: ProfileSet.tryParse('l1+r')!),
        probe: ProbeOutcome.ran(runtime));
    final arabic = [
      renderHtml(report, lang: 'ar'),
      renderMarkdown(report, lang: 'ar'),
      ConsoleReporter(lang: 'ar', color: false).render(report),
      renderProbe(runtime, lang: 'ar', resilienceProfile: true)
    ];
    for (final output in arabic) {
      expect(output, contains(evidenceAr));
      expect(output, contains(Ar.iosNoIndicatorQuery));
      expect(output, contains(Ar.jailbreakLimit));
      expect(output, isNot(contains(evidence)));
      expect(output, isNot(contains(En.jailbreakLimit)));
      expect(output, isNot(contains(En.iosSimulatorBuild)));
    }
    expect(renderHtml(report), contains(evidence));
    final finding = report.results
        .singleWhere((r) => r.meta.id == 'AEG-R07')
        .findings
        .single;
    expect(finding.snippet, evidence);
    expect(finding.snippetOf('ar'), evidenceAr);
    final json = reportToJson(report)['probe'] as Map;
    final checks = json['checks'] as List;
    expect(checks.first['evidence'], evidence);
    expect(checks.first['evidenceAr'], evidenceAr);
    expect(report.complete, isFalse);
    expect(probeExitCode(runtime, resilienceProfile: true), 2);
  });

  test('Arabic skipped probe explains prerequisites without English prose',
      () async {
    final work = Directory.systemTemp.createTempSync('aegis-l10n-skip-');
    addTearDown(() => work.deleteSync(recursive: true));
    final ipa = fixture(work);
    final report = await runAudit(work.path,
        ipaPath: ipa.path,
        offline: true,
        config: AegisConfig(profile: ProfileSet.tryParse('l1+r')!),
        probe: const ProbeOutcome.skipped(En.iosControlMissing,
            skippedAr: Ar.iosControlMissing));
    final html = renderHtml(report, lang: 'ar');
    expect(html, contains(Ar.iosControlMissing));
    expect(html, isNot(contains(En.iosControlMissing)));
    expect(html, isNot(contains('Probe skipped:')));
  });

  test(
      'Arabic IPA reports translate unreadable entitlements without changing the verdict',
      () async {
    final work =
        Directory.systemTemp.createTempSync('aegis-l10n-entitlements-');
    addTearDown(() => work.deleteSync(recursive: true));
    final ipa = fixture(work);
    final report = await runAudit(work.path, ipaPath: ipa.path, offline: true);
    final check = report.results.singleWhere((r) => r.meta.id == 'AEG-I03');
    expect(check.status, RuleStatus.incomplete);
    expect(check.note, En.ipaEntitlementsUnreadable);
    expect(check.noteAr, Ar.ipaEntitlementsUnreadable);
    for (final text in [
      renderHtml(report, lang: 'ar'),
      renderMarkdown(report, lang: 'ar'),
      ConsoleReporter(lang: 'ar', color: false).render(report)
    ]) {
      expect(text, contains(Ar.ipaEntitlementsUnreadable));
      expect(text, isNot(contains(En.ipaEntitlementsUnreadable)));
    }
    expect(renderHtml(report), contains(En.ipaEntitlementsUnreadable));
    if (!Platform.isMacOS) {
      final signing = report.results.singleWhere((r) => r.meta.id == 'AEG-I05');
      expect(signing.note, En.signatureMacOnly);
      expect(signing.noteAr, Ar.signatureMacOnly);
    }
  });

  test('probe --lang ar uses the localized missing-target reason', () async {
    final work = Directory.systemTemp.createTempSync('aegis-l10n-cli-');
    addTearDown(() => work.deleteSync(recursive: true));
    final ipa = fixture(work);
    final result = await Process.run(
        Platform.resolvedExecutable,
        [
          File('bin/aegis.dart').absolute.path,
          'probe',
          ipa.path,
          '--lang',
          'ar',
        ],
        workingDirectory: work.path);
    expect(result.exitCode, 2);
    expect(
        result.stderr,
        contains(
            Platform.isMacOS ? Ar.iosControlMissing : Ar.iosRequiresXcode));
    expect(result.stderr, isNot(contains(En.iosControlMissing)));
    expect(result.stderr, isNot(contains(En.iosRequiresXcode)));
  });

  test('probe --lang ar explains the missing AAB companion in Arabic',
      () async {
    final work = Directory.systemTemp.createTempSync('aegis-l10n-aab-cli-');
    addTearDown(() => work.deleteSync(recursive: true));
    final result = await Process.run(
        Platform.resolvedExecutable,
        [
          File('bin/aegis.dart').absolute.path,
          'probe',
          File('test/fixtures/aab/vulnerable.aab').absolute.path,
          '--project',
          work.path,
          '--lang',
          'ar',
        ],
        workingDirectory: work.path);
    expect(result.exitCode, 2);
    expect(result.stderr, contains(Ar.aabCompanionRequired));
    expect(result.stderr, isNot(contains(En.aabCompanionRequired)));
  });

  test(
      'Android authored probe notes are localized with unchanged exit semantics',
      () async {
    final report = await ProbeRunner(FakeDevice(), wait: Duration.zero).run(
        appPath: 'app.apk',
        package: 'org.example.app',
        workDir: '.',
        only: {'root'});
    final root = report.scored.single;
    expect(root.status, ProbeStatus.inconclusive);
    expect(root.note, En.androidRootDeviceMissing);
    expect(root.noteAr, Ar.androidRootDeviceMissing);
    final arabic = renderProbe(report, lang: 'ar', resilienceProfile: true);
    expect(arabic, contains(Ar.androidRootDeviceMissing));
    expect(arabic, isNot(contains(En.androidRootDeviceMissing)));
    expect(probeExitCode(report, resilienceProfile: true), 2);
  });

  test('code snippets are preserved as evidence, not translated', () {
    final finding = Finding(
        ruleId: 'example',
        message: 'message',
        messageAr: 'رسالة',
        snippet: 'return false;');
    expect(finding.snippetOf('ar'), 'return false;');
  });
}
