import 'dart:convert';
import 'dart:io';

import 'package:aegis/aegis.dart';
import 'package:path/path.dart' as p;
import 'package:test/test.dart';

final l2 = AegisConfig(profile: ProfileSet.tryParse('l2')!);

/// A temporary project that can be edited between audits.
class TempProject {
  TempProject() : dir = Directory.systemTemp.createTempSync('aegis_baseline_') {
    addTearDown(() => dir.deleteSync(recursive: true));
    write('pubspec.yaml', 'name: app\ndependencies:\n  flutter:\n    sdk: flutter\n');
  }

  final Directory dir;
  String get path => dir.path;
  String get baselineFile => p.join(path, defaultBaselineFile);

  void write(String file, String content) {
    final f = File(p.join(path, file));
    f.parent.createSync(recursive: true);
    f.writeAsStringSync(content);
  }

  Future<AuditReport> audit({Baseline? baseline}) =>
      runAudit(path, config: l2, offline: true, baseline: baseline);

  /// Same as `aegis --update-baseline`.
  Future<Baseline> acceptAll() async {
    final r = await audit();
    File(baselineFile).writeAsStringSync(Baseline.fromResults(r.results).toJsonString());
    return Baseline.load(baselineFile);
  }
}

const secrets = '''
const apiKey = 'q8Zr2LwX9vT4mN7pK1sB';
const url = 'http://api.example-shop.com';
''';

Finding finding(String rule, String message, {String? file, int? line}) =>
    Finding(ruleId: rule, message: message, file: file, line: line);

RuleResult failed(String id, List<Finding> findings) {
  final meta = [...allRules, ...apkRules].firstWhere((r) => r.meta.id == id).meta;
  return RuleResult(meta: meta, status: RuleStatus.failed, severity: meta.severity, findings: findings);
}

void main() {
  group('Fingerprints', () {
    test('ignore line numbers, numbers in the message and whitespace', () {
      final a = finding('AEG-D02', 'Cleartext URL  found (3 times).', file: 'lib/a.dart', line: 3);
      final b = finding('AEG-D02', 'cleartext url found (12 times).', file: 'lib/a.dart', line: 40);
      expect(Baseline.fingerprint(a), Baseline.fingerprint(b));
    });

    test('depend on rule, file and message', () {
      final base = finding('AEG-D01', 'Possible secret assigned to "apiKey".', file: 'lib/a.dart');
      final fp = Baseline.fingerprint(base);
      expect(Baseline.fingerprint(finding('AEG-D02', base.message, file: 'lib/a.dart')), isNot(fp));
      expect(Baseline.fingerprint(finding('AEG-D01', base.message, file: 'lib/b.dart')), isNot(fp));
      expect(Baseline.fingerprint(finding('AEG-D01', 'Possible secret assigned to "token".', file: 'lib/a.dart')),
          isNot(fp));
    });

    test('renaming the APK keeps the same fingerprint', () {
      expect(Baseline.normalizeFile('app-prod-release.apk!/AndroidManifest.xml'), 'apk!/AndroidManifest.xml');
      expect(Baseline.normalizeFile('lib/a.dart'), 'lib/a.dart');
      expect(
        Baseline.fingerprint(finding('AEG-B03', 'allowBackup is on.', file: 'app-release.apk!/AndroidManifest.xml')),
        Baseline.fingerprint(finding('AEG-B03', 'allowBackup is on.', file: 'app-prod-release.apk!/AndroidManifest.xml')),
      );
    });
  });

  group('Matching', () {
    test('identical findings are counted, not merged', () {
      final b = Baseline.fromResults([
        failed('AEG-D01', [
          finding('AEG-D01', 'AWS access key found.', file: 'lib/a.dart', line: 1),
          finding('AEG-D01', 'AWS access key found.', file: 'lib/a.dart', line: 2),
        ])
      ]);
      expect(b.entries, hasLength(1));
      expect(b.total, 2);

      // A third identical key is new.
      final now = failed('AEG-D01', [
        for (final line in [1, 2, 3]) finding('AEG-D01', 'AWS access key found.', file: 'lib/a.dart', line: line)
      ]);
      expect(b.apply([now]), isEmpty);
      expect(now.findings.where((f) => f.baselined), hasLength(2));
      expect(now.newFindings, hasLength(1));
      expect(now.hasNew, isTrue);

      // One of the two was removed.
      final fewer = failed('AEG-D01', [finding('AEG-D01', 'AWS access key found.', file: 'lib/a.dart', line: 9)]);
      final resolved = b.apply([fewer]);
      expect(resolved.single.count, 1);
      expect(fewer.hasNew, isFalse);
    });

    test('file round trip', () {
      final b = Baseline.fromResults([
        failed('AEG-D02', [finding('AEG-D02', 'http://x', file: 'lib/b.dart', line: 4)]),
        failed('AEG-D01', [
          finding('AEG-D01', 'k', file: 'lib/a.dart'),
          finding('AEG-D01', 'k', file: 'lib/a.dart'),
        ]),
      ]);
      final dir = Directory.systemTemp.createTempSync('aegis_bl_');
      addTearDown(() => dir.deleteSync(recursive: true));
      final path = p.join(dir.path, 'b.json');
      File(path).writeAsStringSync(b.toJsonString());

      final json = jsonDecode(File(path).readAsStringSync()) as Map<String, dynamic>;
      expect(json['tool'], 'aegis');
      final list = json['findings'] as List;
      expect(list.map((e) => e['rule']), ['AEG-D01', 'AEG-D02'], reason: 'sorted for stable diffs');
      expect(list.first['count'], 2);
      expect(list.last.containsKey('count'), isFalse);
      expect(list.last.containsKey('line'), isFalse, reason: 'lines are not stored');

      final loaded = Baseline.load(path);
      expect(loaded.total, 3);
      expect(loaded.entries.keys.toSet(), b.entries.keys.toSet());
      expect(loaded.path, path);
    });

    test('invalid files are rejected', () {
      final dir = Directory.systemTemp.createTempSync('aegis_bl_');
      addTearDown(() => dir.deleteSync(recursive: true));
      final bad = File(p.join(dir.path, 'b.json'))..writeAsStringSync('{"nope": 1}');
      expect(() => Baseline.load(bad.path), throwsFormatException);
      bad.writeAsStringSync('not json');
      expect(() => Baseline.load(bad.path), throwsFormatException);
    });
  });

  group('Audit with a baseline', () {
    test('accepted findings are known; moving code keeps them known', () async {
      final project = TempProject()..write('lib/a.dart', secrets);
      final before = await project.audit();
      final baseline = await project.acceptAll();
      expect(baseline.total, before.failed.fold<int>(0, (s, r) => s + r.findings.length));

      // Shift every line down.
      project.write('lib/a.dart', '// header\n\n\n$secrets');
      final r = await project.audit(baseline: baseline);
      expect(r.usesBaseline, isTrue);
      expect(r.newFailed, isEmpty);
      expect(r.newFindingCount, 0);
      expect(r.knownFindingCount, baseline.total);
      expect(r.countAtLeast(Severity.low), 0, reason: '--fail-on ignores known findings');
      expect(r.score.value, before.score.value, reason: 'known findings still count in the score');
      expect(r.baselineResolved, isEmpty);
    });

    test('a new finding fails, a removed one is reported as fixed', () async {
      final project = TempProject()..write('lib/a.dart', secrets);
      final baseline = await project.acceptAll();

      project.write('lib/a.dart', '''
const url = 'http://api.example-shop.com';
const awsKey = 'AKIAZ7QW3RT5YU8IO2PL';
''');
      final r = await project.audit(baseline: baseline);

      // The new AWS key is new; the http URL is still known.
      final d01 = r.results.firstWhere((x) => x.meta.id == 'AEG-D01');
      expect(d01.hasNew, isTrue);
      expect(d01.newFindings.single.message, contains('AWS'));
      expect(r.results.firstWhere((x) => x.meta.id == 'AEG-D02').hasNew, isFalse);
      expect(r.countAtLeast(Severity.high), greaterThan(0));

      // The apiKey secret was removed.
      expect(r.baselineResolved.map((e) => e.message).join(), contains('apiKey'));
      expect(r.resolvedCount, 1);
    });

    test('entries for rules that did not run are not reported as fixed', () {
      final b = Baseline.fromResults([
        failed('AEG-B05', [finding('AEG-B05', 'Added by libraries: RECORD_AUDIO.', file: 'app.apk!/AndroidManifest.xml')]),
        failed('AEG-D02', [finding('AEG-D02', 'Cleartext URL: http://a.b', file: 'lib/a.dart')]),
      ]);
      // A source-only run: no APK rules, and the URL was removed.
      final d02 = [...allRules].firstWhere((r) => r.meta.id == 'AEG-D02').meta;
      final resolved = b.apply([RuleResult(meta: d02, status: RuleStatus.passed, severity: d02.severity)]);
      expect(resolved.map((e) => e.ruleId), ['AEG-D02']);
    });

    test('without a baseline every finding is new', () async {
      final project = TempProject()..write('lib/a.dart', secrets);
      final r = await project.audit();
      expect(r.usesBaseline, isFalse);
      expect(r.newFailed.length, r.failed.length);
      expect(r.knownFindingCount, 0);
    });
  });

  group('Reports', () {
    late AuditReport r;
    setUp(() async {
      final project = TempProject()..write('lib/a.dart', "const url = 'http://api.example-shop.com';\n");
      final baseline = await project.acceptAll();
      project.write('lib/a.dart', "const url = 'http://api.example-shop.com';\nconst awsKey = 'AKIAZ7QW3RT5YU8IO2PL';\n");
      r = await project.audit(baseline: baseline);
    });

    test('console separates new and known issues', () {
      final out = ConsoleReporter(color: false).render(r);
      expect(out, contains('New issues (not in the baseline) (1)'));
      expect(out, contains('Known issues (accepted in the baseline)'));
      expect(r.newFindingCount, 1);
      expect(out, contains('${r.knownFindingCount} known · 1 new · 0 fixed'));
      final ar = ConsoleReporter(color: false, lang: 'ar').render(r);
      expect(ar, contains('مشاكل جديدة'));
    });

    test('JSON and SARIF carry the baseline state', () {
      final json = jsonDecode(renderJson(r)) as Map<String, dynamic>;
      expect(json['baseline'], containsPair('new', 1));
      expect(json['baseline'], containsPair('known', r.knownFindingCount));
      final findings = [
        for (final rule in json['rules'] as List)
          for (final f in rule['findings'] as List) f as Map<String, dynamic>
      ];
      expect(findings.where((f) => f['baselined'] == true), hasLength(r.knownFindingCount));
      expect(findings.every((f) => (f['fingerprint'] as String).length == 16), isTrue);

      final sarif = jsonDecode(renderSarif(r)) as Map<String, dynamic>;
      final results = sarif['runs'][0]['results'] as List;
      expect(results.map((x) => x['baselineState']).toSet(), {'new', 'unchanged'});
      expect(results.first['partialFingerprints']['aegis/v1'], isA<String>());
    });

    test('HTML and Markdown show the known section', () {
      expect(renderHtml(r), allOf(contains('Known issues'), contains('class="tag"')));
      expect(renderMarkdown(r), allOf(contains('New issues'), contains('Known issues')));
    });
  });

  group('Azure Pipelines annotations', () {
    test('one annotation per new finding, linked to the file', () async {
      final project = TempProject()
        ..write('lib/a.dart', "const a = 1;\nconst url = 'http://api.example-shop.com/a%20b';\n");
      final r = await project.audit();
      final out = renderAzure(r);
      final lines = out.trim().split('\n');
      final url = lines.firstWhere((l) => l.contains('AEG-D02'));
      expect(url, startsWith('##vso[task.logissue type=error;code=AEG-D02;sourcepath=lib/a.dart;linenumber=2;]'),
          reason: 'D02 is high under L2');
      expect(url, contains('a%AZP2520b'), reason: '% is escaped');
      expect(lines.last, startsWith('##vso[task.complete result=SucceededWithIssues;]'));

      final strict = renderAzure(r, failOn: Severity.critical, failing: true);
      expect(strict, contains('type=warning;code=AEG-D02'));
      expect(strict, isNot(contains('task.complete')), reason: 'the exit code fails the step');
    });

    test('nothing is annotated when every finding is known', () async {
      final project = TempProject()..write('lib/a.dart', secrets);
      final baseline = await project.acceptAll();
      final r = await project.audit(baseline: baseline);
      expect(renderAzure(r), isEmpty);
    });
  });

  test('aegis.yaml can point to another baseline file', () {
    expect(AegisConfig.parse('baseline: security/baseline.json').baseline, 'security/baseline.json');
    expect(AegisConfig.parse('profile: l1').baseline, isNull);
  });
}
