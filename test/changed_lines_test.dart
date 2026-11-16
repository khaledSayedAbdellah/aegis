import 'dart:convert';
import 'dart:io';

import 'package:aegis/aegis.dart';
import 'package:path/path.dart' as p;
import 'package:test/test.dart';

void main() {
  test('reads added and changed lines from a diff', () {
    final files = ChangedLines.parse('''
diff --git a/lib/a.dart b/lib/a.dart
index 1..2 100644
--- a/lib/a.dart
+++ b/lib/a.dart
@@ -3,0 +4,2 @@ void main() {
+  one();
+  two();
@@ -10 +12 @@
-old
+new
diff --git a/lib/b.dart b/lib/b.dart
new file mode 100644
--- /dev/null
+++ b/lib/b.dart
@@ -0,0 +1,3 @@
+a
diff --git a/lib/c.dart b/lib/c.dart
deleted file mode 100644
--- a/lib/c.dart
+++ /dev/null
@@ -1 +0,0 @@
-gone
''');
    expect(files, {
      'lib/a.dart': {4, 5, 12},
      'lib/b.dart': null,
    });
    final changed = ChangedLines('main', files);
    expect(changed.contains('lib/a.dart', 5), isTrue);
    expect(changed.contains('lib/a.dart', 6), isFalse);
    expect(changed.contains('lib/b.dart', 99), isTrue);
    expect(changed.contains('lib/a.dart', null), isTrue);
    expect(changed.contains(null, null), isFalse);
  });

  test('only findings on changed lines are listed; the score covers all',
      () async {
    final dir = Directory.systemTemp.createTempSync('aegis_changed_');
    addTearDown(() => dir.deleteSync(recursive: true));
    final root = p.join(dir.path, 'app');
    void write(String path, String text) {
      final f = File(p.join(root, path));
      f.parent.createSync(recursive: true);
      f.writeAsStringSync(text);
    }

    void git(List<String> args) {
      final r = Process.runSync(
          'git',
          [
            '-c', 'user.name=aegis', '-c', 'user.email=aegis@example.com', //
            '-c', 'commit.gpgsign=false', ...args,
          ],
          workingDirectory: dir.path);
      expect(r.exitCode, 0, reason: '${r.stdout}${r.stderr}');
    }

    write('pubspec.yaml', 'name: app\n');
    write('lib/main.dart', '''
Future<void> f(db, String a) async {
  await db.rawQuery('SELECT * FROM t WHERE a = \$a');
}
''');
    git(['init', '-q']);
    git(['add', '.']);
    git(['commit', '-q', '-m', 'first']);
    // A second query on a new line, and a new, untracked file.
    write('lib/main.dart', '''
Future<void> f(db, String a, String b) async {
  await db.rawQuery('SELECT * FROM t WHERE a = \$a');
  await db.rawQuery('SELECT * FROM t WHERE b = \$b');
}
''');
    write('lib/extra.dart', '''
Future<void> g(db, String c) => db.rawQuery('SELECT * FROM t WHERE c = \$c');
''');

    final changed = ChangedLines.load(root, 'HEAD');
    final all = await runAudit(root, offline: true);
    final r = await runAudit(root, offline: true, changed: changed);
    final sql = r.results.firstWhere((x) => x.meta.id == 'AEG-D11');
    expect(sql.newFindings.map((f) => f.location),
        unorderedEquals(['lib/main.dart:3', 'lib/extra.dart:1']));
    expect(sql.findings, hasLength(3));
    expect(r.outsideChangeCount, greaterThanOrEqualTo(1));
    expect(r.score.value, all.score.value);
    expect(renderMarkdown(r),
        contains('only findings on lines changed since `HEAD`'));
    final sarif = jsonDecode(renderSarif(r)) as Map;
    final lines = [
      for (final x in sarif['runs'][0]['results'] as List)
        if (x['ruleId'] == 'AEG-D11')
          '${x['locations'][0]['physicalLocation']['artifactLocation']['uri']}:'
              '${x['locations'][0]['physicalLocation']['region']['startLine']}'
    ];
    expect(lines, unorderedEquals(['lib/main.dart:3', 'lib/extra.dart:1']));
  });

  test('an unknown ref is explained', () {
    final dir = Directory.systemTemp.createTempSync('aegis_changed_');
    addTearDown(() => dir.deleteSync(recursive: true));
    Process.runSync('git', ['init', '-q'], workingDirectory: dir.path);
    expect(() => ChangedLines.load(dir.path, 'no-such-branch'),
        throwsA(isA<FormatException>()));
  });
}
