import 'package:aegis/aegis.dart';
import 'package:test/test.dart';

import 'rules_test.dart' show audit, result;

Future<List<String>> found(String id, String code) async {
  final r = await audit({'lib/main.dart': code});
  return result(r, id).findings.map((f) => '${f.line}: ${f.message}').toList();
}

void main() {
  group('AEG-D11 SQL', () {
    test('values pasted into SQL are reported', () async {
      expect(await found('AEG-D11', r'''
Future<void> f(db, String id, String name, String q, limit) async {
  await db.rawQuery('SELECT * FROM users WHERE id = $id');
  await db.rawDelete("DELETE FROM users WHERE name = '$name'");
  await db.query('notes', where: 'title LIKE "%$q%"');
  await db.execute('INSERT INTO log (a, b) VALUES (1, ${name.trim()})');
  await db.rawQuery('SELECT * FROM t WHERE a = ' + id + ' AND b = 1');
  await db.customSelect('SELECT * FROM t LIMIT $limit');
}
'''), [
        '2: SQL built with `id` in rawQuery(). Pass it as an argument to a `?` placeholder instead.',
        startsWith('3: SQL built with `name` in rawDelete()'),
        startsWith('4: SQL built with `q` in query()'),
        startsWith('5: SQL built with `name.trim()` in execute()'),
        startsWith('6: SQL built with `id` in rawQuery()'),
        startsWith('7: SQL built with `limit` in customSelect()'),
      ]);
    });

    test('placeholders, table names and constants pass', () async {
      expect(await found('AEG-D11', r'''
const kUsers = 'users';
const TABLE = 'notes';
Future<void> f(db, String id, String table) async {
  await db.rawQuery('SELECT * FROM users WHERE id = ?', [id]);
  await db.query('users', where: 'id = ?', whereArgs: [id]);
  await db.rawQuery('SELECT * FROM $table ORDER BY id');
  await db.execute('CREATE TABLE IF NOT EXISTS $kUsers (id TEXT)');
  await db.rawQuery('SELECT * FROM t WHERE kind = $TABLE');
  await db.select(users);
  await client.execute(request);
  await db.execute('notes $id');
}
'''), isEmpty);
    });
  });

  group('AEG-D11 value flow', () {
    test('a query variable built from data is reported', () async {
      expect(await found('AEG-D11', r'''
Future<void> f(db, TextEditingController nameController, List names) async {
  final name = nameController.text.trim();
  final sql = 'SELECT * FROM users WHERE name = "$name"';
  await db.rawQuery(sql);
  for (final n in names) {
    await db.rawQuery('SELECT * FROM t WHERE n = $n');
  }
}
'''), [
        startsWith('4: SQL built with `name` in rawQuery()'),
        startsWith('6: SQL built with `n` in rawQuery()'),
      ]);
    });

    test('numbers and constants defined in the function pass', () async {
      expect(await found('AEG-D11', r'''
Future<void> f(db, TextEditingController c, int id, {required int limit}) async {
  var where = 'id = $id';
  await db.query('t', where: where);
  final count = int.parse(countController.text);
  await db.rawQuery('SELECT * FROM t LIMIT $count');
  const kind = 'a';
  await db.rawQuery('SELECT * FROM t WHERE k = $kind');
  await db.rawQuery('SELECT * FROM t LIMIT $limit');
  final n = c.text.length;
  await db.rawQuery('SELECT * FROM t WHERE n = $n');
}
'''), isEmpty);
    });

    test('a WebView script variable built from data is reported', () async {
      expect(await found('AEG-D12', r'''
Future<void> f(web, TextEditingController nameController) async {
  final js = 'greet("${nameController.text}")';
  await web.runJavaScript(js);
}
'''), [startsWith('3: `nameController.text` is pasted')]);
    });
  });

  group('AEG-D12 WebView', () {
    test('values pasted into JavaScript or HTML are reported', () async {
      expect(await found('AEG-D12', r'''
Future<void> f(controller, String name, Map data, String body) async {
  await controller.runJavaScript('greet("$name")');
  await controller.loadHtmlString('<h1>' + body + '</h1>');
  await controller.evaluateJavascript(source: 'show(${data['x']})');
}
'''), [
        '2: `name` is pasted into the code passed to runJavaScript() without encoding.',
        startsWith('3: `body` is pasted'),
        startsWith("4: `data['x']` is pasted"),
      ]);
    });

    test('encoded values, constants and plain variables pass', () async {
      expect(await found('AEG-D12', r'''
import 'dart:convert';
const kScript = 'init()';
Future<void> f(controller, Map data, String html, String name) async {
  await controller.runJavaScript('setData(${jsonEncode(data)})');
  await controller.loadHtmlString('<p>${htmlEscape.convert(name)}</p>');
  await controller.runJavaScript('$kScript;');
  await controller.loadHtmlString(html);
  await controller.runJavaScript('window.scrollTo(0, 0)');
}
'''), isEmpty);
    });
  });

  test('both rules are high for L2 and suppressible', () async {
    final r = await audit({
      'lib/main.dart': r'''
Future<void> f(db, String id) async {
  // aegis:ignore AEG-D11
  await db.rawQuery('SELECT * FROM users WHERE id = $id');
}
''',
    });
    expect(result(r, 'AEG-D11').status, RuleStatus.passed);
    expect(result(r, 'AEG-D11').suppressed, 1);
    expect(result(r, 'AEG-D12').severity, Severity.high);
  });
}
