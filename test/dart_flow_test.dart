import 'package:aegis/src/dart_flow.dart';
import 'package:aegis/src/dart_scanner.dart';
import 'package:test/test.dart';

/// The flow for [code] and the index of the first token after [marker].
(ValueFlow, int) at(String code, String marker, {List<DartFile>? files}) {
  final f = DartFile('lib/a.dart', code);
  final offset = code.indexOf(marker);
  expect(offset, isNonNegative, reason: 'marker $marker');
  final i = f.tokens.indexWhere((t) => t.offset >= offset + marker.length);
  return (
    ValueFlow(f, functions: projectFunctions(files ?? [f])),
    i < 0 ? f.tokens.length - 1 : i
  );
}

void main() {
  group('origin', () {
    test('literals, numbers, constants and comparisons are clean', () {
      final (flow, i) = at('''
const kTable = 'users';
void f(int id, String s) {
  final n = s.length;
  final ok = s == 'x';
  final z = int.parse(s);
  /*here*/
}
''', '/*here*/');
      for (final e in [
        "'abc'",
        '42',
        'kTable',
        'TABLE_NAME',
        'id',
        'n',
        'ok',
        'z'
      ]) {
        expect(flow.origin(e, i).clean, isTrue, reason: e);
      }
      expect(flow.origin('s', i).clean, isFalse);
      expect(flow.origin('s', i).fromSource, isFalse);
    });

    test('sources are named by kind and travel through variables', () {
      final (flow, i) = at(r'''
void f(TextEditingController nameController, Uri uri, response) {
  final typed = nameController.text.trim();
  final page = uri.queryParameters['page'];
  final body = response.body;
  final both = '$typed $page';
  /*here*/
}
''', '/*here*/');
      expect(flow.origin('typed', i).kinds, {SourceKind.input});
      expect(flow.origin('page', i).kinds, {SourceKind.link});
      expect(flow.origin('body', i).kinds, {SourceKind.network});
      expect(flow.origin('both', i).kinds, {SourceKind.input, SourceKind.link});
    });

    test('a named argument or a variable called queryParameters is not a link',
        () {
      final (flow, i) = at(r'''
void f(Uri base) {
  final queryParameters = {'a': '1'};
  final u = base.replace(queryParameters: {'b': '2'});
  /*here*/
}
''', '/*here*/');
      expect(flow.origin('queryParameters', i).fromSource, isFalse);
      expect(flow.origin('u', i).fromSource, isFalse);
    });
  });

  group('regions', () {
    test('closure parameters of link streams and text callbacks are sources',
        () {
      final (flow, i) = at(r'''
void f() {
  uriLinkStream.listen((uri) {
    /*link*/
  });
}
''', '/*link*/');
      expect(flow.origin('uri', i).kinds, {SourceKind.link});
      final (flow2, j) = at(r'''
Widget f() => TextField(onChanged: (value) => /*typed*/ save(value));
''', '/*typed*/');
      expect(flow2.origin('value', j).kinds, {SourceKind.input});
    });

    test('a sibling closure\'s variables are out of scope', () {
      final (flow, i) = at(r'''
void f(Uri uri) {
  items.forEach((x) {
    final secret = uri.queryParameters['a'];
  });
  items.forEach((y) {
    /*here*/
  });
}
''', '/*here*/');
      expect(flow.definitions('secret', i), isEmpty);
    });

    test('an arrow body that holds a map literal or a switch', () {
      final (flow, i) = at(r'''
final a = (int count) => {'k': 1}.length + /*here*/ count;
''', '/*here*/');
      expect(flow.origin('count', i).clean, isTrue);
      final (flow2, j) = at(r'''
String label(int n) => switch (n) { 1 => /*here*/ 'one', _ => '$n' };
''', '/*here*/');
      expect(flow2.origin('n', j).clean, isTrue);
    });

    test('a method after other methods is still found', () {
      final (flow, i) = at(r'''
class Screen {
  void a() {}
  void b(String x) => print(x);
  void c(int id) { /*here*/ }
}
''', '/*here*/');
      expect(flow.origin('id', i).clean, isTrue);
      expect(flow.origin('x', i).clean, isFalse, reason: 'not in scope');
    });

    test('arrow functions have their own parameters', () {
      final (flow, i) = at(r'''
final handler = (int count) => /*here*/ count;
''', '/*here*/');
      expect(flow.origin('count', i).clean, isTrue);
    });
  });

  group('definitions', () {
    test('every assignment before the use, and for-in loops', () {
      final (flow, i) = at(r'''
void f(List<String> xs, String a) {
  var v = 'x';
  v = a;
  v += '!';
  for (final item in xs) {
    /*here*/
  }
}
''', '/*here*/');
      expect(flow.definitions('v', i), hasLength(3));
      expect(flow.definitions('item', i), hasLength(1));
      expect(flow.origin('v', i).clean, isFalse);
    });

    test('fields: const, final literals and number types are clean', () {
      final (flow, i) = at(r'''
class Dao {
  static const table = 'users';
  final int pageSize = 20;
  final String order = 'name';
  String filter = 'a';
  void f() { /*here*/ }
}
''', '/*here*/');
      expect(flow.origin('table', i).clean, isTrue);
      expect(flow.origin('pageSize', i).clean, isTrue);
      expect(flow.origin('order', i).clean, isTrue);
      expect(flow.origin('filter', i).clean, isFalse);
    });
  });

  group('checkedBefore', () {
    test('an if, a switch or a ternary that tests the value', () {
      final (flow, i) = at(r'''
void f(Uri uri) {
  if (uri.host != 'example.com') return;
  /*here*/
}
''', '/*here*/');
      expect(flow.checkedBefore({'uri'}, i), isTrue);
      final (flow2, j) = at(r'''
void f(Uri? uri) {
  if (uri == null || uri.toString().isEmpty) return;
  /*here*/
}
''', '/*here*/');
      expect(flow2.checkedBefore({'uri'}, j), isFalse,
          reason: 'null and empty tests say nothing about the value');
    });

    test('a check through a helper variable counts', () {
      final (flow, i) = at(r'''
void f(Uri uri) {
  final ok = allowed.contains(uri.host);
  if (!ok) return;
  /*here*/
}
''', '/*here*/');
      expect(flow.checkedBefore({'uri'}, i), isTrue);
    });
  });

  group('function lookup', () {
    test('the calling file first, then a single declaration elsewhere', () {
      final a = DartFile('lib/a.dart', "String name() => 'fixed';\n");
      final b = DartFile('lib/b.dart', '''
String name() => nameController.text;
String other() => helper();
void f() { /*here*/ }
''');
      final c = DartFile('lib/c.dart', "String helper() => 'h';\n");
      final files = [a, b, c];
      final lookup = projectFunctions(files);
      expect(lookup('name', b)!.$1, same(b));
      expect(lookup('helper', b)!.$1, same(c));
      expect(lookup('_private', b), isNull);
      final d = DartFile('lib/d.dart', "String helper() => 'again';\n");
      expect(projectFunctions([a, b, c, d])('helper', b), isNull,
          reason: 'declared in two files: ambiguous');
    });

    test('a call takes the origin of what the function returns', () {
      final f = DartFile('lib/a.dart', r'''
String fixed() => 'x';
String typed() => nameController.text;
String checked(Uri uri) {
  if (uri.host != 'example.com') return '';
  return uri.queryParameters['next'] ?? '';
}
void g(Uri link) { /*here*/ }
''');
      final flow = ValueFlow(f, functions: projectFunctions([f]));
      final i =
          f.tokens.indexWhere((t) => t.offset > f.source.indexOf('/*here*/'));
      expect(flow.origin('fixed()', i).clean, isTrue);
      expect(flow.origin('typed()', i).kinds, {SourceKind.input});
      expect(flow.origin('checked(link)', i).kinds,
          isNot(contains(SourceKind.link)));
    });
  });

  test('large files stay fast (it was quadratic until F1)', () {
    // 6,000 small methods, 36,000 lines: like a big generated file.
    final b = StringBuffer('class Dao {\n');
    for (var i = 0; i < 6000; i++) {
      b
        ..writeln('  Future<void> q$i(db, String a$i) async {')
        ..writeln("    final sql = 'SELECT * FROM t WHERE a = \$a$i';")
        ..writeln('    await db.rawQuery(sql);')
        ..writeln("    print('done \$a$i');")
        ..writeln('    launchUrl(Uri.parse(a$i));')
        ..writeln('  }');
    }
    b.writeln('}');
    final f = DartFile('lib/dao.dart', b.toString());
    final flow = ValueFlow(f, functions: projectFunctions([f]));
    final sw = Stopwatch()..start();
    for (final c in f.calls({'rawQuery', 'launchUrl'})) {
      final arg = f.args(c.open).first;
      flow.rangeOrigin(arg.start, arg.end);
      flow.namesBehind(f.text(arg.start, arg.end), arg.start);
      flow.checkedBefore({'a1'}, c.close);
    }
    // About 0.1 s now; it took over 15 s before the fix.
    expect(sw.elapsed, lessThan(const Duration(seconds: 5)));
  });
}
