import 'package:aegis/src/dart_scanner.dart';
import 'package:test/test.dart';

void main() {
  group('tokenizer', () {
    test('ignores code inside comments and strings', () {
      final f = DartFile('a.dart', '''
// print(token);
/* nested /* print(x) */ still comment */
final s = "print(notACall)";
void main() { print('hi'); }
''');
      final calls = f.calls({'print'});
      expect(calls, hasLength(1));
      expect(f.lineOfToken(calls.single.nameIndex), 4);
    });

    test('decodes string values and interpolation', () {
      final f = DartFile('a.dart', r'''
final a = 'it\'s';
final b = "x ${user.name} y";
final c = r'raw\n';
final d = """multi
line""";
''');
      final values = f.stringIndexes().map((i) => f.tokens[i].value).toList();
      expect(values, ["it's", r'x ${user.name} y', r'raw\n', 'multi\nline']);
      expect(f.tokens[f.stringIndexes().elementAt(1)].interpolated, isTrue);
    });

    test('handles strings inside interpolation', () {
      final f =
          DartFile('a.dart', r'''final a = "${map['key']} done"; foo();''');
      expect(f.calls({'foo'}), hasLength(1));
    });
  });

  group('calls and args', () {
    test('receivers, named args and declarations', () {
      final f = DartFile('a.dart', '''
void start() {}
Future<void> main() async {
  await Talsec.instance.start(config);
  final c = TalsecConfig(isProd: false, androidConfig: AndroidConfig(packageName: 'a.b'));
}
''');
      final starts = f.calls({'start'});
      expect(starts, hasLength(1), reason: 'the declaration is not a call');
      expect(starts.single.receivers, ['instance', 'Talsec']);

      final cfg = f.calls({'TalsecConfig'}).single;
      final args = f.args(cfg.open);
      expect(args.map((a) => a.name), ['isProd', 'androidConfig']);
      final isProd = f.namedArg(args, 'isProd')!;
      expect(f.text(isProd.start, isProd.end), 'false');
    });

    test('generic calls', () {
      final f = DartFile('a.dart', 'final x = context.read<AuthBloc>(); ');
      expect(f.calls({'read'}).single.receiver, 'context');
    });

    test('contextName for assignments and map keys', () {
      final f = DartFile('a.dart', '''
const apiKey = 'abc';
final m = {'clientSecret': 'def'};
''');
      final names = f.stringIndexes().map(f.contextName).toList();
      expect(names, ['apiKey', null, 'clientSecret']);
    });

    test('suppression comments', () {
      final f = DartFile('a.dart', '''
// aegis:ignore AEG-D02
final a = 'http://x.com';
final b = 'http://y.com'; // aegis:ignore AEG-D02, AEG-D01
''');
      expect(f.isSuppressed('AEG-D02', 2), isTrue);
      expect(f.isSuppressed('AEG-D01', 3), isTrue);
      expect(f.isSuppressed('AEG-D05', 3), isFalse);
    });

    test('functionBody finds declared functions', () {
      final f = DartFile('a.dart', '''
void _onRoot() { exit(0); }
void main() { _onRoot(); }
''');
      final body = f.functionBody('_onRoot');
      expect(body, isNotNull);
      expect(f.text(body!.start, body.end), '{ exit(0); }');
    });
  });
}
