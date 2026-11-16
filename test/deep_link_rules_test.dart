import 'package:aegis/aegis.dart';
import 'package:test/test.dart';

import 'rules_test.dart' show audit, result;

Future<List<String>> found(String code) async {
  final r = await audit({'lib/main.dart': code});
  return result(r, 'AEG-D19')
      .findings
      .map((f) => '${f.line}: ${f.message}')
      .toList();
}

void main() {
  test('link data that reaches a URL, page, file or request is reported',
      () async {
    expect(await found(r'''
import 'package:app_links/app_links.dart';
void init(web) {
  AppLinks().uriLinkStream.listen((uri) {
    launchUrl(uri);
  });
}
Future<void> start() async {
  final link = await getInitialLink();
  final target = Uri.parse(link!);
  await launchUrl(target);
}
final route = GoRoute(path: '/open', builder: (context, state) {
  final next = state.uri.queryParameters['next']!;
  web.loadRequest(Uri.parse(next));
  http.get(Uri.parse(state.pathParameters['u']!));
  File('${dir.path}/${state.pathParameters['name']}').readAsString();
  return const Text('x');
});
void twice() {
  uriLinkStream.listen((uri) {
    if (uri?.host != 'example.com') return;
    launchUrl(uri!);
  });
  uriLinkStream.listen((uri) => launchUrl(flag ? uri! : fallback));
  uriLinkStream.listen((uri) {
    final next = uri?.queryParameters['next'];
    if (next != null && next.isNotEmpty) launchUrl(Uri.parse(next));
  });
}
'''), [
      '4: Deep-link data `uri` reaches launchUrl() without a check.',
      startsWith('10: Deep-link data `target` reaches launchUrl()'),
      startsWith('14: Deep-link data `Uri.parse(next)` reaches loadRequest()'),
      startsWith('15: Deep-link data'),
      startsWith('16: Deep-link data'),
      startsWith('24: Deep-link data `flag ? uri! : fallback`'),
      startsWith('27: Deep-link data `Uri.parse(next)`'),
    ]);
  });

  test('checked link data and fixed values pass', () async {
    expect(await found(r'''
void init() {
  uriLinkStream.listen((uri) {
    if (uri == null || uri.host != 'example.com') return;
    launchUrl(uri);
  });
  uriLinkStream.listen((uri) {
    if (!isAllowed(uri)) return;
    launchUrl(uri!);
  });
  uriLinkStream.listen((uri) => launchUrl(safeUri(uri)));
  uriLinkStream.listen((uri) {
    final ok = allowed.contains(uri?.host);
    launchUrl(ok ? uri! : fallback);
  });
  launchUrl(Uri.parse('https://example.com/help'));
  final name = state.pathParameters['id'];
  http.get(Uri.parse('https://api.example.com/items'));
}
'''), isEmpty);
  });

  test('no link handling: not applicable, and AEG-M08 stays', () async {
    final r = await audit({'lib/main.dart': 'void main() {}'});
    expect(result(r, 'AEG-D19').status, RuleStatus.notApplicable);
    expect(r.manual.map((m) => m.id), contains('AEG-M08'));
  });

  test('AEG-D19 replaces AEG-M08 unless push payloads are handled', () async {
    const links = r'''
void init() => uriLinkStream.listen((uri) => print(uri));
''';
    final r = await audit({'lib/main.dart': links});
    expect(result(r, 'AEG-D19').status, RuleStatus.passed);
    expect(r.manual.map((m) => m.id), isNot(contains('AEG-M08')));
    final push = await audit({
      'lib/main.dart': '$links\n'
          'void push() => FirebaseMessaging.onMessage.listen((m) {});\n',
    });
    expect(push.manual.map((m) => m.id), contains('AEG-M08'));
  });
}
