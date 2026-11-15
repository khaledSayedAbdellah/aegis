import 'package:aegis/aegis.dart';
import 'package:test/test.dart';

import 'rules_test.dart' show audit, result;

Future<List<String>> found(String code) async {
  final r = await audit({'lib/main.dart': code});
  return result(r, 'AEG-D14')
      .findings
      .map((f) => '${f.line}: ${f.message}')
      .toList();
}

void main() {
  test('security decisions only inside assert are reported', () async {
    expect(await found('''
void transfer(User user, Session s) {
  assert(user.hasPermission('transfer'));
  assert(s.isAuthenticated && !device.isRooted);
  send();
}
'''), [
      '2: `hasPermission` is only checked inside assert(), which release builds '
          'remove, so the check never runs in production.',
      startsWith('3: `isAuthenticated` is only checked'),
    ]);
  });

  test('ordinary asserts and checks also made outside pass', () async {
    expect(await found('''
bool get isAdmin => role == 'admin';
void open(User? user, List items, Session s) {
  assert(user != null);
  assert(items.isNotEmpty, 'no items');
  assert(s.isAuthenticated);
  if (!s.isAuthenticated) return;
  final verifyPin = true;
  assert(isAdmin);
}
'''), [startsWith('8: `isAdmin` is only checked')]);
  });

  test('the rule passes on code without asserts', () async {
    final r = await audit({'lib/main.dart': 'void main() {}'});
    expect(result(r, 'AEG-D14').status, RuleStatus.passed);
  });
}
