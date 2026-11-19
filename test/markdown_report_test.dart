import 'package:aegis/aegis.dart';
import 'package:test/test.dart';

import 'rules_test.dart' show audit;

void main() {
  test('project text cannot add HTML to the Markdown report', () async {
    final r = await audit({
      'lib/a.dart': r'''
const url = 'http://evil.example/<img src=x onerror=alert(1)>';
''',
    });
    final md = renderMarkdown(r);
    expect(md, isNot(contains('/<img src=x')));
    expect(md, contains('&lt;img src=x onerror=alert(1)&gt;'));
  });

  test('a backtick in a file name cannot end its code span', () async {
    final r = await audit({
      'lib/we`ird.dart': "const url = 'http://api.shop-backend.net/a';\n",
    });
    expect(renderMarkdown(r), contains('`` lib/we`ird.dart:1 ``'));
  });
}
