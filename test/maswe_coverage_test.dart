import 'dart:io';

import 'package:test/test.dart';

import '../tool/maswe_coverage.dart' as coverage;

void main() {
  test('every MASWE id a rule cites is a real MASWE entry', () {
    final known = coverage.maswe.map((w) => w.$1).toSet();
    expect(known, hasLength(78));
    expect(
        coverage.coverage().keys.where((id) => !known.contains(id)), isEmpty);
  });

  test('doc/maswe-coverage.md is up to date', () {
    // A Windows checkout may turn the file's line ends into CRLF.
    expect(File(coverage.output).readAsStringSync().replaceAll('\r\n', '\n'),
        coverage.generate(),
        reason: 'Run: dart run tool/maswe_coverage.dart');
  });

  test('the table lists covered and uncovered weaknesses', () {
    final text = coverage.generate();
    expect(
        text,
        contains('| [MASWE-0001](https://mas.owasp.org/MASWE/'
            'MASVS-STORAGE/MASWE-0001/) | Sensitive Data Stored Unencrypted in '
            'Private Storage | AEG-D04, AEG-D18, AEG-N04, AEG-R10 |'));
    expect(text, contains('| not covered |'));
  });
}
