/// Base class for all rules.
library;

import 'dart:async';

import '../dart_scanner.dart';
import '../model.dart';
import '../project.dart';

/// Result of a rule's check before suppression and scoring.
class RuleCheck {
  RuleCheck(this.findings)
      : applicable = true,
        note = null;

  RuleCheck.notApplicable([this.note])
      : applicable = false,
        findings = const [];

  final bool applicable;
  final List<Finding> findings;
  final String? note;
}

abstract class Rule {
  const Rule();

  RuleMeta get meta;

  /// Runs the check. [profile] lets a rule be stricter for L2.
  FutureOr<RuleCheck> check(Project project, ProfileSet profile);

  /// Convenience for creating a finding in a Dart file at token [index].
  Finding at(DartFile f, int index, String message,
      {String? messageAr, String? snippet}) {
    final line = f.lineOfToken(index);
    return Finding(
      ruleId: meta.id,
      message: message,
      messageAr: messageAr,
      file: f.path,
      line: line,
      snippet: snippet ?? _short(f.lineText(line)),
    );
  }

  Finding inFile(String? file, int? line, String message,
          {String? messageAr, String? snippet}) =>
      Finding(
        ruleId: meta.id,
        message: message,
        messageAr: messageAr,
        file: file,
        line: line,
        snippet: snippet,
      );

  static String _short(String s) =>
      s.length > 140 ? '${s.substring(0, 137)}...' : s;
}

String shorten(String s, [int max = 140]) =>
    s.length > max ? '${s.substring(0, max - 3)}...' : s;
