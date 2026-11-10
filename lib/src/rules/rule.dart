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
        note = null,
        noteAr = null,
        isIncomplete = false;

  RuleCheck.notApplicable([this.note])
      : applicable = false,
        noteAr = null,
        findings = const [],
        isIncomplete = false;

  RuleCheck.notApplicableLocalized(this.note, this.noteAr)
      : applicable = false, findings = const [], isIncomplete = false;

  RuleCheck.incomplete(this.note, [this.findings = const []])
      : applicable = false,
        noteAr = null,
        isIncomplete = true;

  RuleCheck.incompleteLocalized(this.note, this.noteAr, [this.findings = const []])
      : applicable = false, isIncomplete = true;

  final String? noteAr;
  final bool isIncomplete;

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
      {String? messageAr, String? snippet, String? snippetAr}) {
    final line = f.lineOfToken(index);
    return Finding(
      ruleId: meta.id,
      message: message,
      messageAr: messageAr,
      file: f.path,
      line: line,
      snippetAr: snippetAr,
      snippet: snippet ?? _short(f.lineText(line)),
    );
  }

  Finding inFile(String? file, int? line, String message,
          {String? messageAr, String? snippet, String? snippetAr}) =>
      Finding(
        ruleId: meta.id,
        message: message,
        messageAr: messageAr,
        file: file,
        line: line,
        snippet: snippet,
        snippetAr: snippetAr,
      );

  static String _short(String s) =>
      s.length > 140 ? '${s.substring(0, 137)}...' : s;
}

String shorten(String s, [int max = 140]) =>
    s.length > max ? '${s.substring(0, max - 3)}...' : s;
