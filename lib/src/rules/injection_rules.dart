/// Rules for values pasted into code that another engine runs: SQL handed to
/// SQLite, and HTML or JavaScript handed to a WebView.
library;

import '../dart_scanner.dart';
import '../l10n/messages.g.dart';
import '../model.dart';
import '../project.dart';
import 'rule.dart';

const _all = {MasProfile.l1, MasProfile.l2, MasProfile.r};

/// A string argument split into literal text and the expressions pasted
/// into it, in order. An expression part has [expression] set.
class TemplatePart {
  TemplatePart.text(this.text) : expression = null;
  TemplatePart.value(String this.expression) : text = '';
  final String text;
  final String? expression;
}

/// The parts of the argument made of tokens [start]..[end] of [f]: string
/// literals (with their `$x` / `${...}` interpolations) joined by `+` or
/// written next to each other, and any other expression between them.
/// Null when the argument contains no string literal.
List<TemplatePart>? templateOf(DartFile f, int start, int end) {
  final parts = <TemplatePart>[];
  var sawString = false;
  final pending = StringBuffer();
  void flush() {
    if (pending.isEmpty) return;
    parts.add(TemplatePart.value(pending.toString()));
    pending.clear();
  }

  for (var i = start; i <= end && i < f.tokens.length; i++) {
    final t = f.tokens[i];
    if (t.isString) {
      flush();
      sawString = true;
      final value = t.value ?? '';
      if (!t.interpolated) {
        parts.add(TemplatePart.text(value));
        continue;
      }
      parts.addAll(_interpolations(value));
    } else if (t.isPunct('+')) {
      flush();
    } else {
      pending.write(t.text);
    }
  }
  flush();
  return sawString ? parts : null;
}

/// Splits the decoded value of an interpolated string at `$name` and
/// `${...}`.
List<TemplatePart> _interpolations(String value) {
  final out = <TemplatePart>[];
  final text = StringBuffer();
  var i = 0;
  while (i < value.length) {
    final c = value[i];
    if (c == r'$' && i + 1 < value.length) {
      if (value[i + 1] == '{') {
        var depth = 1, j = i + 2;
        while (j < value.length && depth > 0) {
          if (value[j] == '{') depth++;
          if (value[j] == '}') depth--;
          j++;
        }
        out.add(TemplatePart.text(text.toString()));
        text.clear();
        out.add(TemplatePart.value(value.substring(i + 2, j - 1).trim()));
        i = j;
        continue;
      }
      final m = RegExp(r'[A-Za-z_]\w*').matchAsPrefix(value, i + 1);
      if (m != null) {
        out.add(TemplatePart.text(text.toString()));
        text.clear();
        out.add(TemplatePart.value(m[0]!));
        i = m.end;
        continue;
      }
    }
    text.write(c);
    i++;
  }
  out.add(TemplatePart.text(text.toString()));
  return out;
}

/// Expressions that are constants, not data: `kTable`, `TABLE_NAME`,
/// `Tables.USERS`, numbers.
bool _constant(String e) =>
    RegExp(r'^(?:\w+\.)*(?:_?k[A-Z]\w*|[A-Z][A-Z0-9_]*)$').hasMatch(e) ||
    RegExp(r'^\d+(?:\.\d+)?$').hasMatch(e);

class SqlInjectionRule extends Rule {
  const SqlInjectionRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-D11',
        title: Bilingual(En.sqlInjectionTitle, Ar.sqlInjectionTitle),
        passTitleText: Bilingual(En.sqlInjectionPass, Ar.sqlInjectionPass),
        description:
            Bilingual(En.sqlInjectionDescription, Ar.sqlInjectionDescription),
        fix: Bilingual(En.sqlInjectionFix, Ar.sqlInjectionFix),
        severity: Severity.high,
        masvs: ['MASVS-CODE-4'],
        maswe: ['MASWE-0050'],
        cwe: 'CWE-89',
        profiles: _all,
      );

  /// Calls whose first argument is a whole SQL statement.
  static const _statements = {
    'rawQuery', 'rawInsert', 'rawUpdate', 'rawDelete', //
    'customSelect', 'customStatement', 'customUpdate', 'customInsert',
    'execute', 'select', 'prepare',
  };

  /// Calls whose `where:` argument is a SQL condition.
  static const _conditions = {'query', 'update', 'delete'};

  static final _sql = RegExp(
      r'\b(?:select|insert|update|delete|replace|create|drop|alter|pragma)\b',
      caseSensitive: false);

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final out = <Finding>[];
    for (final f in project.dartFiles) {
      for (final c in f.calls({..._statements, ..._conditions})) {
        final args = f.args(c.open);
        final Arg? arg;
        if (_conditions.contains(c.name)) {
          arg = f.namedArg(args, 'where');
        } else {
          arg = args.where((a) => a.name == null).firstOrNull;
        }
        if (arg == null) continue;
        final parts = templateOf(f, arg.start, arg.end);
        if (parts == null) continue;
        if (_statements.contains(c.name) &&
            !_sql.hasMatch(parts.map((p) => p.text).join(' '))) {
          continue;
        }
        final value = _valueInSql(parts);
        if (value == null) continue;
        out.add(at(f, arg.start,
            En.sqlInjection(value: shorten(value, 40), call: c.name),
            messageAr:
                Ar.sqlInjection(value: shorten(value, 40), call: c.name)));
      }
    }
    return RuleCheck(out);
  }

  /// The first pasted expression that sits where SQL expects a value
  /// (`= $x`, `LIKE '%$x%'`, `IN ($x)`, `VALUES ($a, $b)`), not where it
  /// expects a table or column name.
  static String? _valueInSql(List<TemplatePart> parts) {
    final before = StringBuffer();
    for (final part in parts) {
      final e = part.expression;
      if (e == null) {
        before.write(part.text);
        continue;
      }
      if (!_constant(e) && _valuePosition(before.toString())) return e;
      before.write('x');
    }
    return null;
  }

  static bool _valuePosition(String before) {
    var s = before.toLowerCase().trimRight();
    // Inside a quoted SQL value: `name = '$x'`, `LIKE '%$x%'`.
    s = s.replaceFirst(RegExp(r"""['"`]%?$"""), '').trimRight();
    if (RegExp(r'(?:[=<>]|\blike|\bglob|\bwhere|\band|\bor|\bnot|\bis|'
            r'\blimit|\boffset|\bbetween|\bthen|\belse|\bwhen)$')
        .hasMatch(s)) {
      return true;
    }
    if (s.endsWith('(') || s.endsWith(',')) {
      // Values inside `IN (...)` or `VALUES (...)`.
      final open = s.lastIndexOf('(');
      if (open < 0 || s.indexOf(')', open) >= 0) return false;
      return RegExp(r'\b(?:in|values)\s*$').hasMatch(s.substring(0, open));
    }
    return false;
  }
}

class WebViewInjectionRule extends Rule {
  const WebViewInjectionRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-D12',
        title: Bilingual(En.webInjectionTitle, Ar.webInjectionTitle),
        passTitleText: Bilingual(En.webInjectionPass, Ar.webInjectionPass),
        description:
            Bilingual(En.webInjectionDescription, Ar.webInjectionDescription),
        fix: Bilingual(En.webInjectionFix, Ar.webInjectionFix),
        severity: Severity.medium,
        l2Severity: Severity.high,
        masvs: ['MASVS-PLATFORM-2'],
        maswe: ['MASWE-0035'],
        cwe: 'CWE-79',
        profiles: _all,
      );

  /// Call -> the named argument that holds the code, or null for the first
  /// positional one.
  static const _calls = {
    'runJavaScript': null,
    'runJavaScriptReturningResult': null,
    'evaluateJavascript': 'source',
    'loadHtmlString': null,
    'loadData': 'data',
  };

  /// Pasting an encoded value is the safe way to do this.
  static final _encoded = RegExp(
      r'^(?:jsonEncode|json\.encode|htmlEscape\.convert|const HtmlEscape\(\)\.convert|Uri\.encodeComponent|Uri\.encodeFull|base64Encode|base64\.encode)\(');

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final out = <Finding>[];
    for (final f in project.dartFiles) {
      for (final c in f.calls(_calls.keys.toSet())) {
        final args = f.args(c.open);
        final named = _calls[c.name];
        final arg = (named == null ? null : f.namedArg(args, named)) ??
            args.where((a) => a.name == null).firstOrNull;
        if (arg == null) continue;
        final parts = templateOf(f, arg.start, arg.end);
        if (parts == null) continue;
        final value = parts
            .map((p) => p.expression)
            .whereType<String>()
            .where((e) => !_constant(e) && !_encoded.hasMatch(e))
            .firstOrNull;
        if (value == null) continue;
        out.add(at(f, arg.start,
            En.webInjection(value: shorten(value, 40), call: c.name),
            messageAr:
                Ar.webInjection(value: shorten(value, 40), call: c.name)));
      }
    }
    return RuleCheck(out);
  }
}

const injectionRules = <Rule>[SqlInjectionRule(), WebViewInjectionRule()];
