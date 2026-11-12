/// A small, dependency-free Dart tokenizer with structural helpers.
///
/// It understands comments, all string forms (raw, triple-quoted,
/// interpolated) and bracket nesting, which is enough to find calls, their
/// arguments and closure bodies reliably. It intentionally does not depend on
/// `package:analyzer`, whose API changes often, so `aegis` works with any
/// Dart 3 SDK and never conflicts with your app's own analyzer version.
library;

enum TokKind { ident, string, number, punct }

class Tok {
  Tok(this.kind, this.text, this.offset, this.end,
      {this.value, this.interpolated = false});

  final TokKind kind;

  /// Raw source text of the token.
  final String text;
  final int offset;

  /// Exclusive end offset.
  final int end;

  /// For strings: the content without quotes, escapes decoded,
  /// interpolations kept as `${...}` / `$name`.
  final String? value;

  /// For strings: whether the literal contains interpolation.
  final bool interpolated;

  bool get isIdent => kind == TokKind.ident;
  bool get isString => kind == TokKind.string;
  bool isPunct(String p) => kind == TokKind.punct && text == p;

  @override
  String toString() => '$kind($text)';
}

class SourceComment {
  SourceComment(this.text, this.offset, this.line);
  final String text;
  final int offset;
  final int line;
}

/// A call such as `foo(...)` or `a.b.foo<T>(...)`.
class CallSite {
  CallSite(this.name, this.nameIndex, this.open, this.close, this.receivers);

  final String name;
  final int nameIndex;

  /// Token index of `(`.
  final int open;

  /// Token index of the matching `)`.
  final int close;

  /// Receiver chain, nearest first: for `Talsec.instance.start(` it is
  /// `['instance', 'Talsec']`.
  final List<String> receivers;

  String? get receiver => receivers.isEmpty ? null : receivers.first;
}

/// One argument of a call, as a token range.
class Arg {
  Arg(this.name, this.start, this.end);

  /// Name for named arguments, otherwise null.
  final String? name;

  /// First token of the value (after `name:` for named args).
  final int start;

  /// Last token of the value (inclusive).
  final int end;
}

class DartFile {
  DartFile(this.path, this.source) {
    _computeLineStarts();
    _Lexer(source, tokens, comments).run();
    _fixCommentLines();
    _matchBrackets();
    _collectSuppressions();
  }

  /// Path relative to the project root.
  final String path;
  final String source;
  final List<Tok> tokens = [];
  final List<SourceComment> comments = [];
  final Map<int, int> _match = {};
  final List<int> _lineStarts = [0];
  final Map<int, Set<String>> _suppress = {};
  final Set<String> _fileSuppress = {};

  void _computeLineStarts() {
    for (var i = 0; i < source.length; i++) {
      if (source.codeUnitAt(i) == 0x0A) _lineStarts.add(i + 1);
    }
  }

  void _fixCommentLines() {
    final fixed = comments
        .map((c) => SourceComment(c.text, c.offset, lineOf(c.offset)))
        .toList();
    comments
      ..clear()
      ..addAll(fixed);
  }

  /// 1-based line number of [offset].
  int lineOf(int offset) {
    var lo = 0, hi = _lineStarts.length - 1;
    while (lo < hi) {
      final mid = (lo + hi + 1) >> 1;
      if (_lineStarts[mid] <= offset) {
        lo = mid;
      } else {
        hi = mid - 1;
      }
    }
    return lo + 1;
  }

  int lineOfToken(int index) => lineOf(tokens[index].offset);

  /// The text of [line] (1-based), trimmed.
  String lineText(int line) {
    if (line < 1 || line > _lineStarts.length) return '';
    final start = _lineStarts[line - 1];
    final end = line < _lineStarts.length ? _lineStarts[line] : source.length;
    return source.substring(start, end).trim();
  }

  void _matchBrackets() {
    final stack = <int>[];
    for (var i = 0; i < tokens.length; i++) {
      final t = tokens[i];
      if (t.kind != TokKind.punct) continue;
      switch (t.text) {
        case '(':
        case '[':
        case '{':
        case '?[':
          stack.add(i);
        case ')':
        case ']':
        case '}':
          if (stack.isNotEmpty) {
            final open = stack.removeLast();
            _match[open] = i;
            _match[i] = open;
          }
      }
    }
  }

  void _collectSuppressions() {
    final re = RegExp(r'aegis\s*:\s*ignore(-file)?\s+([A-Za-z0-9\-, ]+)');
    for (final c in comments) {
      final m = re.firstMatch(c.text);
      if (m == null) continue;
      final ids = m
          .group(2)!
          .split(RegExp(r'[,\s]+'))
          .map((s) => s.trim().toUpperCase())
          .where((s) => s.startsWith('AEG-'))
          .toSet();
      if (m.group(1) != null) {
        _fileSuppress.addAll(ids);
      } else {
        _suppress.putIfAbsent(c.line, () => <String>{}).addAll(ids);
      }
    }
  }

  /// Whether [ruleId] is suppressed on [line] (same line or the line above).
  bool isSuppressed(String ruleId, int line) {
    if (_fileSuppress.contains(ruleId)) return true;
    return (_suppress[line]?.contains(ruleId) ?? false) ||
        (_suppress[line - 1]?.contains(ruleId) ?? false);
  }

  /// Index of the bracket matching the one at [index], if any.
  int? matchOf(int index) => _match[index];

  Tok? at(int index) =>
      index >= 0 && index < tokens.length ? tokens[index] : null;

  /// Source text from token [start] to token [end] (inclusive).
  String text(int start, int end) {
    if (start > end || start < 0 || end >= tokens.length) return '';
    return source.substring(tokens[start].offset, tokens[end].end);
  }

  /// Whether the file imports `package:<pkg>/...`.
  bool importsPackage(String pkg) {
    for (var i = 0; i + 1 < tokens.length; i++) {
      final t = tokens[i];
      if (t.isIdent && (t.text == 'import' || t.text == 'export')) {
        final s = tokens[i + 1];
        if (s.isString && (s.value ?? '').startsWith('package:$pkg/')) {
          return true;
        }
      }
    }
    return false;
  }

  /// All string literal token indexes.
  Iterable<int> stringIndexes() sync* {
    for (var i = 0; i < tokens.length; i++) {
      if (tokens[i].isString) yield i;
    }
  }

  /// Whether string token [i] is part of an import/export/part directive.
  bool isDirectiveString(int i) {
    final p = at(i - 1);
    return p != null &&
        p.isIdent &&
        const {'import', 'export', 'part', 'of'}.contains(p.text);
  }

  /// Every call to one of [names].
  List<CallSite> calls(Set<String> names) {
    final out = <CallSite>[];
    for (var i = 0; i < tokens.length; i++) {
      final t = tokens[i];
      if (!t.isIdent || !names.contains(t.text)) continue;
      var j = i + 1;
      // Skip generic type arguments: name<...>(
      if (at(j)?.isPunct('<') ?? false) {
        var depth = 0;
        var k = j;
        for (; k < tokens.length && k < j + 40; k++) {
          final tk = tokens[k];
          if (tk.isPunct('<')) depth++;
          if (tk.isPunct('>')) depth--;
          if (tk.isPunct('>>')) depth -= 2;
          if (depth <= 0) break;
        }
        j = k + 1;
      }
      final open = at(j);
      if (open == null || !open.isPunct('(')) continue;
      final close = matchOf(j);
      if (close == null) continue;
      // Skip declarations such as `void foo() {` or `foo() =>`.
      if (_isDeclarationAfter(close) && !_hasReceiver(i)) {
        final before = at(i - 1);
        final isNew = before != null &&
            before.isIdent &&
            (before.text == 'new' || before.text == 'const');
        if (!isNew && _looksLikeDeclarationBefore(i)) continue;
      }
      out.add(CallSite(t.text, i, j, close, _receivers(i)));
    }
    return out;
  }

  bool _hasReceiver(int nameIndex) {
    final p = at(nameIndex - 1);
    return p != null && (p.isPunct('.') || p.isPunct('?.') || p.isPunct('..'));
  }

  bool _isDeclarationAfter(int closeParen) {
    final n = at(closeParen + 1);
    if (n == null) return false;
    if (n.isPunct('{') || n.isPunct('=>')) return true;
    if (n.isIdent && (n.text == 'async' || n.text == 'sync')) return true;
    return false;
  }

  bool _looksLikeDeclarationBefore(int nameIndex) {
    final p = at(nameIndex - 1);
    if (p == null) return true;
    if (p.isIdent) return true; // `void foo(`, `Future<void> foo(` etc.
    if (p.isPunct('>') || p.isPunct('?')) return true; // `List<int> foo(`
    if (p.isPunct('}') || p.isPunct(';')) return true; // top-level function
    return false;
  }

  List<String> _receivers(int nameIndex) {
    final out = <String>[];
    var k = nameIndex - 1;
    while (k >= 1) {
      final dot = tokens[k];
      if (!(dot.isPunct('.') || dot.isPunct('?.') || dot.isPunct('..'))) break;
      final r = tokens[k - 1];
      if (r.isIdent) {
        out.add(r.text);
        k -= 2;
      } else if (r.isPunct(')')) {
        // `foo().bar(` – take the callee name of the inner call.
        final open = matchOf(k - 1);
        if (open == null || open < 1) break;
        final callee = tokens[open - 1];
        out.add(callee.isIdent ? '${callee.text}()' : '()');
        k = open - 2;
      } else {
        break;
      }
    }
    return out;
  }

  /// Splits the arguments of the call whose `(` is at [open].
  List<Arg> args(int open) {
    final close = matchOf(open);
    if (close == null || close == open + 1) return const [];
    final out = <Arg>[];
    var segStart = open + 1;
    var k = open + 1;
    void flush(int endExclusive) {
      if (segStart >= endExclusive) return;
      final a = tokens[segStart];
      final b = at(segStart + 1);
      if (a.isIdent &&
          b != null &&
          b.isPunct(':') &&
          segStart + 2 < endExclusive) {
        out.add(Arg(a.text, segStart + 2, endExclusive - 1));
      } else {
        out.add(Arg(null, segStart, endExclusive - 1));
      }
    }

    while (k < close) {
      final t = tokens[k];
      if (t.kind == TokKind.punct &&
          (t.text == '(' || t.text == '[' || t.text == '{' || t.text == '?[')) {
        final m = matchOf(k);
        if (m != null && m < close) {
          k = m + 1;
          continue;
        }
      }
      if (t.isPunct(',')) {
        flush(k);
        segStart = k + 1;
      }
      k++;
    }
    flush(close);
    return out;
  }

  /// The value range of named argument [name], or null.
  Arg? namedArg(List<Arg> args, String name) {
    for (final a in args) {
      if (a.name == name) return a;
    }
    return null;
  }

  /// Finds the body of a function or method declared as `name(...) {` or
  /// `name(...) =>` in this file. Returns the token range of the body.
  ({int start, int end})? functionBody(String name, {bool topLevel = false}) {
    for (var i = 0; i < tokens.length; i++) {
      final t = tokens[i];
      if (topLevel && (t.isPunct('{') || t.isPunct('(') || t.isPunct('['))) {
        final end = matchOf(i);
        if (end != null) i = end;
        continue;
      }
      if (!t.isIdent || t.text != name) continue;
      final open = at(i + 1);
      if (open == null || !open.isPunct('(')) continue;
      final close = matchOf(i + 1);
      if (close == null) continue;
      var b = close + 1;
      final n = at(b);
      if (n != null && n.isIdent && (n.text == 'async' || n.text == 'sync')) {
        b++;
      }
      final body = at(b);
      if (body == null) continue;
      if (body.isPunct('{')) {
        final end = matchOf(b);
        if (end != null) return (start: b, end: end);
      } else if (body.isPunct('=>')) {
        var e = b + 1;
        while (e < tokens.length && !tokens[e].isPunct(';')) {
          final m = matchOf(e);
          e = (m != null && m > e) ? m + 1 : e + 1;
        }
        return (start: b, end: e - 1 < b ? b : e - 1);
      }
    }
    return null;
  }

  /// A name describing what string token [i] is assigned to, if any:
  /// `apiKey = '...'`, `apiKey: '...'`, `'apiKey': '...'`,
  /// `setString('token', ...)` (returns `token` for the value argument).
  String? contextName(int i) {
    final p1 = at(i - 1);
    final p2 = at(i - 2);
    if (p1 == null) return null;
    if ((p1.isPunct('=') || p1.isPunct(':') || p1.isPunct('??=')) &&
        p2 != null) {
      if (p2.isIdent) return p2.text;
      if (p2.isString) return p2.value;
      if (p2.isPunct(']')) {
        // map['key'] = '...'
        final open = matchOf(i - 2);
        if (open != null) {
          final k = at(open + 1);
          if (k != null && k.isString) return k.value;
        }
      }
    }
    return null;
  }
}

class _StrScan {
  _StrScan(this.end, this.value, this.interpolated);
  final int end;
  final String value;
  final bool interpolated;
}

class _Lexer {
  _Lexer(this.src, this.out, this.comments);

  final String src;
  final List<Tok> out;
  final List<SourceComment> comments;

  static const _multi = [
    '>>>=', '...?', '?..', '...', '??=', '>>=', '<<=', '~/=', //
    '=>', '==', '!=', '<=', '>=', '&&', '||', '??', '?.', '?[', '..', //
    '++', '--', '+=', '-=', '*=', '/=', '%=', '&=', '|=', '^=', '~/', '<<',
  ];

  bool _isIdentStart(int c) =>
      (c >= 0x41 && c <= 0x5A) ||
      (c >= 0x61 && c <= 0x7A) ||
      c == 0x5F ||
      c == 0x24;

  bool _isIdentPart(int c) => _isIdentStart(c) || (c >= 0x30 && c <= 0x39);

  bool _isDigit(int c) => c >= 0x30 && c <= 0x39;

  void run() {
    var i = 0;
    final n = src.length;
    while (i < n) {
      final c = src.codeUnitAt(i);
      // Whitespace
      if (c == 0x20 || c == 0x09 || c == 0x0A || c == 0x0D || c == 0xFEFF) {
        i++;
        continue;
      }
      // Comments
      if (c == 0x2F && i + 1 < n) {
        final d = src.codeUnitAt(i + 1);
        if (d == 0x2F) {
          var e = src.indexOf('\n', i);
          if (e < 0) e = n;
          comments.add(SourceComment(src.substring(i, e), i, 0));
          i = e;
          continue;
        }
        if (d == 0x2A) {
          var depth = 1;
          var e = i + 2;
          while (e < n && depth > 0) {
            if (src.startsWith('/*', e)) {
              depth++;
              e += 2;
            } else if (src.startsWith('*/', e)) {
              depth--;
              e += 2;
            } else {
              e++;
            }
          }
          comments.add(SourceComment(src.substring(i, e), i, 0));
          i = e;
          continue;
        }
      }
      // Raw strings r'..' / r"..."
      if ((c == 0x72 || c == 0x52) &&
          i + 1 < n &&
          (src.codeUnitAt(i + 1) == 0x27 || src.codeUnitAt(i + 1) == 0x22) &&
          (i == 0 || !_isIdentPart(src.codeUnitAt(i - 1)))) {
        final s = _scanString(i + 1, raw: true);
        out.add(Tok(TokKind.string, src.substring(i, s.end), i, s.end,
            value: s.value));
        i = s.end;
        continue;
      }
      if (_isIdentStart(c)) {
        var e = i + 1;
        while (e < n && _isIdentPart(src.codeUnitAt(e))) {
          e++;
        }
        out.add(Tok(TokKind.ident, src.substring(i, e), i, e));
        i = e;
        continue;
      }
      if (_isDigit(c) ||
          (c == 0x2E && i + 1 < n && _isDigit(src.codeUnitAt(i + 1)))) {
        var e = i + 1;
        while (e < n) {
          final d = src.codeUnitAt(e);
          if (_isIdentPart(d)) {
            e++;
          } else if (d == 0x2E &&
              e + 1 < n &&
              _isDigit(src.codeUnitAt(e + 1))) {
            e++;
          } else if ((d == 0x2B || d == 0x2D) &&
              (src.codeUnitAt(e - 1) == 0x65 ||
                  src.codeUnitAt(e - 1) == 0x45) &&
              !src.substring(i, e).toLowerCase().startsWith('0x')) {
            e++;
          } else {
            break;
          }
        }
        out.add(Tok(TokKind.number, src.substring(i, e), i, e));
        i = e;
        continue;
      }
      if (c == 0x27 || c == 0x22) {
        final s = _scanString(i, raw: false);
        out.add(Tok(TokKind.string, src.substring(i, s.end), i, s.end,
            value: s.value, interpolated: s.interpolated));
        i = s.end;
        continue;
      }
      var matched = false;
      for (final op in _multi) {
        if (src.startsWith(op, i)) {
          out.add(Tok(TokKind.punct, op, i, i + op.length));
          i += op.length;
          matched = true;
          break;
        }
      }
      if (matched) continue;
      out.add(Tok(TokKind.punct, src[i], i, i + 1));
      i++;
    }
  }

  /// Scans a string literal starting at the opening quote [start].
  _StrScan _scanString(int start, {required bool raw}) {
    final n = src.length;
    final q = src[start];
    final triple = src.startsWith('$q$q$q', start);
    final delim = triple ? '$q$q$q' : q;
    var j = start + delim.length;
    final buf = StringBuffer();
    var interp = false;
    while (j < n) {
      if (src.startsWith(delim, j)) {
        j += delim.length;
        return _StrScan(j, buf.toString(), interp);
      }
      final ch = src[j];
      if (!triple && (ch == '\n')) {
        break; // unterminated
      }
      if (!raw && ch == r'\' && j + 1 < n) {
        final e = src[j + 1];
        switch (e) {
          case 'n':
            buf.write('\n');
          case 't':
            buf.write('\t');
          case 'r':
            buf.write('\r');
          default:
            buf.write(e);
        }
        j += 2;
        continue;
      }
      if (!raw && ch == r'$' && j + 1 < n) {
        interp = true;
        if (src[j + 1] == '{') {
          final e = _skipInterpolation(j + 2);
          buf.write(src.substring(j, e));
          j = e;
          continue;
        }
      }
      buf.write(ch);
      j++;
    }
    return _StrScan(j, buf.toString(), interp);
  }

  /// Returns the index just after the `}` closing an interpolation whose
  /// content starts at [k].
  int _skipInterpolation(int k) {
    final n = src.length;
    var depth = 1;
    while (k < n) {
      final c = src[k];
      if (c == "'" || c == '"') {
        final raw = k > 0 && (src[k - 1] == 'r' || src[k - 1] == 'R');
        k = _scanString(k, raw: raw).end;
        continue;
      }
      if (c == '/' && k + 1 < n && src[k + 1] == '/') {
        final e = src.indexOf('\n', k);
        k = e < 0 ? n : e;
        continue;
      }
      if (c == '{') depth++;
      if (c == '}') {
        depth--;
        if (depth == 0) return k + 1;
      }
      k++;
    }
    return n;
  }
}
