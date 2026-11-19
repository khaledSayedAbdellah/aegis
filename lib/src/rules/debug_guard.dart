/// Whether code runs only in debug builds, read from the bracket structure
/// of the file (comments are not tokens, so they never count).
library;

import '../dart_scanner.dart';

/// Whether [name] is a debug-only flag, read word by word: `kDebugMode`,
/// `isDebug`, `devMode`, `verbose`, `enableLogging`, `isLogEnabled`,
/// `kProfileMode`. Not `isDebuggerAttached` or `isDevice`.
bool _isDebugName(String name) {
  final words = RegExp(r'[A-Z]?[a-z0-9]+|[A-Z]+(?![a-z])')
      .allMatches(name)
      .map((m) => m[0]!.toLowerCase())
      .toSet();
  if (words.intersection(
      const {'debug', 'dev', 'development', 'verbose'}).isNotEmpty) {
    return true;
  }
  if (name == 'kProfileMode') return true;
  final log = words.intersection(const {'log', 'logs', 'logging'}).isNotEmpty;
  return log && words.intersection(const {'enable', 'enabled'}).isNotEmpty;
}

final _parentsOf = Expando<List<int>>();

/// For each token, the innermost open bracket around it, or -1.
List<int> _parents(DartFile f) => _parentsOf[f] ??= () {
      final out = List<int>.filled(f.tokens.length, -1);
      final stack = <int>[];
      for (var i = 0; i < f.tokens.length; i++) {
        final t = f.tokens[i];
        final closing = t.kind == TokKind.punct &&
            (t.text == ')' || t.text == ']' || t.text == '}');
        if (closing && stack.isNotEmpty && f.matchOf(i) == stack.last) {
          stack.removeLast();
        }
        out[i] = stack.isEmpty ? -1 : stack.last;
        if (_opens(t) && f.matchOf(i) != null) stack.add(i);
      }
      return out;
    }();

bool _opens(Tok t) =>
    t.kind == TokKind.punct &&
    (t.text == '(' || t.text == '[' || t.text == '{' || t.text == '?[');

/// Whether the code at token [index] only runs in debug builds: inside the
/// body of `if (kDebugMode)` / `if (!kReleaseMode)` (or the `else` of
/// `if (kReleaseMode)`), after a braceless `if (kDebugMode)`, in the true
/// branch of `kDebugMode ? ... : ...`, inside `assert(...)`, or after an
/// early `if (!kDebugMode) return;` in the same function.
bool guardedByDebugBuild(DartFile f, int index) {
  if (index < 0 || index >= f.tokens.length) return false;
  final parents = _parents(f);
  var pos = index;
  var b = parents[index];
  while (true) {
    if (_statementGuarded(f, b, pos)) return true;
    if (b < 0) break;
    final open = f.tokens[b];
    if (open.isPunct('(') && (f.at(b - 1)?.text == 'assert')) return true;
    if (open.isPunct('{')) {
      if (_blockGuarded(f, b)) return true;
      if (_isFunctionBody(f, b) && _returnsUnlessDebug(f, b, pos)) {
        return true;
      }
    }
    pos = b;
    b = parents[b];
  }
  return false;
}

/// `if (cond) { here }` with a debug-only cond, or `else { here }` after a
/// release-only one.
bool _blockGuarded(DartFile f, int brace) {
  final cond = _ifCondition(f, brace - 1);
  if (cond != null) return _debugOnly(f, cond.$1, cond.$2);
  final before = f.at(brace - 1);
  if (before != null && before.isIdent && before.text == 'else') {
    final thenClose = brace - 2;
    final thenOpen = f.matchOf(thenClose);
    if (thenOpen != null && f.tokens[thenClose].isPunct('}')) {
      final c = _ifCondition(f, thenOpen - 1);
      if (c != null) return _releaseOnly(f, c.$1, c.$2);
    }
  }
  return false;
}

/// The condition range of `if ( ... )` when [close] is its `)`.
(int, int)? _ifCondition(DartFile f, int close) {
  final t = f.at(close);
  if (t == null || !t.isPunct(')')) return null;
  final open = f.matchOf(close);
  if (open == null || open < 1) return null;
  final kw = f.tokens[open - 1];
  if (!kw.isIdent || kw.text != 'if') return null;
  return (open + 1, close - 1);
}

/// The statement at this level that contains [pos] (inside the bracket at
/// [b]): a braceless `if (kDebugMode) ...;`, a collection `if`, or a ternary whose true branch
/// holds [pos].
bool _statementGuarded(DartFile f, int b, int pos) {
  var s = pos - 1;
  while (s > b) {
    final t = f.tokens[s];
    if (t.isPunct(';') || t.isPunct('{') || t.isPunct(',')) break;
    if (t.kind == TokKind.punct &&
        (t.text == ')' || t.text == ']' || t.text == '}')) {
      final m = f.matchOf(s);
      if (t.text == '}' && m != null && m < s && _isStatementBlock(f, m)) {
        break;
      }
      s = (m != null && m < s) ? m - 1 : s - 1;
      continue;
    }
    s--;
  }
  final start = s + 1;
  // `if (cond) here;` / `else if (cond) here;`
  var first = f.at(start);
  var ifAt = start;
  if (first != null && first.isIdent && first.text == 'else') {
    first = f.at(++ifAt);
  }
  if (first != null && first.isIdent && first.text == 'if') {
    final open = ifAt + 1;
    final close = f.matchOf(open);
    if (close != null && close < pos && _debugOnly(f, open + 1, close - 1)) {
      return true;
    }
  }
  // `cond ? here : other`
  for (var q = pos - 1; q >= start; q--) {
    final t = f.tokens[q];
    if (t.kind == TokKind.punct &&
        (t.text == ')' || t.text == ']' || t.text == '}')) {
      final m = f.matchOf(q);
      if (m != null && m < q) q = m;
      continue;
    }
    if (t.isPunct(':')) return false; // In the false branch.
    if (t.isPunct('?')) {
      var c = q - 1;
      while (c >= start) {
        final u = f.tokens[c];
        if (u.isPunct('=') ||
            u.isPunct('=>') ||
            u.isPunct(',') ||
            u.isPunct('(') ||
            (u.isIdent && u.text == 'return')) {
          break;
        }
        if (u.kind == TokKind.punct &&
            (u.text == ')' || u.text == ']' || u.text == '}')) {
          final m = f.matchOf(c);
          c = (m != null && m < c) ? m - 1 : c - 1;
          continue;
        }
        c--;
      }
      return _debugOnly(f, c + 1, q - 1);
    }
  }
  return false;
}

/// A `{` that opens a function body, a class body or a statement block
/// (not a map or set literal).
bool _isStatementBlock(DartFile f, int brace) {
  final before = f.at(brace - 1);
  if (before == null) return true;
  if (before.isPunct(')') || before.isPunct('>')) return true;
  if (before.isIdent) return true; // else, try, async, class names...
  return false;
}

bool _isFunctionBody(DartFile f, int brace) {
  var p = brace - 1;
  var t = f.at(p);
  if (t != null && t.isPunct('*')) t = f.at(--p);
  if (t != null && t.isIdent && (t.text == 'async' || t.text == 'sync')) {
    t = f.at(--p);
  }
  if (t == null || !t.isPunct(')')) return false;
  final open = f.matchOf(p);
  final kw = open == null ? null : f.at(open - 1);
  return kw == null ||
      !(kw.isIdent &&
          const {'if', 'for', 'while', 'switch', 'catch'}.contains(kw.text));
}

/// Whether the function body at [brace] has, before [pos] and at its top
/// level, `if (!kDebugMode) return;` (or `throw`, or `{ return; }`).
bool _returnsUnlessDebug(DartFile f, int brace, int pos) {
  final parents = _parents(f);
  for (var k = brace + 1; k < pos; k++) {
    final t = f.tokens[k];
    if (!t.isIdent || t.text != 'if' || parents[k] != brace) continue;
    final open = k + 1;
    final close = f.matchOf(open);
    if (close == null || close >= pos) continue;
    if (!_releaseOnly(f, open + 1, close - 1)) continue;
    var next = f.at(close + 1);
    if (next != null && next.isPunct('{')) next = f.at(close + 2);
    if (next != null &&
        next.isIdent &&
        (next.text == 'return' || next.text == 'throw')) {
      return true;
    }
  }
  return false;
}

/// The atoms of a condition split on `op` at its top level.
List<(int, int)> _split(DartFile f, int start, int end, String op) {
  final out = <(int, int)>[];
  var from = start;
  for (var k = start; k <= end; k++) {
    final t = f.tokens[k];
    if (_opens(t)) {
      final m = f.matchOf(k);
      if (m != null && m <= end) k = m;
      continue;
    }
    if (t.isPunct(op)) {
      out.add((from, k - 1));
      from = k + 1;
    }
  }
  out.add((from, end));
  return out;
}

/// `kDebugMode`, `!kReleaseMode`, `config.enableLogging`, `isDebug == true`;
/// `true` when the atom is negated and [negated] is asked for.
bool _atom(DartFile f, int start, int end, {required bool negated}) {
  var s = start, e = end;
  // Drop wrapping parentheses.
  while (s <= e && f.tokens[s].isPunct('(') && f.matchOf(s) == e) {
    s++;
    e--;
  }
  if (s > e) return false;
  var not = false;
  if (f.tokens[s].isPunct('!')) {
    not = true;
    s++;
  }
  // `x == true` / `x == false`.
  if (e - s >= 2 && f.tokens[e - 1].isPunct('==')) {
    final v = f.tokens[e].text;
    if (v == 'false') not = !not;
    if (v == 'true' || v == 'false') e -= 2;
  }
  // The last name of a member chain: `config.enableLogging`.
  for (var k = s; k <= e; k++) {
    final t = f.tokens[k];
    if (!(t.isIdent || t.isPunct('.') || t.isPunct('?.'))) return false;
  }
  final name = f.tokens[e].text;
  final release = name == 'kReleaseMode';
  final debug = _isDebugName(name);
  if (!release && !debug) return false;
  final debugOnly = (debug && !not) || (release && not);
  return negated ? !debugOnly : debugOnly;
}

/// Whether the condition is only true in debug builds.
bool _debugOnly(DartFile f, int start, int end) {
  if (start > end) return false;
  return _split(f, start, end, '||').every((d) => _split(f, d.$1, d.$2, '&&')
      .any((c) => _atom(f, c.$1, c.$2, negated: false)));
}

/// Whether the condition is only true in release builds (`!kDebugMode`,
/// `kReleaseMode`).
bool _releaseOnly(DartFile f, int start, int end) {
  if (start > end) return false;
  return _split(f, start, end, '||').every((d) => _split(f, d.$1, d.$2, '&&')
      .any((c) => _atom(f, c.$1, c.$2, negated: true)));
}
