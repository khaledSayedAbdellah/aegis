/// A light value-flow model on top of the tokenizer: what a value used at
/// one point of a function is known to be, from its definitions earlier in
/// that function and the functions around it.
///
/// It follows `final x = ...`, `x = ...`, `x += ...`, `for (final x in ...)`
/// and parameters. It does not follow calls into other functions, fields or
/// values across files: those are unknown, never clean.
library;

import 'dart_scanner.dart';

/// Where data that an attacker may control comes from.
enum SourceKind {
  /// Deep links and app links: `uni_links`, `app_links`, go_router state.
  link,

  /// Text typed by the user.
  input,

  /// HTTP response bodies.
  network,

  /// Platform-channel arguments.
  channel,

  /// Push notification payloads.
  push,
}

/// What a value is known to be.
class Origin {
  const Origin(this.kinds, {required this.clean, this.via});

  static const unknown = Origin({}, clean: false);
  static const constant = Origin({}, clean: true);

  /// The sources the value can come from.
  final Set<SourceKind> kinds;

  /// True when every part of the value is a literal, a constant or a number,
  /// so it can never carry outside data.
  final bool clean;

  /// The source expression, for messages.
  final String? via;

  bool get fromSource => kinds.isNotEmpty;

  Origin merge(Origin o) => Origin({...kinds, ...o.kinds},
      clean: clean && o.clean, via: via ?? o.via);
}

/// Expressions that read data from a source.
final _sources = <SourceKind, RegExp>{
  SourceKind.link: RegExp(
      r'\b(?:getInitial(?:App)?Link(?:String)?|getInitialUri|getLatest(?:App)?Link(?:String)?|getLatestUri)\s*\(|'
      r'\bstate\.(?:uri|pathParameters|queryParameters|location|matchedLocation|fullPath)\b|'
      // Read from a Uri (`uri.queryParameters`), not a variable or a named
      // argument with that name (`replace(queryParameters: {...})`).
      r'\??\.(?:queryParameters(?:All)?|pathParameters)\b(?!\s*:)'),
  SourceKind.input: RegExp(r'\b\w*[cC]ontroller\.(?:value\.)?text\b'),
  SourceKind.network:
      RegExp(r'\b\w*(?:[rR]esponse|[rR]esp|res)\.(?:body|bodyBytes|data)\b'),
  SourceKind.channel: RegExp(r'\b(?:call|methodCall)\.arguments\b'),
  SourceKind.push: RegExp(r'\b\w*[mM]essage\.data\b'),
};

/// Streams whose listener gets a link, and push streams.
final _linkStream = RegExp(
    r'^(?:uriLinkStream|linkStream|stringLinkStream|allUriLinkStream|allStringLinkStream)$');
final _pushStream = RegExp(r'^(?:onMessage|onMessageOpenedApp)$');

/// Named arguments whose callback gets what the user typed.
const _inputCallbacks = {
  'onChanged',
  'onSubmitted',
  'onFieldSubmitted',
  'onSaved',
  'validator',
};

/// Named arguments whose callback gets the route a deep link opened.
const _routeCallbacks = {'onGenerateRoute', 'onUnknownRoute'};

/// Calls that turn any value into a number, a flag or a length.
final _numeric = RegExp(
    r'^(?:(?:int|double|num)\.(?:parse|tryParse)\(.*\)|.*\.(?:length|isEmpty|isNotEmpty|hashCode|toInt\(\)|round\(\)|floor\(\)|ceil\(\)|truncate\(\)))$',
    dotAll: true);

const _numericTypes = {'int', 'double', 'num', 'bool'};

/// Whether [e] is a comparison or a test (`a == b`, `x.contains(y)`, `!x`),
/// not a conditional that picks one of two values.
bool _boolean(String e) {
  final plain = e.replaceAll(RegExp(r'\?\.|\?\[|\?\?'), '');
  if (plain.contains('?')) return false;
  return RegExp(
          r'==|!=|<=|>=|&&|\|\||^!|\.(?:contains|startsWith|endsWith|isScheme|hasMatch|any|every)\(')
      .hasMatch(plain);
}

const _keywords = {
  'true', 'false', 'null', 'this', 'super', 'new', 'const', 'await', 'as', //
  'is', 'in', 'final', 'var', 'late', 'required', 'return', 'if', 'else',
  'async', 'yield', 'throw', 'case', 'default',
};

const _control = {'if', 'for', 'while', 'switch', 'catch', 'on'};

/// Constants by naming convention: `kTable`, `TABLE_NAME`, `Tables.USERS`.
bool constantName(String e) =>
    RegExp(r'^(?:\w+\.)*(?:_?k[A-Z]\w*|[A-Z][A-Z0-9_]*)$').hasMatch(e) ||
    RegExp(r'^\d+(?:\.\d+)?$').hasMatch(e);

/// A function body: its `{` and `}` token indexes and its parameters.
class _Region {
  _Region(this.open, this.close, this.params);
  final int open;
  final int close;
  final Map<String, Origin> params;
}

/// One definition of a variable: the token range of the assigned value.
class Definition {
  Definition(this.start, this.end, {this.type});
  final int start;
  final int end;

  /// The declared type, when written.
  final String? type;
}

class ValueFlow {
  ValueFlow(this.f, {this.functions});

  final DartFile f;

  /// Finds a function or static method declared in the project by name, so
  /// a call takes the origin of what it returns.
  final FunctionLookup? functions;
  final _regionCache = <int, List<_Region>>{};

  /// Function bodies around token [i], innermost first.
  List<_Region> _regionsAt(int i) =>
      _regionCache[i] ??= List.unmodifiable(_findRegions(i));

  List<_Region> _findRegions(int i) {
    final out = <_Region>[];
    var k = i - 1;
    // A `;` or `,` at this level ends any arrow body further back.
    var ended = false;
    while (k >= 0) {
      final t = f.tokens[k];
      if (t.kind == TokKind.punct &&
          (t.text == ')' || t.text == ']' || t.text == '}')) {
        final m = f.matchOf(k);
        k = (m != null && m < k) ? m - 1 : k - 1;
        continue;
      }
      if (t.isPunct(';') || t.isPunct(',')) ended = true;
      if (t.isPunct('(') || t.isPunct('[') || t.isPunct('?[')) ended = false;
      if (t.isPunct('=>') && !ended) {
        out.add(_region(k, close: _expressionEnd(k + 1)));
      }
      if (t.isPunct('{')) {
        ended = false;
        final kind = _braceKind(k);
        if (kind == _Brace.type) break;
        if (kind == _Brace.function) out.add(_region(k));
      }
      k--;
    }
    return out;
  }

  _Brace _braceKind(int b) {
    var p = b - 1;
    var t = f.at(p);
    if (t == null) return _Brace.type;
    if (t.isPunct('*')) t = f.at(--p);
    if (t != null && t.isIdent && (t.text == 'async' || t.text == 'sync')) {
      t = f.at(--p);
    }
    if (t == null) return _Brace.type;
    if (t.isPunct(')')) {
      final open = f.matchOf(p);
      final callee = open == null ? null : f.at(open - 1);
      if (callee != null && callee.isIdent && _control.contains(callee.text)) {
        return _Brace.block;
      }
      return _Brace.function;
    }
    if (t.isIdent) {
      if (const {'else', 'try', 'finally', 'do'}.contains(t.text)) {
        return _Brace.block;
      }
      if (f.at(p - 1)?.text == 'get') return _Brace.function;
      return _Brace.type;
    }
    if (t.isPunct('>')) return _Brace.type;
    return _Brace.block;
  }

  /// The function whose body starts at [b] (`{` or `=>`).
  _Region _region(int b, {int? close}) {
    close ??= f.matchOf(b) ?? f.tokens.length - 1;
    var p = b - 1;
    if (f.at(p)?.isPunct('*') ?? false) p--;
    final a = f.at(p);
    if (a != null && a.isIdent && (a.text == 'async' || a.text == 'sync')) {
      p--;
    }
    final params = <String, Origin>{};
    if (f.at(p)?.isPunct(')') ?? false) {
      final open = f.matchOf(p);
      if (open != null) {
        final kind = _closureSource(open);
        var first = true;
        for (final (name, type) in _params(open, p)) {
          if (kind != null && (first || kind == SourceKind.input)) {
            params[name] = Origin({kind}, clean: false, via: name);
          } else if (_numericTypes.contains(type)) {
            params[name] = Origin.constant;
          } else {
            params[name] = Origin.unknown;
          }
          first = false;
        }
      }
    }
    return _Region(b, close, params);
  }

  /// The parameters between the parentheses at [open] and [close], with
  /// their declared types.
  List<(String, String?)> _params(int open, int close) {
    final out = <(String, String?)>[];
    var angle = 0;
    for (var k = open + 1; k < close; k++) {
      final t = f.tokens[k];
      if (t.isPunct('(')) {
        final m = f.matchOf(k);
        if (m != null && m < close) k = m;
        continue;
      }
      if (t.isPunct('<')) angle++;
      if (t.isPunct('>')) angle--;
      if (t.isPunct('>>')) angle -= 2;
      if (angle > 0 || !t.isIdent || _keywords.contains(t.text)) continue;
      final n = f.at(k + 1);
      if (n == null ||
          !(n.isPunct(',') ||
              n.isPunct(')') ||
              n.isPunct('}') ||
              n.isPunct(']') ||
              n.isPunct('=') ||
              n.isPunct(':'))) {
        continue;
      }
      String? type;
      var q = k - 1;
      if (f.at(q)?.isPunct('?') ?? false) q--;
      final before = f.at(q);
      if (before != null &&
          before.isIdent &&
          !const {'required', 'final', 'covariant', 'this'}
              .contains(before.text)) {
        type = before.text;
      }
      out.add((t.text, type));
    }
    return out;
  }

  /// What the closure whose parameter list opens at [open] is handed: a
  /// link, typed text, a push message or a platform call.
  SourceKind? _closureSource(int open) {
    final before = f.at(open - 1);
    if (before == null) return null;
    if (before.isPunct(':')) {
      final name = f.at(open - 2);
      if (name != null && _inputCallbacks.contains(name.text)) {
        return SourceKind.input;
      }
      // Flutter's deep linking passes the link's path as the route name.
      if (name != null && _routeCallbacks.contains(name.text)) {
        return SourceKind.link;
      }
    }
    if (!(before.isPunct('(') || before.isPunct(','))) return null;
    // The call this closure is an argument of.
    var k = open - 1;
    while (k >= 0 && !f.tokens[k].isPunct('(')) {
      final m = f.matchOf(k);
      k = (m != null && m < k) ? m - 1 : k - 1;
    }
    final callee = f.at(k - 1);
    if (callee == null || !callee.isIdent) return null;
    final receivers = <String>[];
    var r = k - 2;
    while (r >= 1 && (f.tokens[r].isPunct('.') || f.tokens[r].isPunct('?.'))) {
      final t = f.tokens[r - 1];
      if (t.isIdent) {
        receivers.add(t.text);
        r -= 2;
      } else if (t.isPunct(')')) {
        final m = f.matchOf(r - 1);
        if (m == null) break;
        final c = f.at(m - 1);
        if (c != null && c.isIdent) receivers.add(c.text);
        r = m - 2;
      } else {
        break;
      }
    }
    switch (callee.text) {
      case 'listen':
        if (receivers.any(_linkStream.hasMatch)) return SourceKind.link;
        if (receivers.any(_pushStream.hasMatch)) return SourceKind.push;
      case 'then':
        if (receivers.any((r) => _sources[SourceKind.link]!.hasMatch('$r('))) {
          return SourceKind.link;
        }
      case 'setMethodCallHandler':
        return SourceKind.channel;
    }
    return null;
  }

  /// The index to continue a forward scan toward [at] from token [k]: past
  /// the body of a function that ends before [at] (a sibling closure, whose
  /// variables and checks are not in scope at [at]).
  int _skipClosed(int k, int at) {
    if (!f.tokens[k].isPunct('{')) return k;
    final close = f.matchOf(k);
    if (close == null || close >= at) return k;
    return _braceKind(k) == _Brace.function ? close : k;
  }

  /// Definitions of [name] earlier than token [at] in the functions around
  /// it.
  List<Definition> definitions(String name, int at) {
    final regions = _regionsAt(at);
    if (regions.isEmpty) return const [];
    final from = regions.last.open;
    final out = <Definition>[];
    for (var k = from + 1; k < at; k++) {
      k = _skipClosed(k, at);
      final t = f.tokens[k];
      if (!t.isIdent || t.text != name) continue;
      final p = f.at(k - 1);
      if (p != null && (p.isPunct('.') || p.isPunct('?.') || p.isPunct('..'))) {
        continue;
      }
      final n = f.at(k + 1);
      if (n == null) continue;
      if (n.isIdent && n.text == 'in') {
        final close = _closeOf(k);
        if (close != null) out.add(Definition(k + 2, close - 1));
        continue;
      }
      if (!(n.isPunct('=') || n.isPunct('??=') || n.isPunct('+='))) continue;
      final end = _expressionEnd(k + 2);
      if (end < k + 2) continue;
      String? type;
      var q = k - 1;
      if (f.at(q)?.isPunct('?') ?? false) q--;
      final b = f.at(q);
      if (b != null &&
          b.isIdent &&
          !const {'final', 'var', 'const', 'late'}.contains(b.text)) {
        type = b.text;
      }
      out.add(Definition(k + 2, end, type: type));
    }
    return out;
  }

  /// The `)` closing the parentheses around token [k].
  int? _closeOf(int k) {
    var j = k;
    while (j < f.tokens.length) {
      final t = f.tokens[j];
      if (t.isPunct('(') || t.isPunct('[') || t.isPunct('{')) {
        final m = f.matchOf(j);
        if (m == null) return null;
        j = m + 1;
        continue;
      }
      if (t.isPunct(')')) return j;
      j++;
    }
    return null;
  }

  /// The last token of the expression starting at [start].
  int _expressionEnd(int start) {
    var e = start;
    while (e < f.tokens.length) {
      final t = f.tokens[e];
      if (t.isPunct(';') ||
          t.isPunct(',') ||
          t.isPunct(')') ||
          t.isPunct(']') ||
          t.isPunct('}')) {
        break;
      }
      final m = f.matchOf(e);
      e = (m != null && m > e) ? m + 1 : e + 1;
    }
    return e - 1;
  }

  /// What the value of tokens [start]..[end] is known to be.
  Origin rangeOrigin(int start, int end) => origin(f.text(start, end), start);

  /// What [expression], used at token [at], is known to be.
  Origin origin(String expression, int at) =>
      _origin(expression.trim(), at, 0, const {});

  Origin _origin(String e, int at, int depth, Set<String> seen) {
    if (e.isEmpty) return Origin.constant;
    // A number or a yes/no made from anything carries no text.
    if (constantName(e) || _numeric.hasMatch(e) || _boolean(e)) {
      return Origin.constant;
    }
    for (final entry in _sources.entries) {
      if (entry.value.hasMatch(e)) {
        return Origin({entry.key}, clean: false, via: e);
      }
    }
    final mini = DartFile('', e);
    var result = Origin.constant;
    final toks = mini.tokens;
    for (var i = 0; i < toks.length; i++) {
      final t = toks[i];
      if (t.isString) {
        if (t.interpolated) {
          for (final inner in interpolatedExpressions(t.value ?? '')) {
            result = result.merge(_origin(inner, at, depth, seen));
          }
        }
        continue;
      }
      if (!t.isIdent || _keywords.contains(t.text)) continue;
      final prev = i > 0 ? toks[i - 1] : null;
      final next = i + 1 < toks.length ? toks[i + 1] : null;
      final member = prev != null &&
          (prev.isPunct('.') || prev.isPunct('?.') || prev.isPunct('..'));
      // `helper(x)` or `Router.resolve(x)`: a function of this project.
      final staticCall = member &&
          i >= 2 &&
          toks[i - 2].isIdent &&
          RegExp(r'^[A-Z]').hasMatch(toks[i - 2].text);
      if (next != null && next.isPunct('(') && (!member || staticCall)) {
        final called = depth < 3 ? _callOrigin(t.text, depth, seen) : null;
        // Without the function's code the result is unknown; its arguments
        // are scanned next either way.
        result = result.merge(called ?? Origin.unknown);
        continue;
      }
      if (member) continue;
      if (next != null && (next.isPunct('(') || next.isPunct('<'))) {
        result = result.merge(Origin.unknown);
        continue;
      }
      if (constantName(t.text) || RegExp(r'^[A-Z]').hasMatch(t.text)) {
        continue; // A constant or a class name such as `Uri`.
      }
      result = result.merge(_resolve(t.text, at, depth, seen));
    }
    return result;
  }

  /// What the function [name] of the project returns, or null when its
  /// code is not in the project. A value it checks before returning
  /// (`if (uri.host != ...) return null; return uri;`) no longer counts as
  /// link data.
  Origin? _callOrigin(String name, int depth, Set<String> seen) {
    final key = '()$name';
    if (seen.contains(key)) return Origin.unknown;
    final found = functions?.call(name, f);
    if (found == null) return null;
    final (file, start, end) = found;
    final flow =
        identical(file, f) ? this : ValueFlow(file, functions: functions);
    final returns = <(int, int)>[];
    if (file.tokens[start].isPunct('=>')) {
      returns.add((start + 1, end));
    } else {
      for (var k = start + 1; k < end; k++) {
        final t = file.tokens[k];
        if (!t.isIdent || t.text != 'return') continue;
        var e = k + 1;
        while (e < end && !file.tokens[e].isPunct(';')) {
          final m = file.matchOf(e);
          e = (m != null && m > e) ? m + 1 : e + 1;
        }
        if (e > k + 1) returns.add((k + 1, e - 1));
      }
    }
    if (returns.isEmpty) return Origin.unknown;
    Origin? result;
    for (final (a, b) in returns) {
      final text = file.text(a, b);
      var o = flow._origin(text.trim(), a, depth + 1, {...seen, key});
      if (o.kinds.contains(SourceKind.link)) {
        final names = {
          for (final n in flow.namesBehind(text, a))
            if (flow.origin(n, a).kinds.contains(SourceKind.link)) n
        };
        if (flow.checkedBefore(names, a)) {
          o = Origin({...o.kinds}..remove(SourceKind.link), clean: false);
        }
      }
      result = result == null ? o : result.merge(o);
    }
    return result;
  }

  Origin _resolve(String name, int at, int depth, Set<String> seen) {
    if (seen.contains(name) || depth > 6) return Origin.unknown;
    final regions = _regionsAt(at);
    Origin? result;
    for (final r in regions) {
      final p = r.params[name];
      if (p != null) {
        result = p;
        break;
      }
    }
    for (final d in definitions(name, at)) {
      final o = _numericTypes.contains(d.type)
          ? Origin.constant
          : _origin(f.text(d.start, d.end).trim(), d.start, depth + 1,
              {...seen, name});
      result = result == null ? o : result.merge(o);
    }
    if (result == null && _fileConstant(name)) return Origin.constant;
    return result ?? Origin.unknown;
  }

  bool _fileConstant(String name) {
    for (var k = 1; k + 1 < f.tokens.length; k++) {
      final t = f.tokens[k];
      if (t.isIdent &&
          t.text == name &&
          f.tokens[k + 1].isPunct('=') &&
          (f.tokens[k - 1].text == 'const' || f.at(k - 2)?.text == 'const')) {
        return true;
      }
    }
    return false;
  }

  /// The variables [expression] at [at] is built from, and the variables
  /// those were built from.
  Set<String> namesBehind(String expression, int at) {
    final out = <String>{};
    void walk(String e, int at, int depth) {
      if (depth > 6) return;
      for (final name in _roots(e)) {
        if (!out.add(name)) continue;
        for (final d in definitions(name, at)) {
          walk(f.text(d.start, d.end), d.start, depth + 1);
        }
      }
    }

    walk(expression, at, 0);
    return out;
  }

  /// Variable names read by [e]: not members, calls or constants.
  /// Variable names read by [e]: not members, calls or constants.
  Iterable<String> roots(String e) => _roots(e);

  Iterable<String> _roots(String e) sync* {
    final toks = DartFile('', e).tokens;
    for (var i = 0; i < toks.length; i++) {
      final t = toks[i];
      if (t.isString && t.interpolated) {
        for (final inner in interpolatedExpressions(t.value ?? '')) {
          yield* _roots(inner);
        }
        continue;
      }
      if (!t.isIdent || _keywords.contains(t.text)) continue;
      final prev = i > 0 ? toks[i - 1] : null;
      if (prev != null && (prev.isPunct('.') || prev.isPunct('?.'))) continue;
      final next = i + 1 < toks.length ? toks[i + 1] : null;
      if (next != null && next.isPunct('(')) continue;
      if (constantName(t.text) || RegExp(r'^[A-Z]').hasMatch(t.text)) {
        continue;
      }
      yield t.text;
    }
  }

  /// Whether a condition before token [at] in the same function reads one
  /// of [names]: `if (...)`, `while (...)`, `switch (...)`, or a ternary.
  bool checkedBefore(Set<String> names, int at) {
    final regions = _regionsAt(at);
    if (regions.isEmpty || names.isEmpty) return false;
    final word = RegExp('\\b(?:${names.map(RegExp.escape).join('|')})\\b');
    // A condition and the variables it is made of: `final ok = ...; if (ok)`.
    // Null and empty tests say nothing about what the value is.
    String expand(String cond, int at) => [
          cond,
          for (final name in _roots(cond))
            if (!names.contains(name))
              for (final d in definitions(name, at)) f.text(d.start, d.end),
        ].join(' ').replaceAll(_presenceTest, ' ');
    for (var k = regions.last.open + 1; k < at; k++) {
      k = _skipClosed(k, at);
      final t = f.tokens[k];
      if (t.isIdent && const {'if', 'while', 'switch'}.contains(t.text)) {
        final open = k + 1;
        if (!(f.at(open)?.isPunct('(') ?? false)) continue;
        final close = f.matchOf(open);
        if (close == null) continue;
        if (word.hasMatch(expand(f.text(open + 1, close - 1), open))) {
          return true;
        }
      } else if (t.isPunct('?') && k + 1 < at) {
        // `cond ? a : b`: look back to the start of the condition.
        var s = k - 1;
        while (s > regions.last.open) {
          final b = f.tokens[s];
          if (b.isPunct(';') ||
              b.isPunct('{') ||
              b.isPunct('(') ||
              b.isPunct(',') ||
              b.isPunct('=') ||
              b.isPunct('=>')) {
            break;
          }
          final m = f.matchOf(s);
          s = (m != null && m < s) ? m - 1 : s - 1;
        }
        final cond = expand(f.text(s + 1, k - 1), k);
        if (cond.isNotEmpty &&
            RegExp(r'==|!=|contains|startsWith|endsWith|isScheme|allow|trust|valid|match',
                    caseSensitive: false)
                .hasMatch(cond) &&
            word.hasMatch(cond)) {
          return true;
        }
      }
    }
    return false;
  }
}

enum _Brace { function, block, type }

/// Finds a function by name: its file and the token range of its body (from
/// `{` or `=>`).
/// [from] is the file the call is in.
typedef FunctionLookup = (DartFile, int, int)? Function(
    String name, DartFile from);

final _lookups = Expando<FunctionLookup>();

/// A [FunctionLookup] over [files], built once per list. The calling file
/// comes first; a private name (`_x`) is looked up only there; a name
/// declared in more than one other file is ambiguous and stays unknown.
FunctionLookup projectFunctions(List<DartFile> files) =>
    _lookups[files] ??= () {
      final elsewhere = <String, (DartFile, int, int)?>{};
      return (String name, DartFile from) {
        final own = from.functionBody(name);
        if (own != null) return (from, own.start, own.end);
        if (name.startsWith('_')) return null;
        return elsewhere.putIfAbsent(name, () {
          (DartFile, int, int)? found;
          for (final file in files) {
            if (!file.source.contains(name)) continue;
            final body = file.functionBody(name);
            if (body == null) continue;
            if (found != null) return null; // Declared twice: ambiguous.
            found = (file, body.start, body.end);
          }
          return found;
        });
      };
    }();

/// `x != null`, `null == x`, `x.isEmpty`, `x?.isNotEmpty == true`.
final _presenceTest = RegExp(
    r'[\w.?!\[\]\x27"]+\s*[!=]=\s*null\b|\bnull\s*[!=]=\s*[\w.?!]+|'
    r'[\w.?!\[\]\x27"]+\??\.(?:isEmpty|isNotEmpty)\b(?:\s*[!=]=\s*(?:true|false))?');

/// The expressions pasted into a string value (`$name`, `${...}`).
Iterable<String> interpolatedExpressions(String value) sync* {
  var i = 0;
  while (i < value.length) {
    if (value[i] == r'$' && i + 1 < value.length) {
      if (value[i + 1] == '{') {
        var depth = 1, j = i + 2;
        while (j < value.length && depth > 0) {
          if (value[j] == '{') depth++;
          if (value[j] == '}') depth--;
          j++;
        }
        yield value.substring(i + 2, j - 1).trim();
        i = j;
        continue;
      }
      final m = RegExp(r'[A-Za-z_]\w*').matchAsPrefix(value, i + 1);
      if (m != null) {
        yield m[0]!;
        i = m.end;
        continue;
      }
    }
    i++;
  }
}
