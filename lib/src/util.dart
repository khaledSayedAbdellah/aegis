/// Small helpers shared across the package.
library;

import 'dart:math' as math;

/// Converts a glob such as `lib/generated/**` or `**/*.g.dart` to a RegExp
/// matched against `/`-separated relative paths.
RegExp globToRegExp(String glob) {
  final b = StringBuffer('^');
  var i = 0;
  while (i < glob.length) {
    final c = glob[i];
    if (c == '*') {
      if (i + 1 < glob.length && glob[i + 1] == '*') {
        // `**/` matches zero or more directories.
        if (i + 2 < glob.length && glob[i + 2] == '/') {
          b.write('(?:.*/)?');
          i += 3;
        } else {
          b.write('.*');
          i += 2;
        }
        continue;
      }
      b.write('[^/]*');
    } else if (c == '?') {
      b.write('[^/]');
    } else if ('.+()|^\$[]{}\\'.contains(c)) {
      b.write('\\$c');
    } else {
      b.write(c);
    }
    i++;
  }
  b.write(r'$');
  return RegExp(b.toString());
}

/// Shannon entropy in bits per character.
double shannonEntropy(String s) {
  if (s.isEmpty) return 0;
  final counts = <int, int>{};
  for (final c in s.codeUnits) {
    counts[c] = (counts[c] ?? 0) + 1;
  }
  var e = 0.0;
  for (final n in counts.values) {
    final p = n / s.length;
    e -= p * (math.log(p) / math.ln2);
  }
  return e;
}

/// Redacts a secret so the report itself never leaks it:
/// `sk_live_abcdef123456` -> `sk_l…3456 (20 chars)`.
String redact(String secret) {
  final s = secret.trim();
  if (s.length <= 8) return '${'*' * s.length} (${s.length} chars)';
  return '${s.substring(0, 4)}…${s.substring(s.length - 4)} (${s.length} chars)';
}

/// Finds the `{ ... }` block that follows [keyword] in [text], skipping
/// strings and comments. Returns the block content (without braces) and the
/// offset where it starts, or null.
({String body, int offset})? findBlock(String text, String keyword,
    {int from = 0}) {
  final re = RegExp('(?<![A-Za-z0-9_])${RegExp.escape(keyword)}\\s*(\\([^)]*\\))?\\s*\\{');
  for (final m in re.allMatches(text, from)) {
    if (_insideCommentOrString(text, m.start)) continue;
    final open = m.end - 1;
    final close = matchingBrace(text, open);
    if (close == null) return null;
    return (body: text.substring(open + 1, close), offset: open + 1);
  }
  return null;
}

/// Index of the `}` matching the `{` at [open], skipping strings/comments.
int? matchingBrace(String text, int open) {
  var depth = 0;
  var i = open;
  while (i < text.length) {
    final c = text[i];
    if (c == '/' && i + 1 < text.length && text[i + 1] == '/') {
      final e = text.indexOf('\n', i);
      if (e < 0) return null;
      i = e;
      continue;
    }
    if (c == '/' && i + 1 < text.length && text[i + 1] == '*') {
      final e = text.indexOf('*/', i + 2);
      if (e < 0) return null;
      i = e + 2;
      continue;
    }
    if (c == '"' || c == "'") {
      var j = i + 1;
      while (j < text.length && text[j] != c && text[j] != '\n') {
        if (text[j] == '\\') j++;
        j++;
      }
      i = j + 1;
      continue;
    }
    if (c == '{') depth++;
    if (c == '}') {
      depth--;
      if (depth == 0) return i;
    }
    i++;
  }
  return null;
}

bool _insideCommentOrString(String text, int offset) {
  final lineStart = text.lastIndexOf('\n', offset > 0 ? offset - 1 : 0) + 1;
  final before = text.substring(lineStart, offset);
  if (before.contains('//')) return true;
  final lastOpen = text.lastIndexOf('/*', offset);
  if (lastOpen >= 0) {
    final lastClose = text.lastIndexOf('*/', offset);
    if (lastClose < lastOpen) return true;
  }
  return false;
}

/// Removes `//` and `/* */` comments from Groovy/Kotlin/Swift-like text,
/// keeping line breaks so offsets stay on the same lines.
String stripCComments(String text) {
  final b = StringBuffer();
  var i = 0;
  while (i < text.length) {
    final c = text[i];
    if (c == '"' || c == "'") {
      var j = i + 1;
      while (j < text.length && text[j] != c && text[j] != '\n') {
        if (text[j] == '\\') j++;
        j++;
      }
      final end = j < text.length ? j + 1 : text.length;
      b.write(text.substring(i, end));
      i = end;
      continue;
    }
    if (c == '/' && i + 1 < text.length && text[i + 1] == '/') {
      final e = text.indexOf('\n', i);
      if (e < 0) break;
      i = e;
      continue;
    }
    if (c == '/' && i + 1 < text.length && text[i + 1] == '*') {
      final e = text.indexOf('*/', i + 2);
      final end = e < 0 ? text.length : e + 2;
      b.write('\n' * '\n'.allMatches(text.substring(i, end)).length);
      i = end;
      continue;
    }
    b.write(c);
    i++;
  }
  return b.toString();
}

/// 1-based line of [offset] in [text].
int lineAt(String text, int offset) {
  var line = 1;
  final end = offset.clamp(0, text.length).toInt();
  for (var i = 0; i < end; i++) {
    if (text.codeUnitAt(i) == 0x0A) line++;
  }
  return line;
}

/// 1-based line of the first match of [pattern] in [text], or null.
int? lineOfFirst(String text, Pattern pattern) {
  final m = pattern.allMatches(text).cast<Match?>().firstWhere(
        (_) => true,
        orElse: () => null,
      );
  return m == null ? null : lineAt(text, m.start);
}

/// Normalizes a path to `/` separators.
String slash(String p) => p.replaceAll('\\', '/');

/// Parses a menu answer such as `3`, ` 3 `, `٣` (Arabic-Indic) or `۳`
/// (Persian). Returns null unless it is a number from 1 to [max].
int? parseMenuChoice(String? input, int max) {
  if (input == null) return null;
  final ascii = String.fromCharCodes(input.trim().runes.map((c) {
    if (c >= 0x0660 && c <= 0x0669) return c - 0x0660 + 0x30; // ٠-٩
    if (c >= 0x06F0 && c <= 0x06F9) return c - 0x06F0 + 0x30; // ۰-۹
    return c;
  }));
  final n = int.tryParse(ascii);
  return n != null && n >= 1 && n <= max ? n : null;
}
