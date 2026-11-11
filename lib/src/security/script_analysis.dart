import 'native_analysis.dart';

/// A bounded lexical view, not a JavaScript/TypeScript type checker. Offsets and
/// newlines are preserved. Template expressions and JSX expressions are visited;
/// literal text, comments and regex bodies cannot masquerade as executable calls.
class ScriptScan {
  ScriptScan(this.comments, this.code, this.literals, this.limited);
  final String comments, code;
  final List<NativeLiteral> literals;
  final bool limited;
}

ScriptScan scanScript(String source) {
  final comments = source.split(''), code = source.split('');
  final literals = <NativeLiteral>[];
  var i = 0, depth = 0;
  var limited = false;
  void blank(List<String> target, int start, int end) {
    for (var j = start; j < end; j++) {
      if (target[j] != '\n' && target[j] != '\r') target[j] = ' ';
    }
  }

  void hide(int start, int end) {
    blank(comments, start, end);
    blank(code, start, end);
  }

  late void Function([bool]) expression;
  void quoted() {
    final start = i, quote = source[i++];
    final content = i;
    while (i < source.length && source[i] != quote) {
      if (source[i] == r'\' && i + 1 < source.length) {
        i += 2;
      } else {
        i++;
      }
    }
    final end = i;
    if (i < source.length) {
      i++;
    } else {
      limited = true;
    }
    literals.add(NativeLiteral(start, i, source.substring(content, end)));
    blank(code, start, i);
  }

  void template() {
    final start = i++;
    var segment = start;
    final content = i;
    var interpolated = false;
    while (i < source.length && source[i] != '`') {
      if (source[i] == r'\' && i + 1 < source.length) {
        i += 2;
      } else if (source.startsWith(r'${', i)) {
        interpolated = true;
        hide(segment, i + 2);
        i += 2;
        expression(true);
        segment = i;
      } else {
        i++;
      }
    }
    final end = i;
    if (i < source.length) {
      i++;
    } else {
      limited = true;
    }
    if (!interpolated) {
      literals.add(NativeLiteral(start, i, source.substring(content, end)));
      blank(code, start, i);
    } else {
      hide(segment, i);
    }
  }

  bool regexStart() {
    final before =
        comments.sublist((i - 512).clamp(0, i), i).join().trimRight();
    if (before.isEmpty) return true;
    if (RegExp(
            r'[=(:,!&|?;{}\[]$|=>$|\b(?:return|throw|case|yield|await|else)$')
        .hasMatch(before)) {
      return true;
    }
    // After a closing parenthesis/brace this may be either a regex statement
    // or division. Avoid interpreting a possible regex body as executable code
    // and expose the ambiguity instead of granting a complete pass.
    if (RegExp(r'[)}]$').hasMatch(before)) {
      var cursor = i + 1;
      while (cursor < source.length && source[cursor] != '\n') {
        if (source[cursor] == r'\' && cursor + 1 < source.length) {
          cursor += 2;
          continue;
        }
        if (source[cursor] == '/') {
          limited = true;
          return true;
        }
        cursor++;
      }
    }
    return false;
  }

  void regex() {
    final start = i++;
    var inClass = false, closed = false;
    while (i < source.length && source[i] != '\n') {
      final ch = source[i++];
      if (ch == r'\' && i < source.length) {
        i++;
        continue;
      }
      if (ch == '[') inClass = true;
      if (ch == ']') inClass = false;
      if (ch == '/' && !inClass) {
        closed = true;
        break;
      }
    }
    while (i < source.length &&
        RegExp('[a-z]', caseSensitive: false).hasMatch(source[i])) {
      i++;
    }
    hide(start, i);
    if (!closed) limited = true;
  }

  late void Function() jsx;
  jsx = () {
    // JSX tags/attributes stay available for narrow property checks, while text
    // children are masked. TypeScript angle assertions/generics are ambiguous:
    // unfinished markup is reported as limited, never silently accepted.
    var tags = 0;
    while (i < source.length) {
      if (source[i] == '<') {
        final closing = source.startsWith('</', i);
        i += closing ? 2 : 1;
        while (i < source.length && source[i] != '>') {
          if (source[i] == '"' || source[i] == "'") {
            quoted();
          } else if (source[i] == '{') {
            i++;
            expression(true);
          } else {
            i++;
          }
        }
        if (i >= source.length) {
          limited = true;
          return;
        }
        final selfClosing = i > 0 && source[i - 1] == '/';
        i++;
        tags += closing ? -1 : (selfClosing ? 0 : 1);
        if (tags <= 0) return;
      } else if (source[i] == '{') {
        i++;
        expression(true);
      } else {
        final start = i;
        while (i < source.length && source[i] != '<' && source[i] != '{') {
          i++;
        }
        hide(start, i);
      }
    }
    limited = true;
  };

  expression = ([bool stopAtBrace = false]) {
    if (++depth > 64) {
      limited = true;
      hide(i, source.length);
      i = source.length;
      depth--;
      return;
    }
    while (i < source.length) {
      final start = i;
      if (source.startsWith('//', i)) {
        while (i < source.length && source[i] != '\n') {
          i++;
        }
        hide(start, i);
      } else if (source.startsWith('/*', i)) {
        final end = source.indexOf('*/', i + 2);
        if (end < 0) limited = true;
        i = end < 0 ? source.length : end + 2;
        hide(start, i);
      } else if (source[i] == '"' || source[i] == "'") {
        quoted();
      } else if (source[i] == '`') {
        template();
      } else if (source[i] == '/' && regexStart()) {
        regex();
      } else if (source[i] == '{') {
        i++;
        expression(true);
      } else if (source[i] == '}' && stopAtBrace) {
        i++;
        depth--;
        return;
      } else if (source[i] == '<' &&
          i + 1 < source.length &&
          RegExp(r'[A-Za-z>]').hasMatch(source[i + 1]) &&
          RegExp(r'(?:^|[=(,:;>?&|\[]|\breturn)\s*$')
              .hasMatch(comments.sublist((i - 512).clamp(0, i), i).join())) {
        jsx();
      } else {
        i++;
      }
    }
    if (stopAtBrace) limited = true;
    depth--;
  };
  expression();
  return ScriptScan(comments.join(), code.join(), literals, limited);
}

/// Explicit unsafe configuration patterns; no inferred data flow or runtime
/// protection verdicts. Values in ordinary strings/comments are filtered out.
final scriptPatterns = <String, List<RegExp>>{
  'AEG-N01': [RegExp(r'\brejectUnauthorized\s*:\s*false\b')],
  'AEG-N02': [
    RegExp(
        r'\ballow(?:UniversalAccessFromFileURLs|FileAccessFromFileURLs)\s*(?::\s*true\b|=\s*\{\s*true\s*\})'),
    RegExp('\\bmixedContentMode\\s*(?::|=)\\s*["\x27]always["\x27]'),
  ],
  'AEG-N03': [RegExp(r'\bCryptoJS\.(?:DES|TripleDES|RC4)\.encrypt\s*\(')],
  'AEG-N04': [],
};
