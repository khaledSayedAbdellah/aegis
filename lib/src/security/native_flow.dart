/// A line-based value tracker for Kotlin, Java and Swift: data that comes
/// from outside the app, the variables it is copied into within one
/// function, and the calls it reaches.
library;

/// What an Intent or a link brings from another app.
final nativeLinkSource = RegExp(
    r'\bintent\??\.(?:data|dataString|extras|getData\(\)|getDataString\(\)|getExtras\(\))|'
    r'\bgetIntent\s*\(\s*\)\s*\.\s*(?:getData|getDataString|getExtras)\s*\(|'
    r'\bget(?:String|Parcelable|Serializable|CharSequence|ByteArray)Extra\s*[(<]|'
    r'\.getQueryParameter(?:s|Names)?\s*\(|'
    // Swift: `open url: URL`, `.onOpenURL { url in`, Universal Links.
    r'\buserActivity\.webpageURL\b|\.queryItems\b|\.onOpenURL\s*\{\s*(\w+)\s+in');

/// Swift handlers whose `url` parameter is the incoming link.
final swiftLinkHandler = RegExp(
    r'func\s+(?:application|scene)\s*\([^)]*\bopen(?:URLContexts)?\s+(\w+)\s*:');

final _check = RegExp(
    r'\b(?:if|when|guard|require|check|switch)\b.*(?:host|scheme|startsWith|hasPrefix|'
    r'contains|==|!=|equals|allow|valid|trust|matches|whitelist|signature|verify)',
    caseSensitive: false);

/// Declarations: `val url = ...`, `String url = ...`, `let url = ...`.
final _decl = RegExp(
    r'^\s*(?:(?:private|public|final|internal)\s+)*(?:val|var|let|byte\s*\[\]|String|Uri|URL|Intent|[A-Z][\w<>\[\]]*)\s+(\w+)\s*(?::\s*[\w.?<>\[\]]+\s*)?=\s*(.+)$');

/// A new function: data from one does not flow into the next.
final _function = RegExp(
    r'^\s*(?:@\w+\s+)*(?:(?:override|private|public|protected|internal|static|final|open|suspend|@objc)\s+)*(?:fun|func)\s|'
    r'^\s*(?:(?:public|private|protected|static|final|synchronized)\s+)+[\w<>\[\]]+\s+\w+\s*\(');

final _guardCall = RegExp(
    r'\b\w*(?:valid|sanit|allow|trust|safe|verif|whitelist)\w*\s*\(',
    caseSensitive: false);

/// Data from outside reaching a call.
class NativeFlowHit {
  NativeFlowHit(this.line, this.call, this.value);

  /// 1-based line of the call.
  final int line;
  final String call;

  /// The variable or expression that carries the data.
  final String value;
}

/// The calls matching [sinks] (group 1 names the call) that receive data
/// matching [sources], directly or through variables declared from it in
/// the same function, with no check of it in between. [accept] can reject a
/// call by its line. [code] should have its comments removed.
List<NativeFlowHit> nativeFlows(
  String code, {
  required RegExp sources,
  required RegExp sinks,
  bool Function(String call, String line)? accept,
}) {
  final out = <NativeFlowHit>[];
  final lines = code.split('\n');
  var tainted = <String, int>{}; // variable -> line it got the data
  bool mentions(String text, String v) =>
      RegExp('\\b${RegExp.escape(v)}\\b').hasMatch(text);
  for (var i = 0; i < lines.length; i++) {
    final line = lines[i];
    if (_function.hasMatch(line)) tainted = {};
    final handler = swiftLinkHandler.firstMatch(line);
    if (handler != null && sources.pattern.contains(nativeLinkSource.pattern)) {
      tainted[handler[1]!] = i;
    }
    // A closure parameter named by the source pattern (`{ url in`).
    final closure = sources.firstMatch(line);
    if (closure != null) {
      for (var g = 1; g <= closure.groupCount; g++) {
        if (closure[g] != null) tainted[closure[g]!] = i;
      }
    }
    bool carries(String text) =>
        sources.hasMatch(text) || tainted.keys.any((v) => mentions(text, v));
    for (final m in sinks.allMatches(line)) {
      final call = m[1]!;
      if (accept != null && !accept(call, line)) continue;
      final args = line.substring(m.end);
      if (!carries(args) || _guardCall.hasMatch(args)) continue;
      final names = [
        for (final v in tainted.keys)
          if (mentions(args, v)) v
      ];
      final from = names.isEmpty
          ? i
          : names.map((v) => tainted[v]!).reduce((a, b) => a < b ? a : b);
      final checked = [for (var k = from; k <= i; k++) lines[k]].any((l) =>
          _check.hasMatch(l) &&
          (names.isEmpty || names.any((v) => mentions(l, v))));
      if (checked) continue;
      final value = names.isNotEmpty ? names.first : args.split(')').first;
      out.add(NativeFlowHit(i + 1, call, value.trim()));
      break;
    }
    final decl = _decl.firstMatch(line);
    if (decl != null && carries(decl[2]!) && !_guardCall.hasMatch(decl[2]!)) {
      tainted[decl[1]!] = i;
    }
  }
  return out;
}
