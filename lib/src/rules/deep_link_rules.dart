/// Data from a deep link that reaches a sensitive action without a check.
library;

import '../dart_flow.dart';
import '../dart_scanner.dart';
import '../l10n/messages.g.dart';
import '../model.dart';
import '../project.dart';
import '../security/native_analysis.dart' show withoutComments;
import 'rule.dart';

/// Code that reads deep links: `uni_links`, `app_links`, go_router.
final _readsLinks = RegExp(
    r'\b(?:uriLinkStream|linkStream|stringLinkStream|allUriLinkStream|allStringLinkStream|getInitial(?:App)?Link|getInitialUri|getLatest(?:App)?Link|getLatestUri)\b|'
    r'\bstate\.(?:uri|pathParameters|queryParameters)\b|\b(?:queryParameters|pathParameters)\b|'
    r'\bonGenerateRoute\s*:');

/// Wrappers that check or clean the value they are given.
final _guard = RegExp(
    r'\b\w*(?:valid|sanit|allow|trust|safe|verif|whitelist|check)\w*\s*\(',
    caseSensitive: false);

/// Receivers of HTTP calls.
final _httpClient = RegExp(r'^_?(?:http|dio|client|httpClient|api|apiClient)$',
    caseSensitive: false);

class DeepLinkActionRule extends Rule {
  const DeepLinkActionRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-D19',
        title: Bilingual(En.deepLinkActionTitle, Ar.deepLinkActionTitle),
        passTitleText: Bilingual(En.deepLinkActionPass, Ar.deepLinkActionPass),
        description: Bilingual(
            En.deepLinkActionDescription, Ar.deepLinkActionDescription),
        fix: Bilingual(En.deepLinkActionFix, Ar.deepLinkActionFix),
        severity: Severity.medium,
        l2Severity: Severity.high,
        masvs: ['MASVS-PLATFORM-1'],
        maswe: ['MASWE-0029'],
        cwe: 'CWE-939',
        profiles: {MasProfile.l1, MasProfile.l2, MasProfile.r},
      );

  /// Sinks: opening a URL, loading a page, a file path, an HTTP request.
  static const _sinks = {
    'launchUrl', 'launchUrlString', 'launch', //
    'loadRequest', 'loadUrl', 'WebUri', 'URLRequest',
    'File', 'Directory',
    'get', 'post', 'put', 'patch', 'delete', 'head', 'read',
  };

  static const _http = {
    'get',
    'post',
    'put',
    'patch',
    'delete',
    'head',
    'read'
  };

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final out = <Finding>[];
    // Link data can reach a file through a helper in another file, so every
    // file is read once any file reads links.
    final readsLinks =
        project.dartFiles.any((f) => _readsLinks.hasMatch(f.source));
    for (final f in readsLinks ? project.dartFiles : const <DartFile>[]) {
      final flow = ValueFlow(f, functions: projectFunctions(project.dartFiles));
      for (final c in f.calls(_sinks)) {
        if (_http.contains(c.name) &&
            !(c.receiver != null && _httpClient.hasMatch(c.receiver!))) {
          continue;
        }
        final args = f.args(c.open);
        if (args.isEmpty) continue;
        final arg = args.where((a) => a.name == null).firstOrNull ??
            (c.name == 'URLRequest' ? f.namedArg(args, 'url') : null);
        if (arg == null) continue;
        final text = f.text(arg.start, arg.end);
        if (_guard.hasMatch(text)) continue;
        final origin = flow.rangeOrigin(arg.start, arg.end);
        if (!origin.kinds.contains(SourceKind.link)) continue;
        final names = {
          for (final n in flow.namesBehind(text, arg.start))
            if (flow.origin(n, arg.start).kinds.contains(SourceKind.link)) n
        };
        if (flow.checkedBefore(names, c.close)) continue;
        final value = shorten(text, 40);
        out.add(at(
            f, c.nameIndex, En.deepLinkAction(value: value, call: c.name),
            messageAr: Ar.deepLinkAction(value: value, call: c.name)));
      }
    }
    final native = _native(project);
    out.addAll(native.$1);
    if (!readsLinks && !native.$2) {
      return RuleCheck.notApplicableLocalized(
          En.deepLinkActionNone, Ar.deepLinkActionNone);
    }
    return RuleCheck(out);
  }
}

/// Kotlin / Java: what an Intent or a link brings from another app.
final _nativeSource = RegExp(
    r'\bintent\??\.(?:data|dataString|extras|getData\(\)|getDataString\(\)|getExtras\(\))|'
    r'\bget(?:String|Parcelable|Serializable|CharSequence)Extra\s*[(<]|'
    r'\.getQueryParameter(?:s|Names)?\s*\(|'
    // Swift: `open url: URL`, `.onOpenURL { url in`, Universal Links.
    r'\buserActivity\.webpageURL\b|\.queryItems\b|\.onOpenURL\s*\{\s*(\w+)\s+in');

/// Sinks in Kotlin, Java and Swift: the second group names the call.
final _nativeSink = RegExp(
    r'\b(loadUrl|loadData|loadDataWithBaseURL|evaluateJavascript|startActivity|'
    r'sendBroadcast|startService|File|FileInputStream|FileOutputStream|'
    r'evaluateJavaScript|loadHTMLString|load|open)\s*\(');

final _nativeCheck = RegExp(
    r'\b(?:if|when|guard|require|check|switch)\b.*(?:host|scheme|startsWith|hasPrefix|'
    r'contains|==|!=|equals|allow|valid|trust|matches|whitelist)',
    caseSensitive: false);

/// Declarations: `val url = ...`, `String url = ...`, `let url = ...`.
final _nativeDecl = RegExp(
    r'^\s*(?:(?:private|public|final|internal)\s+)*(?:val|var|let|String|Uri|URL|Intent|[A-Z]\w*)\s+(\w+)\s*(?::\s*[\w.?<>\[\]]+\s*)?=\s*(.+)$');

/// A new function: data from one does not flow into the next.
final _nativeFunction = RegExp(
    r'^\s*(?:@\w+\s+)*(?:(?:override|private|public|protected|internal|static|final|open|suspend|@objc)\s+)*(?:fun|func)\s|'
    r'^\s*(?:(?:public|private|protected|static|final|synchronized)\s+)+[\w<>\[\]]+\s+\w+\s*\(');

/// Swift handlers whose `url` parameter is the incoming link.
final _swiftLinkHandler = RegExp(
    r'func\s+(?:application|scene)\s*\([^)]*\bopen(?:URLContexts)?\s+(\w+)\s*:');

/// Returns the findings and whether any native code reads links or Intents.
(List<Finding>, bool) _native(Project project) {
  final out = <Finding>[];
  var reads = false;
  for (final file in project.nativeSources) {
    final ext = file.path.split('.').last;
    if (!const {'kt', 'java', 'swift'}.contains(ext)) continue;
    final code = withoutComments(file.text);
    if (!_nativeSource.hasMatch(code) && !_swiftLinkHandler.hasMatch(code)) {
      continue;
    }
    reads = true;
    final lines = code.split('\n');
    var tainted = <String, int>{}; // variable -> line it got link data
    for (var i = 0; i < lines.length; i++) {
      final line = lines[i];
      if (_nativeFunction.hasMatch(line)) tainted = {};
      final handler = _swiftLinkHandler.firstMatch(line);
      if (handler != null) tainted[handler[1]!] = i;
      final closure = _nativeSource.firstMatch(line);
      if (closure?[1] != null) tainted[closure![1]!] = i;
      bool carries(String text) =>
          _nativeSource.hasMatch(text) ||
          tainted.keys
              .any((v) => RegExp('\\b${RegExp.escape(v)}\\b').hasMatch(text));
      final decl = _nativeDecl.firstMatch(line);
      if (decl != null && carries(decl[2]!) && !_guardCall.hasMatch(decl[2]!)) {
        tainted[decl[1]!] = i;
        continue;
      }
      for (final m in _nativeSink.allMatches(line)) {
        final call = m[1]!;
        // `load` and `open` are only sinks in Swift WebViews and UIApplication.
        if ((call == 'load' || call == 'open') &&
            !RegExp(r'(?:webView|\.shared)\s*\.\s*(?:load|open)\s*\(|load\(\s*URLRequest')
                .hasMatch(line)) {
          continue;
        }
        final args = line.substring(m.end);
        if (!carries(args) || _guardCall.hasMatch(args)) continue;
        // Checked between where the data came in and here.
        final names = [
          for (final v in tainted.keys)
            if (RegExp('\\b${RegExp.escape(v)}\\b').hasMatch(args)) v
        ];
        final from = names.isEmpty
            ? i
            : names.map((v) => tainted[v]!).reduce((a, b) => a < b ? a : b);
        final checked = [for (var k = from; k <= i; k++) lines[k]].any((l) =>
            _nativeCheck.hasMatch(l) &&
            (names.isEmpty ||
                names.any(
                    (v) => RegExp('\\b${RegExp.escape(v)}\\b').hasMatch(l))));
        if (checked) continue;
        final value =
            shorten(names.isNotEmpty ? names.first : args.split(')').first, 40);
        out.add(Finding(
            ruleId: 'AEG-D19',
            message: En.deepLinkActionNative(value: value, call: call),
            messageAr: Ar.deepLinkActionNative(value: value, call: call),
            file: file.path,
            line: i + 1));
        break;
      }
    }
  }
  return (out, reads);
}

final _guardCall = RegExp(
    r'\b\w*(?:valid|sanit|allow|trust|safe|verif|whitelist)\w*\s*\(',
    caseSensitive: false);

/// Whether the Dart code handles push notification payloads, which
/// `AEG-D19` does not follow.
bool handlesPushPayloads(Project project) => project.dartFiles.any((f) =>
    f.importsPackage('firebase_messaging') ||
    f.importsPackage('onesignal_flutter') ||
    f.importsPackage('flutter_local_notifications') ||
    RegExp(r'\b(?:onMessage|onMessageOpenedApp|getInitialMessage|onBackgroundMessage)\b')
        .hasMatch(f.source));

/// Whether the AEG-D19 result settles the manual deep-link check AEG-M08.
bool deepLinksDecided(List<RuleResult> results, Project project) {
  final d19 = results.where((r) => r.meta.id == 'AEG-D19').firstOrNull;
  return d19 != null &&
      d19.counts &&
      !d19.incomplete &&
      !handlesPushPayloads(project);
}
