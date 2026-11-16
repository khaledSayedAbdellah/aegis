/// Data from a deep link that reaches a sensitive action without a check.
library;

import '../dart_flow.dart';
import '../dart_scanner.dart';
import '../l10n/messages.g.dart';
import '../model.dart';
import '../project.dart';
import '../security/evidence.dart';
import '../security/native_analysis.dart' show withoutComments;
import '../security/native_flow.dart';
import 'rule.dart';

/// Code that reads deep links: `uni_links`, `app_links`, go_router.
final _readsLinks = RegExp(
    r'\b(?:uriLinkStream|linkStream|stringLinkStream|allUriLinkStream|allStringLinkStream|getInitial(?:App)?Link|getInitialUri|getLatest(?:App)?Link|getLatestUri)\b|'
    r'\bstate\.(?:uri|pathParameters|queryParameters)\b|\??\.(?:queryParameters|pathParameters)\b(?!\s*:)|'
    r'\bonGenerateRoute\s*:');

/// The link APIs whose use lets AEG-D19 stand in for manual check AEG-M08.
final _linkApi = RegExp(
    r'\b(uriLinkStream|linkStream|stringLinkStream|allUriLinkStream|allStringLinkStream|getInitial(?:App)?Link|getInitialUri|getLatest(?:App)?Link|getLatestUri)\b|'
    r'\b(GoRouter|GoRoute)\s*\(|\b(onGenerateRoute)\s*:');

/// The link APIs the Dart code uses, by name.
Set<String> linkApis(Project project) => {
      for (final f in project.dartFiles)
        for (final m in _linkApi.allMatches(f.source)) m[1] ?? m[2] ?? m[3]!
    };

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
    final apis = linkApis(project);
    if (apis.isNotEmpty && !handlesPushPayloads(project)) {
      final list = (apis.toList()..sort()).join(', ');
      project.securityEvidence.add(SecurityEvidence(
          meta.id,
          '.',
          Bilingual(En.deepLinkReplacesManual(apis: list),
              Ar.deepLinkReplacesManual(apis: list)),
          status: 'facts',
          data: {'linkApis': apis.toList()..sort()}));
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

/// Sinks in Kotlin, Java and Swift: group 1 names the call.
final _nativeSink = RegExp(
    r'\b(loadUrl|loadData|loadDataWithBaseURL|evaluateJavascript|startActivity|'
    r'sendBroadcast|startService|File|FileInputStream|FileOutputStream|'
    r'evaluateJavaScript|loadHTMLString|load|open)\s*\(');

/// Whether the Intent passed on [line] names its target class, inline or
/// where the variable passed was declared.
bool _explicitIntent(String code, String line) {
  final explicit = RegExp(
      r'::class\.java|\.class\s*\)|setClass(?:Name)?\s*\(|setComponent\s*\(|ComponentName\s*\(');
  final call =
      RegExp(r'\b(?:startActivity|sendBroadcast|startService)\s*\((.*)')
          .firstMatch(line);
  if (call == null) return false;
  final args = call[1]!;
  if (explicit.hasMatch(args)) return true;
  final name = RegExp(r'^\s*(\w+)\s*[),]').firstMatch(args)?[1];
  if (name == null) return false;
  final decl = RegExp(
          '(?:val|var|Intent)\\s+${RegExp.escape(name)}\\s*(?::\\s*Intent\\??\\s*)?=\\s*([^\\n]*)')
      .allMatches(code)
      .lastOrNull;
  if (decl == null) return false;
  // An Intent read from another app's Intent is not explicit, whatever it says.
  if (RegExp(r'getParcelableExtra').hasMatch(decl[1]!)) return false;
  return explicit.hasMatch(decl[1]!);
}

/// Returns the findings and whether any native code reads links or Intents.
(List<Finding>, bool) _native(Project project) {
  final out = <Finding>[];
  var reads = false;
  for (final file in project.nativeSources) {
    final ext = file.path.split('.').last;
    if (!const {'kt', 'java', 'swift'}.contains(ext)) continue;
    final code = withoutComments(file.text);
    if (!nativeLinkSource.hasMatch(code) && !swiftLinkHandler.hasMatch(code)) {
      continue;
    }
    reads = true;
    for (final hit in nativeFlows(code,
        sources: nativeLinkSource, sinks: _nativeSink, accept: (call, line) {
      // `load` and `open` are only sinks in Swift WebViews and
      // UIApplication.
      if (call == 'load' || call == 'open') {
        return RegExp(
                r'(?:webView|\.shared)\s*\.\s*(?:load|open)\s*\(|load\(\s*URLRequest')
            .hasMatch(line);
      }
      // Handing data to one of the app's own screens is not a redirect;
      // an Intent that came from outside, or an implicit one, is.
      if (const {'startActivity', 'sendBroadcast', 'startService'}
          .contains(call)) {
        return !_explicitIntent(code, line);
      }
      return true;
    })) {
      final value = shorten(hit.value, 40);
      out.add(Finding(
          ruleId: 'AEG-D19',
          message: En.deepLinkActionNative(value: value, call: hit.call),
          messageAr: Ar.deepLinkActionNative(value: value, call: hit.call),
          file: file.path,
          line: hit.line));
    }
  }
  return (out, reads);
}

/// Whether the Dart code handles push notification payloads, which
/// `AEG-D19` does not follow.
bool handlesPushPayloads(Project project) => project.dartFiles.any((f) =>
    f.importsPackage('firebase_messaging') ||
    f.importsPackage('onesignal_flutter') ||
    f.importsPackage('flutter_local_notifications') ||
    RegExp(r'\b(?:onMessage|onMessageOpenedApp|getInitialMessage|onBackgroundMessage)\b')
        .hasMatch(f.source));

/// Whether the AEG-D19 result settles the manual deep-link check AEG-M08:
/// it ran to the end, the Dart code reads links through a link API it
/// follows, and no push payloads (which it does not follow) are handled.
bool deepLinksDecided(List<RuleResult> results, Project project) {
  final d19 = results.where((r) => r.meta.id == 'AEG-D19').firstOrNull;
  return d19 != null &&
      d19.counts &&
      !d19.incomplete &&
      linkApis(project).isNotEmpty &&
      !handlesPushPayloads(project);
}
