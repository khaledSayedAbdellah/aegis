/// Data from a deep link that reaches a sensitive action without a check.
library;

import '../dart_flow.dart';
import '../l10n/messages.g.dart';
import '../model.dart';
import '../project.dart';
import 'rule.dart';

/// Code that reads deep links: `uni_links`, `app_links`, go_router.
final _readsLinks = RegExp(
    r'\b(?:uriLinkStream|linkStream|stringLinkStream|allUriLinkStream|allStringLinkStream|getInitial(?:App)?Link|getInitialUri|getLatest(?:App)?Link|getLatestUri)\b|'
    r'\bstate\.(?:uri|pathParameters|queryParameters)\b|\b(?:queryParameters|pathParameters)\b');

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
    var readsLinks = false;
    for (final f in project.dartFiles) {
      if (!_readsLinks.hasMatch(f.source)) continue;
      readsLinks = true;
      final flow = ValueFlow(f);
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
    if (!readsLinks) {
      return RuleCheck.notApplicableLocalized(
          En.deepLinkActionNone, Ar.deepLinkActionNone);
    }
    return RuleCheck(out);
  }
}

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
