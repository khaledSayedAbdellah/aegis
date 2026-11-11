/// Cross-platform static policy facts. Runtime observations are deliberately
/// separate and never promoted to whole-application coverage.
library;

import 'package:xml/xml.dart';

class BackupPolicy {
  BackupPolicy(this.flows, this.issues);
  final Map<String, List<Map<String, String>>> flows;
  final List<String> issues;
}

BackupPolicy inspectBackupPolicy(XmlDocument doc) {
  final flows = <String, List<Map<String, String>>>{};
  final issues = <String>[];
  final root = doc.rootElement;
  final nodes = root.name.local == 'full-backup-content'
      ? [root]
      : root.name.local == 'data-extraction-rules'
          ? root.childElements.toList()
          : <XmlElement>[];
  if (nodes.isEmpty) issues.add('empty_or_unknown_policy');
  for (final node in nodes) {
    final flow = node.name.local;
    if (!{'full-backup-content', 'cloud-backup', 'device-transfer'}
            .contains(flow) ||
        flows.containsKey(flow)) {
      issues.add('unknown_or_duplicate_flow');
      continue;
    }
    final rows = <Map<String, String>>[];
    flows[flow] = rows;
    for (final e in node.childElements) {
      final domain = e.getAttribute('domain'), path = e.getAttribute('path');
      if (!{'include', 'exclude'}.contains(e.name.local) ||
          !{
            'root',
            'file',
            'database',
            'sharedpref',
            'external',
            'device_root',
            'device_file',
            'device_database',
            'device_sharedpref'
          }.contains(domain) ||
          path == null ||
          path.isEmpty ||
          path.startsWith('/') ||
          path.contains('\\') ||
          path.split('/').contains('..') ||
          path.contains('*')) {
        issues.add('invalid_rule');
        continue;
      }
      rows.add({
        'action': e.name.local,
        'domain': domain!,
        'path': path,
        if (e.getAttribute('requireFlags') != null)
          'requireFlags': e.getAttribute('requireFlags')!
      });
    }
    if (rows.length > 4096) {
      issues.add('limit');
      flows[flow] = rows.take(4096).toList();
    }
  }
  return BackupPolicy(flows, issues);
}

/// AASA identity authorization only. Path/component matching and Apple CDN state
/// require a concrete URL/device and are not inferred from an appID match.
bool? iosAssociationMatches(Object? json, String appId) {
  if (json is! Map || json['applinks'] is! Map) return null;
  final details = (json['applinks'] as Map)['details'];
  if (details is! List) return null;
  var malformed = false, matchedIdentity = false;
  for (final item in details) {
    if (item is! Map) {
      malformed = true;
      continue;
    }
    final ids = item['appIDs'];
    if ((item.containsKey('appID') &&
            (item['appID'] is! String || (item['appID'] as String).isEmpty)) ||
        (item.containsKey('appIDs') &&
            (ids is! List ||
                ids.isEmpty ||
                ids.any((id) => id is! String || id.isEmpty))) ||
        !item.containsKey('appID') && !item.containsKey('appIDs')) {
      malformed = true;
      continue;
    }
    if (item['appID'] == appId || ids is List && ids.contains(appId)) {
      matchedIdentity = true;
      final paths = item['paths'], components = item['components'];
      if (paths is List &&
              paths.every((p) => p is String) &&
              paths.any(
                  (p) => (p as String).isNotEmpty && !p.startsWith('NOT ')) ||
          components is List &&
              components.every((c) => c is Map) &&
              components.any((c) =>
                  c is Map &&
                  (!c.containsKey('exclude') || c['exclude'] is bool) &&
                  c['exclude'] != true &&
                  ((c['/'] is String && (c['/'] as String).isNotEmpty) ||
                      (c['#'] is String && (c['#'] as String).isNotEmpty) ||
                      c['?'] is String ||
                      c['?'] is Map &&
                          (c['?'] as Map).isNotEmpty &&
                          (c['?'] as Map).values.every((v) => v is String)))) {
        return true;
      }
      // An entry containing only exclusions does not establish an allowed URL.
      // Keep looking: another entry may authorize this same identity.
    }
  }
  return malformed || matchedIdentity ? null : false;
}

const platformKinds = [
  'screen',
  'backup',
  'key_access',
  'links',
  'webview',
  'tapjacking'
];
const platformRuleIds = {
  'screen': 'AEG-P11',
  'backup': 'AEG-N05',
  'key_access': 'AEG-N06',
  'links': 'AEG-I12',
  'webview': 'AEG-N07',
  'tapjacking': 'AEG-A14',
};

/// Controls each automatic observer collects, per probe target and observer.
/// A control outside these sets has no runtime test that a probe run could
/// leave unfinished (physical iOS devices have no observer at all).
///
/// `control` is the stock launch observer every probe of that target asks for.
/// `instrumented` runs only alongside the Android Frida checks, so its controls
/// are requested only once the runner recorded that it started.
const platformObserverKinds = <String, Map<String, Set<String>>>{
  'android': {
    'control': {'screen', 'webview', 'tapjacking'},
    'instrumented': {'screen', 'webview', 'key_access', 'tapjacking'},
  },
  'ios-simulator': {
    'control': {'screen', 'webview', 'backup', 'key_access', 'links'},
  },
};

/// Whether a probe run asked for a runtime observation of [kind]: its target's
/// launch observer covers it, or an optional observer that covers it started.
bool platformObservationRequested(
    String target, String kind, Set<String> attempts) {
  final observers = platformObserverKinds[target] ?? const {};
  return observers.entries.any((e) =>
      e.value.contains(kind) &&
      (e.key == 'control' || attempts.contains(e.key)));
}

/// The collector flag, and the value it takes, when an observer stopped before
/// covering everything it found for a control.
const platformObserverLimits = <String, (String, bool)>{
  'screen': ('viewLimitReached', true),
  'webview': ('viewLimitReached', true),
  'tapjacking': ('viewLimitReached', true),
  'backup': ('fileLimitReached', true),
  'key_access': ('keyQueriesComplete', false),
};

final platformReferences = <String, RegExp>{
  'screen': RegExp(
      r'FLAG_SECURE|setSecure\b|setRecentsScreenshotEnabled|isCaptured|sceneCaptureState|UIScreenCapturedDidChange|applicationWillResignActive|sceneWillResignActive|secureTextEntry|isSecureTextEntry|screen_protector|secure_application|no_screenshot'),
  'backup': RegExp(
      r'NSURLIsExcludedFromBackupKey|isExcludedFromBackup|NSFileProtection|noBackupFilesDir|getNoBackupFilesDir|dataExtractionRules|fullBackupContent'),
  'key_access': RegExp(
      r'SecAccessControlCreateWithFlags|kSecAccessControl\w+|kSecAttrAccessible\w+|setUserAuthenticationRequired|setInvalidatedByBiometricEnrollment|setUserAuthenticationParameters|BiometricPrompt|CryptoObject|evaluatePolicy|biometryCurrentSet|biometryAny|userPresence|local_auth|biometric_storage'),
  'links': RegExp(
      r'continueUserActivity|openURL|handleOpenURL|NSUserActivityTypeBrowsingWeb|applinks:|CFBundleURLTypes|app_links'),
  'webview': RegExp(
      r'WKWebView|UIWebView|addJavascriptInterface|addScriptMessageHandler|WKScriptMessageHandler|loadHTMLString|loadDataWithBaseURL|setAllowFileAccess|setAllowContentAccess|javaScriptEnabled|javaScriptCanOpenWindowsAutomatically|WebViewWidget|JavascriptChannel|NavigationDelegate|InAppWebView'),
  'tapjacking': RegExp(
      r'filterTouchesWhenObscured|setFilterTouchesWhenObscured|FLAG_WINDOW_IS_OBSCURED|FLAG_WINDOW_IS_PARTIALLY_OBSCURED|setHideOverlayWindows|HIDE_OVERLAY_WINDOWS|accessibilityDataSensitive'),
};

// Explicit configuration is review evidence. Without a sensitive-operation
// context, it cannot establish a vulnerability or a whole-app control verdict.
final platformWeakConfig = <String, List<RegExp>>{
  'screen': [],
  'backup': [],
  'key_access': [
    RegExp(r'\bsetUserAuthenticationRequired\s*\(\s*false\s*\)'),
    RegExp(r'\bsetInvalidatedByBiometricEnrollment\s*\(\s*false\s*\)')
  ],
  'links': [],
  'webview': [
    RegExp(r'\bsetWebContentsDebuggingEnabled\s*\(\s*true\s*\)'),
    RegExp(r'\bisInspectable\s*=\s*(?:true|YES)\b'),
    RegExp(r'\bsetJavaScriptCanOpenWindowsAutomatically\s*\(\s*true\s*\)')
  ],
  'tapjacking': [
    RegExp(r'\bsetFilterTouchesWhenObscured\s*\(\s*false\s*\)'),
    RegExp(r'\bsetHideOverlayWindows\s*\(\s*false\s*\)')
  ],
};
