import 'package:xml/xml.dart';

/// Parse only the verified target's windows/nodes; never retain UI text.
Map<String, Object?> inspectAndroidPlatform(
    String package, String windows, String? hierarchy) {
  final screen = <String, int>{}, web = <String, int>{}, taps = <String, int>{};
  var count = 0, secure = 0, knownFlags = 0;
  for (final block in windows.split(RegExp(r'(?=Window #\d+ Window\{)'))) {
    final head = block.split('\n').first;
    if (!RegExp('\\b${RegExp.escape(package)}/').hasMatch(head)) continue;
    count++;
    final flags =
        RegExp(r'\b(?:fl|flags)=(?:0x)?([0-9a-fA-F]+)\b').firstMatch(block);
    if (flags != null) {
      final value = int.tryParse(flags[1]!, radix: 16);
      if (value != null) {
        knownFlags++;
        if (value & 0x2000 != 0) secure++;
      }
    } else if (RegExp(r'\bFLAG_SECURE\b|\bSECURE\b').hasMatch(block)) {
      knownFlags++;
      secure++;
    }
  }
  if (count > 0) screen['windows'] = count;
  if (knownFlags > 0) screen['secureWindows'] = secure;
  if (hierarchy != null && hierarchy.length <= 2 * 1024 * 1024) {
    try {
      final doc = XmlDocument.parse(hierarchy);
      final nodes = doc
          .findAllElements('node')
          .where((n) => n.getAttribute('package') == package)
          .take(5000)
          .toList();
      if (nodes.isNotEmpty) {
        screen['passwordFields'] =
            nodes.where((n) => n.getAttribute('password') == 'true').length;
        web['webviews'] = nodes
            .where((n) => n.getAttribute('class') == 'android.webkit.WebView')
            .length;
        taps['clickableViews'] =
            nodes.where((n) => n.getAttribute('clickable') == 'true').length;
      }
    } on XmlException {/* no parsed tree means no negative conclusion */}
  }
  return {'screen': screen, 'webview': web, 'tapjacking': taps};
}
