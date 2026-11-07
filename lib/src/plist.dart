/// Minimal XML property-list parser (Info.plist, *.entitlements).
library;

import 'package:xml/xml.dart';

/// Parses an XML plist into Dart values: Map, List, String, bool, int,
/// double. Returns null if [text] is not a valid XML plist.
Map<String, Object?>? parsePlist(String text) {
  try {
    final doc = XmlDocument.parse(text);
    final plist = doc.findAllElements('plist').cast<XmlElement?>().firstWhere(
          (_) => true,
          orElse: () => null,
        );
    if (plist == null) return null;
    final root = plist.childElements.cast<XmlElement?>().firstWhere(
          (_) => true,
          orElse: () => null,
        );
    if (root == null) return null;
    final v = _value(root);
    return v is Map<String, Object?> ? v : null;
  } catch (_) {
    return null;
  }
}

Object? _value(XmlElement e) {
  switch (e.name.local) {
    case 'dict':
      final map = <String, Object?>{};
      String? key;
      for (final c in e.childElements) {
        if (c.name.local == 'key') {
          key = c.innerText.trim();
        } else if (key != null) {
          map[key] = _value(c);
          key = null;
        }
      }
      return map;
    case 'array':
      return e.childElements.map(_value).toList();
    case 'true':
      return true;
    case 'false':
      return false;
    case 'integer':
      return int.tryParse(e.innerText.trim());
    case 'real':
      return double.tryParse(e.innerText.trim());
    default:
      return e.innerText;
  }
}
