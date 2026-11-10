import '../binary/apk.dart';

/// Reference-only DEX/native inspection; it is not Java/Kotlin decompilation.
class AndroidReferences {
  final Map<String, List<String>> files = {};
  bool limited = false;
  AndroidReferences(ApkContext apk) {
    var total = 0, count = 0;
    for (final e in apk.archive.entries.values
        .where((e) => e.name.endsWith('.dex') || e.name.endsWith('.so'))) {
      total += e.size;
      if (++count > 128 ||
          e.size > 64 * 1024 * 1024 ||
          total > 256 * 1024 * 1024) {
        limited = true;
        continue;
      }
      try {
        final values = printableStrings(
            apk.archive.readEntry(e, maxBytes: 64 * 1024 * 1024),
            min: 4);
        // Only retain strings that can matter to native API or tracker review.
        files[apk.location(e.name)] = values
            .where((s) =>
                s.length <= 4096 &&
                RegExp(r'(SSL|[Tt]rust|[Cc]ert|MD[245]|SHA|DES|RC[24]|[Rr]andom|WebView|[Ff]ile|[Cc]lip|[Ll]og|sqlite|[Rr]and|firebase|facebook|appsflyer|adjust)')
                    .hasMatch(s))
            .take(50000)
            .toList();
        if (values.length > 50000) limited = true;
      } catch (_) {
        limited = true;
      }
    }
  }
}
