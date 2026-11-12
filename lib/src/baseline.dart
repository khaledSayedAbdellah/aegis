/// Baselines: accept the findings a project has today so that CI only fails
/// on new ones.
///
/// A baseline is a JSON file (`aegis-baseline.json` by default) committed to
/// the repository. Each finding is identified by a fingerprint built from the
/// rule, the file and the message, without line numbers, so findings keep
/// matching when code moves around.
library;

import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';

import 'model.dart';
import 'version.dart';

const defaultBaselineFile = 'aegis-baseline.json';

/// One accepted finding.
class BaselineEntry {
  BaselineEntry({
    required this.fingerprint,
    required this.ruleId,
    required this.file,
    required this.message,
    this.count = 1,
  });

  final String fingerprint;
  final String ruleId;
  final String? file;
  final String message;

  /// How many identical findings were accepted.
  int count;

  Map<String, Object?> toJson() => {
        'fingerprint': fingerprint,
        'rule': ruleId,
        if (file != null) 'file': file,
        'message': message,
        if (count != 1) 'count': count,
      };
}

class Baseline {
  Baseline(this.entries, {this.path});

  /// Entries by fingerprint.
  final Map<String, BaselineEntry> entries;

  /// Where the baseline was loaded from, if any.
  final String? path;

  int get total => entries.values.fold(0, (s, e) => s + e.count);

  /// Reads a baseline file. Throws [FormatException] when it is not one.
  static Baseline load(String path) {
    final Object? json;
    try {
      json = jsonDecode(File(path).readAsStringSync());
    } on FormatException catch (e) {
      throw FormatException('Invalid baseline $path: ${e.message}');
    }
    final list = json is Map ? json['findings'] : null;
    if (list is! List) {
      throw FormatException('Invalid baseline $path: no "findings" list.');
    }
    final entries = <String, BaselineEntry>{};
    for (final e in list) {
      if (e is! Map || e['fingerprint'] == null || e['rule'] == null) continue;
      final fp = e['fingerprint'].toString();
      final count = e['count'] is int ? e['count'] as int : 1;
      final existing = entries[fp];
      if (existing != null) {
        existing.count += count;
      } else {
        entries[fp] = BaselineEntry(
          fingerprint: fp,
          ruleId: e['rule'].toString(),
          file: e['file']?.toString(),
          message: (e['message'] ?? '').toString(),
          count: count,
        );
      }
    }
    return Baseline(entries, path: path);
  }

  /// A baseline that accepts every failing finding in [results].
  static Baseline fromResults(List<RuleResult> results) {
    final entries = <String, BaselineEntry>{};
    for (final r in results) {
      if (r.status != RuleStatus.failed) continue;
      for (final f in r.findings) {
        final fp = fingerprint(f);
        final existing = entries[fp];
        if (existing != null) {
          existing.count++;
        } else {
          entries[fp] = BaselineEntry(
            fingerprint: fp,
            ruleId: f.ruleId,
            file: normalizeFile(f.file),
            message: f.message,
          );
        }
      }
    }
    return Baseline(entries);
  }

  /// The baseline file content. Entries are sorted so that diffs stay small.
  String toJsonString() {
    final sorted = entries.values.toList()
      ..sort((a, b) {
        final r = a.ruleId.compareTo(b.ruleId);
        if (r != 0) return r;
        final f = (a.file ?? '').compareTo(b.file ?? '');
        return f != 0 ? f : a.message.compareTo(b.message);
      });
    return '${const JsonEncoder.withIndent('  ').convert({
          'tool': 'aegis',
          'version': aegisVersion,
          'description':
              'Findings accepted as known. aegis reports them separately and --fail-on ignores them. '
                  'Regenerate with: aegis --update-baseline',
          'findings': [for (final e in sorted) e.toJson()],
        })}\n';
  }

  /// Marks the findings of [results] that are in this baseline and returns
  /// the entries that no longer match anything (fixed since the baseline).
  ///
  /// Only rules that ran count: an APK finding is not "fixed" because this
  /// run had no `--apk`.
  List<BaselineEntry> apply(List<RuleResult> results) {
    final ran = {
      for (final r in results)
        if (r.counts && !r.incomplete) r.meta.id
    };
    final remaining = {for (final e in entries.values) e.fingerprint: e.count};
    for (final r in results) {
      if (r.status != RuleStatus.failed) continue;
      for (final f in r.findings) {
        final fp = fingerprint(f);
        final left = remaining[fp] ?? 0;
        if (left > 0) {
          f.baselined = true;
          remaining[fp] = left - 1;
        }
      }
    }
    return [
      for (final e in entries.values)
        if ((remaining[e.fingerprint] ?? 0) > 0 && ran.contains(e.ruleId))
          BaselineEntry(
            fingerprint: e.fingerprint,
            ruleId: e.ruleId,
            file: e.file,
            message: e.message,
            count: remaining[e.fingerprint]!,
          )
    ];
  }

  /// `app-prod-release.apk!/AndroidManifest.xml` -> `apk!/AndroidManifest.xml`,
  /// so renaming the APK does not turn known findings into new ones. App
  /// bundles and APK sets use the same APK-style entry names. Runtime
  /// findings can also point to a preselected APK directory.
  static String? normalizeFile(String? file) => file?.replaceFirst(
      RegExp(r'^[^/]*(?:\.(?:apks?|aab|ipa)!/|!/(?=runtime$))',
          caseSensitive: false),
      'apk!/');

  /// Rule + file + message, ignoring line numbers, numbers in the message
  /// (counts, versions), whitespace, and whether it says APK or AAB.
  static String fingerprint(Finding f) {
    final message = f.message
        .toLowerCase()
        .replaceAll(RegExp(r'\baab\b'), 'apk')
        .replaceAll(RegExp(r'\d+'), '#')
        .replaceAll(RegExp(r'\s+'), ' ')
        .trim();
    final key = '${f.ruleId}|${normalizeFile(f.file) ?? ''}|$message';
    return sha256.convert(utf8.encode(key)).toString().substring(0, 16);
  }
}
