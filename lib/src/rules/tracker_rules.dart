import 'dart:convert';
import 'dart:io';
import '../binary/apk.dart';
import '../model.dart';
import '../project.dart';
import '../config.dart';
import '../l10n/messages.g.dart';
import '../security/evidence.dart';
import '../security/metadata.dart';
import 'rule.dart';

/// Small, explicit baseline. Custom signatures use literal prefixes, never
/// remote executable regular expressions. No claim of exhaustive detection.
const builtInTrackerSignatures = [
  {
    'name': 'Google Analytics for Firebase',
    'prefixes': [
      'com/google/firebase/analytics/',
      'com.google.firebase.analytics.',
      'FIRAnalytics',
      'firebase_analytics',
      'FirebaseAnalytics'
    ]
  },
  {
    'name': 'Meta App Events',
    'prefixes': [
      'com/facebook/appevents/',
      'com.facebook.appevents.',
      'FBSDKAppEvents',
      'facebook_app_events'
    ]
  },
  {
    'name': 'AppsFlyer',
    'prefixes': [
      'com/appsflyer/',
      'com.appsflyer.',
      'AppsFlyerLib',
      'appsflyer_sdk'
    ]
  },
  {
    'name': 'Adjust',
    'prefixes': [
      'com/adjust/sdk/',
      'com.adjust.sdk.',
      'ADJConfig',
      'adjust_sdk'
    ]
  },
];

class TrackerInventoryRule extends Rule {
  const TrackerInventoryRule();
  @override
  RuleMeta get meta => extendedMeta('AEG-T01');
  @override
  RuleCheck check(Project p, ProfileSet profile) {
    final signatures = <Map>[...builtInTrackerSignatures];
    var limited = false;
    final custom = AegisConfig.resolve(p.root, p.config.trackerSignatures);
    if (custom != null) {
      try {
        final f = File(custom);
        if (f.lengthSync() > 1024 * 1024) {
          throw const FormatException('Signature limit');
        }
        final data = jsonDecode(f.readAsStringSync());
        if (data is! List || data.length > 5000) {
          throw const FormatException('Signature format');
        }
        for (final entry in data) {
          if (entry is! Map ||
              entry['name'] is! String ||
              entry['prefixes'] is! List ||
              (entry['prefixes'] as List).isEmpty ||
              (entry['prefixes'] as List).length > 20 ||
              (entry['prefixes'] as List)
                  .any((s) => s is! String || s.length < 4 || s.length > 200)) {
            throw const FormatException('Signature format');
          }
          signatures.add(entry);
        }
      } catch (_) {
        limited = true;
      }
    }
    final matched = <String>{};
    void scan(String file, Iterable<String> strings) {
      for (final s in strings) {
        for (final sig in signatures) {
          final name = sig['name'] as String;
          if (matched.contains('$name|$file')) continue;
          if ((sig['prefixes'] as List).cast<String>().any(s.contains)) {
            matched.add('$name|$file');
            p.securityEvidence.add(SecurityEvidence(meta.id, file,
                Bilingual('$name. ${En.extScope}', '$name. ${Ar.extScope}'),
                data: {
                  'sdk': name,
                  'collectionVerified': false,
                  'database':
                      '${builtInTrackerSignatures.length} built-in signatures${custom == null ? '' : ' + custom'}'
                }));
          }
        }
      }
    }

    if (p.hasSource && !p.nativeOnly) {
      scan('pubspec.lock / pubspec.yaml',
          [...p.locked.keys, ...p.dependencies.keys]);
    }
    for (final source in [...p.nativeSources, ...p.scriptSources]) {
      scan(source.path, [source.text]);
    }
    final apk = p.apk;
    if (apk != null) {
      var total = 0;
      var count = 0;
      for (final e
          in apk.archive.entries.values.where((e) => e.name.endsWith('.dex'))) {
        total += e.size;
        if (++count > 128 ||
            e.size > 64 * 1024 * 1024 ||
            total > 256 * 1024 * 1024) {
          limited = true;
          continue;
        }
        try {
          scan(
              apk.location(e.name),
              printableStrings(
                  apk.archive.readEntry(e, maxBytes: 64 * 1024 * 1024),
                  min: 4));
        } catch (_) {
          limited = true;
        }
      }
    }
    final ipa = p.ipa;
    if (ipa != null) {
      limited |= ipa.staticAnalysis.limited;
      for (final b in ipa.staticAnalysis.binaries) {
        scan('${ipa.label}!/${b.path}', [
          b.path,
          ...b.slices
              .where((s) => !s.encrypted)
              .expand((s) => [...s.symbols, ...s.strings])
        ]);
      }
    }
    if (limited) {
      p.securityEvidence.add(SecurityEvidence(meta.id, custom ?? 'binary',
          const Bilingual(En.extIncomplete, Ar.extIncomplete),
          status: 'unavailable'));
    }
    return limited
        ? RuleCheck.incompleteLocalized(En.extIncomplete, Ar.extIncomplete)
        : RuleCheck.notApplicableLocalized(
            En.extIndicatorOnly, Ar.extIndicatorOnly);
  }
}
