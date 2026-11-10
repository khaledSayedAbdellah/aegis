import 'dart:io';
import 'package:xml/xml.dart';
import '../l10n/messages.g.dart';
import '../model.dart';
import '../project.dart';
import '../security/evidence.dart';
import '../security/metadata.dart';
import '../security/native_analysis.dart';
import '../security/platform_checks.dart';
import '../security/public_json.dart';
import 'platform_security_rules.dart' show AssociationFetcher;
import 'rule.dart';

const platformProtectionRules = [
  PlatformProtectionRule('screen'),
  PlatformProtectionRule('backup'),
  PlatformProtectionRule('key_access'),
  PlatformProtectionRule('links'),
  PlatformProtectionRule('webview'),
  PlatformProtectionRule('tapjacking'),
];

class PlatformProtectionRule extends Rule {
  const PlatformProtectionRule(this.kind, {this.fetcher});
  final String kind;
  final AssociationFetcher? fetcher;
  @override
  RuleMeta get meta => extendedMeta(platformRuleIds[kind]!);

  @override
  Future<RuleCheck> check(Project p, ProfileSet profile) async {
    final ios = p.ipa != null || p.apk == null && p.infoPlistData != null;
    final android =
        p.apk != null || p.ipa == null && p.androidManifestXml != null;
    if ((!ios && !android) ||
        kind == 'links' && !ios ||
        kind == 'tapjacking' && !android) {
      return RuleCheck.notApplicable();
    }
    final out = <Finding>[];
    final label = p.ipa?.label ?? p.apk?.fileName ?? 'source';
    void evidence(String file, Bilingual detail,
        {Map<String, Object?> data = const {}, String status = 'facts'}) {
      p.securityEvidence.add(
          SecurityEvidence(meta.id, file, detail, data: data, status: status));
    }

    evidence(label, meta.description, data: {
      'scope': 'partial',
      'automatic': true,
      'requiresAppKnowledge': false
    });
    final files = [
      if (android) ...p.androidNativeSources,
      if (ios) ...p.iosNativeSources,
      ...p.dartFiles.map((f) => ProjectFile(f.path, f.source)),
    ];
    for (final f in files) {
      final source = withoutComments(f.text);
      final hits = platformReferences[kind]!
          .allMatches(source)
          .map((m) => m[0]!)
          .toSet()
          .take(30)
          .toList();
      if (hits.isNotEmpty) {
        evidence(
            f.path,
            Bilingual(En.platformReferences(tokens: hits.join(', ')),
                Ar.platformReferences(tokens: hits.join(', '))),
            data: {
              'source': 'source-reference',
              'references': hits,
              'runtimeVerified': false
            });
      }
      final masked = maskNativeLiterals(source);
      for (final pattern in platformWeakConfig[kind]!) {
        for (final m in pattern.allMatches(source).take(20)) {
          if (masked[m.start].trim().isEmpty) continue;
          evidence(
              f.path,
              Bilingual(En.platformConfiguration(token: m[0]),
                  Ar.platformConfiguration(token: m[0])),
              data: {
                'source': 'source-configuration',
                'line':
                    '\n'.allMatches(source.substring(0, m.start)).length + 1,
                'runtimeVerified': false
              });
        }
      }
    }
    final refs = <(String, Iterable<String>)>[
      if (ios && p.ipa != null)
        for (final b in p.ipa!.staticAnalysis.binaries)
          for (final s in b.slices.where((s) => !s.encrypted))
            (
              '${b.path} [${s.architecture}]',
              s.symbols
                  .followedBy(s.strings)
                  .followedBy(s.metadata.entries.map((e) => e.qualifiedName))
            ),
      if (android && p.nativeAndroidReferences != null)
        ...p.nativeAndroidReferences!.files.entries
            .map((e) => (e.key, e.value)),
    ];
    for (final (file, values) in refs) {
      final hits = <String>{};
      for (final v in values) {
        hits.addAll(platformReferences[kind]!.allMatches(v).map((m) => m[0]!));
        if (hits.length >= 30) break;
      }
      if (hits.isNotEmpty) {
        evidence(
            file,
            Bilingual(En.platformReferences(tokens: hits.join(', ')),
                Ar.platformReferences(tokens: hits.join(', '))),
            data: {
              'source': 'binary-reference',
              'references': hits.toList(),
              'runtimeVerified': false
            });
      }
    }
    if (kind == 'tapjacking' && android) _layouts(p, evidence);
    if (kind == 'backup' && android) _backup(p, evidence);
    if (kind == 'links') await _links(p, out, evidence);
    final primary = p.probe?.report?.platformObservations;
    final observations = <Map<String, Object?>?>[
      if (primary?['control'] is Map)
        Map<String, Object?>.from(primary!['control'] as Map),
      primary,
    ];
    for (final observation in observations) {
      final facts = observation?[kind];
      if (observation?['verified'] == true &&
          facts is Map &&
          facts.isNotEmpty) {
        // Only known numeric fields are rendered; never echo app text or secrets.
        final clean = <String, int>{};
        for (final key in platformFactLabels.keys) {
          if (facts[key] is int &&
              (facts[key] as int) >= 0 &&
              (facts[key] as int) <= 100000) {
            clean[key] = facts[key] as int;
          }
        }
        if (clean.isNotEmpty) {
          String display(String lang) => clean.entries
              .map((e) => '${platformFactLabels[e.key]!.of(lang)}: ${e.value}')
              .join('; ');
          final platform =
              '${p.probe!.report!.platform}${observation?['instrumented'] == true ? '-instrumented' : '-control'}';
          evidence(
              label,
              Bilingual(
                  En.platformRuntime(platform: platform, facts: display('en')),
                  Ar.platformRuntime(platform: platform, facts: display('ar'))),
              data: {
                'source': 'automatic-runtime-observer',
                'platform': platform,
                'scope': 'launch-only',
                'facts': clean,
                'coverageComplete': false,
                'instrumented': observation?['instrumented'] == true,
                for (final key in [
                  'viewLimitReached',
                  'fileLimitReached',
                  'keyQueriesComplete'
                ])
                  if (observation?[key] is bool) key: observation?[key]
              });
          if (kind == 'webview' && (clean['webviewInsecureContent'] ?? 0) > 0) {
            out.add(inFile(
                label,
                null,
                En.platformWeakRuntime(
                    fact: En.platformFactWebviewInsecureContent),
                messageAr: Ar.platformWeakRuntime(
                    fact: Ar.platformFactWebviewInsecureContent)));
          }
        }
      } else {
        evidence(
            label, const Bilingual(En.platformNoRuntime, Ar.platformNoRuntime),
            status: 'unavailable');
      }
      if (observation?['viewLimitReached'] == true ||
          observation?['fileLimitReached'] == true ||
          observation?['keyQueriesComplete'] == false) {
        evidence(
            label,
            const Bilingual(
                En.platformObservationLimited, Ar.platformObservationLimited),
            status: 'unavailable');
      }
    }
    // Generic automatic exploration cannot establish every application's policy.
    // Findings survive partial coverage; no references/flags become global passes.
    return RuleCheck.incompleteLocalized(
        En.platformIncomplete, Ar.platformIncomplete, out);
  }

  void _layouts(
      Project p,
      void Function(String, Bilingual,
              {Map<String, Object?> data, String status})
          evidence) {
    final paths = <String>[];
    if (p.apk != null) {
      paths.addAll(p.apk!.zip.entries.keys.where(
          (f) => RegExp(r'^res/layout(?:-[^/]+)?/[^/]+\.xml$').hasMatch(f)));
    } else {
      final root = Directory(p.abs('android/app/src/main/res'));
      if (FileSystemEntity.typeSync(root.path, followLinks: false) !=
          FileSystemEntityType.directory) {
        return;
      }
      for (final dir in root
          .listSync(followLinks: false)
          .whereType<Directory>()
          .where(
              (d) => RegExp(r'[/\\]layout(?:-[^/\\]+)?$').hasMatch(d.path))) {
        paths.addAll(dir
            .listSync(followLinks: false)
            .whereType<File>()
            .where((f) => f.path.endsWith('.xml'))
            .map((f) => f.path));
        if (paths.length > 64) break;
      }
    }
    if (paths.length > 64) {
      evidence(
          'layout',
          const Bilingual(
              En.platformObservationLimited, Ar.platformObservationLimited),
          status: 'unavailable');
    }
    for (final path in paths.take(64)) {
      try {
        XmlDocument doc;
        if (p.apk != null) {
          doc = p.apk!.readXmlResource(path);
        } else {
          final file = File(path);
          if (file.lengthSync() > 1024 * 1024) {
            throw const FormatException('Layout limit');
          }
          doc = XmlDocument.parse(file.readAsStringSync());
        }
        var count = 0;
        for (final e in doc.descendants.whereType<XmlElement>()) {
          final value = androidAttr(e, 'filterTouchesWhenObscured');
          if (value == null) continue;
          if (++count > 100) {
            evidence(
                path,
                const Bilingual(En.platformObservationLimited,
                    Ar.platformObservationLimited),
                status: 'unavailable');
            break;
          }
          final token = '${e.name.local}: filterTouchesWhenObscured=$value';
          evidence(
              path,
              Bilingual(En.platformConfiguration(token: token),
                  Ar.platformConfiguration(token: token)),
              data: {'source': 'layout-configuration', 'value': value});
        }
      } catch (_) {
        evidence(
            path,
            const Bilingual(
                En.platformObservationLimited, Ar.platformObservationLimited),
            status: 'unavailable');
      }
    }
  }

  void _backup(
      Project p,
      void Function(String, Bilingual,
              {Map<String, Object?> data, String status})
          evidence) {
    final app = (p.apk?.manifest ?? p.androidManifestXml)
        ?.findAllElements('application')
        .firstOrNull;
    if (app == null) return;
    final config = <String, Object?>{
      'allowBackup': androidAttr(app, 'allowBackup') ?? 'default true'
    };
    for (final key in ['fullBackupContent', 'dataExtractionRules']) {
      final ref = androidAttr(app, key);
      config[key] = ref;
      if (ref == null || ref == 'false' || ref == '@null') {
        evidence(key,
            const Bilingual(En.platformBackupMissing, Ar.platformBackupMissing),
            data: {'reference': ref});
        continue;
      }
      try {
        final docs = <(String, XmlDocument)>[];
        if (p.apk != null) {
          for (final file in p.apk!.xmlResourcePaths(ref)) {
            docs.add((p.apk!.location(file), p.apk!.readXmlResource(file)));
          }
        } else {
          final match = RegExp(r'^@xml/([A-Za-z0-9_]+)$').firstMatch(ref);
          if (match == null) throw const FormatException('Unresolved resource');
          final root = Directory(p.abs('android/app/src/main/res'));
          if (FileSystemEntity.typeSync(root.path, followLinks: false) !=
              FileSystemEntityType.directory) {
            throw const FormatException('Missing resources');
          }
          for (final dir in root
              .listSync(followLinks: false)
              .whereType<Directory>()
              .where(
                  (d) => RegExp(r'[/\\]xml(?:-[^/\\]+)?$').hasMatch(d.path))) {
            final file = File('${dir.path}/${match[1]}.xml');
            if (!file.existsSync()) continue;
            if (FileSystemEntity.typeSync(file.path, followLinks: false) !=
                    FileSystemEntityType.file ||
                file.lengthSync() > 1024 * 1024 ||
                docs.length >= 64) {
              throw const FormatException('Resource limit');
            }
            docs.add((file.path, XmlDocument.parse(file.readAsStringSync())));
          }
        }
        if (docs.isEmpty) throw const FormatException('Missing resource');
        for (final (file, doc) in docs) {
          final policy = inspectBackupPolicy(doc);
          final expected = key == 'fullBackupContent'
              ? 'full-backup-content'
              : 'data-extraction-rules';
          if (policy.issues.isNotEmpty ||
              doc.rootElement.name.local != expected) {
            evidence(
                file,
                Bilingual(En.platformBackupInvalid(file: file),
                    Ar.platformBackupInvalid(file: file)),
                status: 'unavailable',
                data: {'issues': policy.issues});
          }
          for (final flow in policy.flows.entries) {
            final includes =
                flow.value.where((r) => r['action'] == 'include').length;
            final excludes =
                flow.value.where((r) => r['action'] == 'exclude').length;
            evidence(
                file,
                Bilingual(
                    En.platformBackupPolicy(
                        file: file,
                        flow: flow.key,
                        includes: includes,
                        excludes: excludes),
                    Ar.platformBackupPolicy(
                        file: file,
                        flow: flow.key,
                        includes: includes,
                        excludes: excludes)),
                data: {'flow': flow.key, 'rules': flow.value});
          }
          if (key == 'dataExtractionRules' &&
              !policy.flows.keys
                  .toSet()
                  .containsAll(['cloud-backup', 'device-transfer'])) {
            evidence(
                file,
                const Bilingual(
                    En.platformBackupMissing, Ar.platformBackupMissing));
          }
        }
      } catch (_) {
        evidence(key,
            const Bilingual(En.platformBackupMissing, Ar.platformBackupMissing),
            status: 'unavailable');
      }
    }
    evidence(p.apk?.fileName ?? 'AndroidManifest.xml',
        const Bilingual(En.platformN05Limit, Ar.platformN05Limit),
        data: config);
  }

  Future<void> _links(
      Project p,
      List<Finding> out,
      void Function(String, Bilingual,
              {Map<String, Object?> data, String status})
          evidence) async {
    final hosts = <String>{}, ids = <String>{};
    for (final value in p.entitlements.values) {
      final domains = value['com.apple.developer.associated-domains'];
      if (domains is List) {
        hosts.addAll(domains
            .whereType<String>()
            .where((s) => s.startsWith('applinks:'))
            .map((s) => s.substring(9)));
      }
      if (value['application-identifier'] is String) {
        ids.add(value['application-identifier'] as String);
      }
    }
    if (hosts.isEmpty ||
        p.offline ||
        p.ipa == null ||
        ids.length != 1 ||
        !ids.single.endsWith('.${p.ipa!.bundleId}')) {
      evidence(
          p.ipa?.label ?? 'entitlements',
          const Bilingual(
              En.platformAasaUnavailable, Ar.platformAasaUnavailable),
          status: 'unavailable');
      return;
    }
    for (final host in hosts.take(8)) {
      bool? matched;
      if (RegExp(r'^[A-Za-z0-9.-]+$').hasMatch(host) && host.contains('.')) {
        for (final path in [
          '/.well-known/apple-app-site-association',
          '/apple-app-site-association'
        ]) {
          try {
            matched = iosAssociationMatches(
                await (fetcher ?? fetchPublicJson)(
                    Uri(scheme: 'https', host: host, path: path)),
                ids.single);
            if (matched != null) break;
          } catch (_) {/* A failed lookup is not a negative authorization. */}
        }
      }
      if (matched == false) {
        out.add(inFile(p.ipa!.label, null, En.platformAasaMismatch(host: host),
            messageAr: Ar.platformAasaMismatch(host: host)));
      }
      evidence(
          host,
          matched == null
              ? const Bilingual(
                  En.platformAasaUnavailable, Ar.platformAasaUnavailable)
              : Bilingual(
                  En.platformAasa(
                      host: host,
                      authorized: matched ? En.platformYes : En.platformNo),
                  Ar.platformAasa(
                      host: host,
                      authorized: matched ? Ar.platformYes : Ar.platformNo)),
          status: matched == null ? 'unavailable' : 'facts',
          data: {'authorizedIdentity': matched, 'urlRoutingVerified': false});
    }
    if (hosts.length > 8) {
      evidence(
          'AASA',
          const Bilingual(
              En.platformAasaUnavailable, Ar.platformAasaUnavailable),
          status: 'unavailable');
    }
  }
}

const platformFactLabels = <String, Bilingual>{
  'windows': Bilingual(En.platformFactWindows, Ar.platformFactWindows),
  'passwordFields':
      Bilingual(En.platformFactPasswordFields, Ar.platformFactPasswordFields),
  'unmaskedPasswordFields': Bilingual(En.platformFactUnmaskedPasswordFields,
      Ar.platformFactUnmaskedPasswordFields),
  'files': Bilingual(En.platformFactFiles, Ar.platformFactFiles),
  'excludedFiles':
      Bilingual(En.platformFactExcludedFiles, Ar.platformFactExcludedFiles),
  'unexcludedFiles':
      Bilingual(En.platformFactUnexcludedFiles, Ar.platformFactUnexcludedFiles),
  'unknownFiles':
      Bilingual(En.platformFactUnknownFiles, Ar.platformFactUnknownFiles),
  'keychainItems':
      Bilingual(En.platformFactKeychainItems, Ar.platformFactKeychainItems),
  'keychainAlways':
      Bilingual(En.platformFactKeychainAlways, Ar.platformFactKeychainAlways),
  'keychainAcl':
      Bilingual(En.platformFactKeychainAcl, Ar.platformFactKeychainAcl),
  'webviews': Bilingual(En.platformFactWebviews, Ar.platformFactWebviews),
  'webviewJs': Bilingual(En.platformFactWebviewJs, Ar.platformFactWebviewJs),
  'webviewInsecureContent': Bilingual(En.platformFactWebviewInsecureContent,
      Ar.platformFactWebviewInsecureContent),
  'customSchemes':
      Bilingual(En.platformFactCustomSchemes, Ar.platformFactCustomSchemes),
  'secureWindows':
      Bilingual(En.platformFactSecureWindows, Ar.platformFactSecureWindows),
  'clickableViews':
      Bilingual(En.platformFactClickableViews, Ar.platformFactClickableViews),
  'filterControls':
      Bilingual(En.platformFactFilterControls, Ar.platformFactFilterControls),
  'filterRejectsFull': Bilingual(
      En.platformFactFilterRejectsFull, Ar.platformFactFilterRejectsFull),
  'filterRejectsPartial': Bilingual(
      En.platformFactFilterRejectsPartial, Ar.platformFactFilterRejectsPartial),
  'keystoreAliases':
      Bilingual(En.platformFactKeystoreAliases, Ar.platformFactKeystoreAliases),
  'authRequiredKeys': Bilingual(
      En.platformFactAuthRequiredKeys, Ar.platformFactAuthRequiredKeys),
  'unknownKeys':
      Bilingual(En.platformFactUnknownKeys, Ar.platformFactUnknownKeys),
  'screenshotsCaptured': Bilingual(
      En.platformFactScreenshotsCaptured, Ar.platformFactScreenshotsCaptured),
  'backgroundObserved': Bilingual(
      En.platformFactBackgroundObserved, Ar.platformFactBackgroundObserved),
  'backgroundPasswordFields': Bilingual(En.platformFactBackgroundPasswordFields,
      Ar.platformFactBackgroundPasswordFields),
  'backgroundUnmaskedPasswordFields': Bilingual(
      En.platformFactBackgroundUnmaskedPasswordFields,
      Ar.platformFactBackgroundUnmaskedPasswordFields),
};
