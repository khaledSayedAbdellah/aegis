import 'package:xml/xml.dart';
import '../model.dart';
import '../project.dart';
import '../l10n/messages.g.dart';
import '../security/evidence.dart';
import '../security/metadata.dart';
import '../security/public_json.dart';
import 'rule.dart';

typedef AssociationFetcher = Future<Object?> Function(Uri uri);
String? _a(XmlElement e, String name) => androidAttr(e, name);
XmlDocument? _manifest(Project p) => p.apk?.manifest ?? p.androidManifestXml;
String _file(Project p) =>
    p.apk?.location('AndroidManifest.xml') ??
    p.androidManifest?.path ??
    'AndroidManifest.xml';
Iterable<XmlElement> _links(XmlDocument doc) =>
    doc.findAllElements('intent-filter').where((f) =>
        f
            .findElements('action')
            .any((a) => _a(a, 'name') == 'android.intent.action.VIEW') &&
        f
            .findElements('category')
            .any((a) => _a(a, 'name') == 'android.intent.category.BROWSABLE'));

class AndroidLinksRule extends Rule {
  const AndroidLinksRule();
  @override
  RuleMeta get meta => extendedMeta('AEG-A11');
  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final doc = _manifest(project);
    if (doc == null) return RuleCheck.notApplicable();
    final out = <Finding>[];
    for (final f in _links(doc)) {
      final data = f.findElements('data').toList();
      final web = data.any((d) => ['http', 'https'].contains(_a(d, 'scheme')));
      final component = _a(f.parent as XmlElement, 'name') ?? 'VIEW';
      void add(String en, String ar) => out.add(inFile(_file(project), null,
          En.extManifestFinding(component: component, detail: en),
          messageAr: Ar.extManifestFinding(component: component, detail: ar)));
      if (web) {
        if (_a(f, 'autoVerify') != 'true') add(En.extLinkAuto, Ar.extLinkAuto);
        final hosts = data.map((d) => _a(d, 'host')).whereType<String>();
        if (hosts.isEmpty || hosts.any((h) => h.contains('*'))) {
          add(En.extLinkBroad, Ar.extLinkBroad);
        }
      }
      if (data.any((d) =>
          _a(d, 'scheme') != null &&
          !['http', 'https'].contains(_a(d, 'scheme')))) {
        project.securityEvidence.add(SecurityEvidence(meta.id, _file(project),
            const Bilingual(En.extLinkCustom, Ar.extLinkCustom)));
      }
    }
    return RuleCheck(out);
  }
}

/// Checks BOTH provider operations and inherited application permissions.
class AndroidPermissionStrengthRule extends Rule {
  const AndroidPermissionStrengthRule();
  @override
  RuleMeta get meta => extendedMeta('AEG-A12');
  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final doc = _manifest(project);
    if (doc == null) return RuleCheck.notApplicable();
    final app = doc.findAllElements('application').firstOrNull;
    if (app == null) {
      return RuleCheck.incompleteLocalized(En.extIncomplete, Ar.extIncomplete);
    }
    final declared = {
      for (final e in doc.findAllElements('permission'))
        _a(e, 'name'): _a(e, 'protectionLevel') ?? 'normal'
    };
    final target = int.tryParse(
            (doc.findAllElements('uses-sdk').firstOrNull == null
                    ? null
                    : _a(doc.findAllElements('uses-sdk').first,
                        'targetSdkVersion')) ??
                '') ??
        1;
    final out = <Finding>[];
    var unknown = false;
    for (final e in app.children.whereType<XmlElement>().where((e) => [
          'activity',
          'activity-alias',
          'service',
          'receiver',
          'provider'
        ].contains(e.name.local))) {
      final provider = e.name.local == 'provider';
      final exported = _a(e, 'exported');
      if (exported == 'false' ||
          exported != 'true' &&
              !(provider
                  ? target < 17
                  : e.findElements('intent-filter').isNotEmpty)) {
        continue;
      }
      final common = _a(e, 'permission') ?? _a(app, 'permission');
      for (final op in provider ? ['read', 'write'] : ['invoke']) {
        final permission =
            (provider ? _a(e, '${op}Permission') : null) ?? common;
        String? en, ar;
        if (permission == null || permission.isEmpty) {
          if (!provider) {
            continue; // A06/B04 own ordinary unprotected components.
          }
          en = En.extProviderOpen(operation: op);
          ar = Ar.extProviderOpen(operation: op);
        } else if (declared.containsKey(permission)) {
          final value = declared[permission]!;
          final number = value.startsWith('0x')
              ? int.tryParse(value.substring(2), radix: 16)
              : int.tryParse(value);
          final base = value.split('|').first.trim();
          final strong = number != null
              ? [2, 3, 4].contains(number & 15)
              : ['signature', 'signatureOrSystem', 'internal'].contains(base);
          if (!strong) {
            en = En.extPermissionWeak(operation: op, permission: permission);
            ar = Ar.extPermissionWeak(operation: op, permission: permission);
          }
        } else {
          unknown = true;
          project.securityEvidence.add(SecurityEvidence(
              meta.id,
              _file(project),
              Bilingual(En.extPermissionUnknown(permission: permission),
                  Ar.extPermissionUnknown(permission: permission)),
              status: 'unavailable'));
        }
        if (en != null) {
          out.add(inFile(
              _file(project),
              null,
              En.extManifestFinding(
                  component: _a(e, 'name') ?? e.name.local, detail: en),
              messageAr: Ar.extManifestFinding(
                  component: _a(e, 'name') ?? e.name.local, detail: ar)));
        }
      }
      // A path permission may override otherwise strong provider protection.
      for (final path in e.findElements('path-permission')) {
        for (final key in ['permission', 'readPermission', 'writePermission']) {
          final permission = _a(path, key);
          if (permission != null &&
              ['normal', 'dangerous', '0', '1', '0x0', '0x1']
                  .contains(declared[permission])) {
            out.add(inFile(
                _file(project),
                null,
                En.extPermissionWeak(
                    operation: 'path/$key', permission: permission),
                messageAr: Ar.extPermissionWeak(
                    operation: 'path/$key', permission: permission)));
          }
        }
      }
    }
    return unknown
        ? RuleCheck.incompleteLocalized(En.extIncomplete, Ar.extIncomplete, out)
        : RuleCheck(out);
  }
}

bool authorizesAndroidAssociation(
    Object? json, String package, Set<String> fingerprints) {
  if (json is! List || fingerprints.isEmpty) return false;
  final authorized = <String>{};
  for (final statement in json.whereType<Map>()) {
    final target = statement['target'];
    final relation = statement['relation'];
    if (target is! Map ||
        relation is! List ||
        !relation.contains('delegate_permission/common.handle_all_urls') ||
        target['namespace'] != 'android_app' ||
        target['package_name'] != package) {
      continue;
    }
    final certs = target['sha256_cert_fingerprints'];
    if (certs is List) {
      authorized.addAll(certs
          .whereType<String>()
          .map((s) => s.replaceAll(':', '').toLowerCase()));
    }
  }
  return fingerprints
      .every((s) => authorized.contains(s.replaceAll(':', '').toLowerCase()));
}

class AndroidAssociationRule extends Rule {
  const AndroidAssociationRule({this.fetcher});
  final AssociationFetcher? fetcher;
  @override
  RuleMeta get meta => extendedMeta('AEG-A13');
  @override
  Future<RuleCheck> check(Project project, ProfileSet profile) async {
    final doc = _manifest(project);
    if (doc == null) return RuleCheck.notApplicable();
    final hosts = <String>{};
    for (final f in _links(doc)) {
      if (!f
          .findElements('data')
          .any((e) => ['http', 'https'].contains(_a(e, 'scheme')))) {
        continue;
      }
      hosts.addAll(
          f.findElements('data').map((e) => _a(e, 'host')).whereType<String>());
    }
    if (hosts.isEmpty) return RuleCheck.notApplicable();
    final apk = project.apk;
    if (project.offline ||
        apk == null ||
        apk.isBundle ||
        apk.certificates.isEmpty) {
      return RuleCheck.incompleteLocalized(
          En.extLinkUnavailable, Ar.extLinkUnavailable);
    }
    final out = <Finding>[];
    var incomplete = hosts.length > 8;
    for (final host in hosts.take(8)) {
      try {
        if (host.contains('*')) {
          incomplete = true;
          continue;
        }
        final uri = Uri(
            scheme: 'https', host: host, path: '/.well-known/assetlinks.json');
        final json = await (fetcher ?? fetchPublicJson)(uri);
        if (json is! List) {
          incomplete = true;
          continue;
        }
        if (!authorizesAndroidAssociation(json, apk.packageName!,
            apk.certificates.map((c) => c.sha256Hex).toSet())) {
          out.add(inFile(_file(project), null, '$host: ${En.extLinkMismatch}',
              messageAr: '$host: ${Ar.extLinkMismatch}'));
        }
      } catch (_) {
        incomplete = true;
      }
    }
    return incomplete
        ? RuleCheck.incompleteLocalized(
            En.extLinkUnavailable, Ar.extLinkUnavailable, out)
        : RuleCheck(out);
  }
}

class IosEntitlementScopeRule extends Rule {
  const IosEntitlementScopeRule();
  @override
  RuleMeta get meta => extendedMeta('AEG-I10');
  @override
  RuleCheck check(Project project, ProfileSet profile) {
    if (project.entitlements.isEmpty) {
      return project.ipa != null
          ? RuleCheck.incompleteLocalized(En.extIncomplete, Ar.extIncomplete)
          : RuleCheck.notApplicable();
    }
    final out = <Finding>[];
    for (final e in project.entitlements.entries) {
      if (project.ipa == null &&
          RegExp(r'(debug|profile)', caseSensitive: false).hasMatch(e.key)) {
        continue;
      }
      for (final v in e.value.entries) {
        final sensitive = [
              'platform-application',
              'com.apple.private.security.no-sandbox',
              'com.apple.private.security.no-container'
            ].contains(v.key) &&
            v.value == true;
        final broad = [
              'keychain-access-groups',
              'com.apple.security.application-groups',
              'com.apple.developer.associated-domains'
            ].contains(v.key) &&
            v.value is List &&
            (v.value as List)
                .whereType<String>()
                .any((s) => s.contains('*') || s.contains('?mode=developer'));
        if (sensitive || broad) {
          out.add(inFile(
              e.key, null, En.extEntitlement(key: v.key, value: v.value),
              messageAr: Ar.extEntitlement(key: v.key, value: v.value)));
        }
        // Hardened-runtime flags are primarily macOS concepts. Inventory only.
        if (v.key.startsWith('com.apple.security.cs.') && v.value == true) {
          project.securityEvidence.add(SecurityEvidence(
              meta.id,
              e.key,
              Bilingual(En.extEntitlement(key: v.key, value: v.value),
                  Ar.extEntitlement(key: v.key, value: v.value))));
        }
      }
    }
    final partial =
        project.ipa?.machO.any((s) => s.entitlements == null) ?? false;
    return partial
        ? RuleCheck.incompleteLocalized(En.extIncomplete, Ar.extIncomplete, out)
        : RuleCheck(out);
  }
}

class AtsForwardSecrecyRule extends Rule {
  const AtsForwardSecrecyRule();
  @override
  RuleMeta get meta => extendedMeta('AEG-I11');
  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final info = project.infoPlistData;
    if (info == null) return RuleCheck.notApplicable();
    final ats = info['NSAppTransportSecurity'];
    final domains = ats is Map ? ats['NSExceptionDomains'] : null;
    final out = <Finding>[];
    if (domains is Map) {
      domains.forEach((domain, cfg) {
        if (cfg is! Map) {
          return;
        }
        for (final key in [
          'NSExceptionRequiresForwardSecrecy',
          'NSTemporaryExceptionRequiresForwardSecrecy'
        ]) {
          if (cfg[key] == false) {
            out.add(inFile(project.infoPlist?.path, null,
                En.extNativeMatch(token: '$domain / $key = false'),
                messageAr: Ar.extNativeMatch(token: '$domain / $key = false')));
          }
        }
      });
    }
    return RuleCheck(out);
  }
}
