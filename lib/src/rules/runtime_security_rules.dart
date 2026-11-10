import '../model.dart';
import '../project.dart';
import '../l10n/messages.g.dart';
import '../security/evidence.dart';
import '../security/metadata.dart';
import 'rule.dart';

class RuntimeSecurityRule extends Rule {
  const RuntimeSecurityRule(this.id);
  final String id;
  @override
  RuleMeta get meta => extendedMeta(id);
  @override
  RuleCheck check(Project p, ProfileSet profile) {
    final result = p.runtimeSecurity;
    if (result == null) return RuleCheck.notApplicable();
    if (!result.requested) {
      return RuleCheck.notApplicableLocalized(
          En.extRuntimeDisabled, Ar.extRuntimeDisabled);
    }
    if (!result.configured) {
      return RuleCheck.incompleteLocalized(
          En.extRuntimeMissing, Ar.extRuntimeMissing);
    }
    final data = result.data;
    p.securityEvidence.add(SecurityEvidence(
        id,
        result.scenario,
        Bilingual(
            En.extRuntimeScope(
                scenario: result.scenario, digest: result.digest),
            Ar.extRuntimeScope(
                scenario: result.scenario, digest: result.digest)),
        status: 'facts',
        data: {
          'artifactSha256': result.digest,
          'baseline': data['baseline'] == true,
          'cleanup': data['cleanup'] == true,
          'scenario': result.scenario
        }));
    if (data['baseline'] != true) {
      return RuleCheck.incompleteLocalized(
          En.extRuntimeIncomplete, Ar.extRuntimeIncomplete);
    }
    final out = <Finding>[];
    if (id == 'AEG-R09') {
      final network = data['network'];
      if (network is List) {
        final seen = <String>{};
        for (final e in network.whereType<Map>()) {
          final host = e['host'], phase = e['phase'];
          if (host is! String ||
              !['untrusted', 'trusted'].contains(phase) ||
              phase == 'trusted' && !result.pinnedHosts.contains(host) ||
              !seen.add('$host/$phase')) {
            continue;
          }
          out.add(inFile(
              result.scenario, null, En.extRuntimeTls(host: host, phase: phase),
              messageAr: Ar.extRuntimeTls(host: host, phase: phase)));
        }
      }
      // No request may mean the UI never reached the request, routing failed, or
      // RASP stopped instrumentation. Never turn silence into a pinning pass.
      return RuleCheck.incompleteLocalized(
          En.extRuntimeIncomplete, Ar.extRuntimeIncomplete, out);
    }
    final storage = data['storage'];
    if (storage is Map && storage['hits'] is List) {
      for (final e in (storage['hits'] as List).whereType<Map>()) {
        if (!result.markers.contains(e['marker']) ||
            !['files', 'logs', 'clipboard'].contains(e['channel'])) {
          continue;
        }
        out.add(inFile(result.scenario, null,
            En.extRuntimeLeak(marker: e['marker'], channel: e['channel']),
            messageAr:
                Ar.extRuntimeLeak(marker: e['marker'], channel: e['channel'])));
      }
    }
    final channels = storage is Map ? storage['channels'] : null;
    final complete = result.markers.isNotEmpty &&
        channels is Map &&
        ['files', 'logs', 'clipboard'].every((c) => channels[c] == true) &&
        storage is Map && storage['limited'] == false &&
        data['cleanup'] == true;
    return complete
        ? RuleCheck(out)
        : RuleCheck.incompleteLocalized(
            En.extRuntimeIncomplete, Ar.extRuntimeIncomplete, out);
  }
}

const runtimeSecurityRules = [
  RuntimeSecurityRule('AEG-R09'),
  RuntimeSecurityRule('AEG-R10')
];
