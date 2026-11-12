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
    // A scenario part with nothing configured was never requested: say so
    // instead of leaving the other part's run permanently incomplete.
    if (data['baseline'] == true) {
      if (id == 'AEG-R09' && result.hosts.isEmpty) {
        return RuleCheck.notApplicableLocalized(
            En.extRuntimeNoHosts, Ar.extRuntimeNoHosts);
      }
      if (id == 'AEG-R10' && result.markers.isEmpty) {
        return RuleCheck.notApplicableLocalized(
            En.extRuntimeNoMarkers, Ar.extRuntimeNoMarkers);
      }
    }
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
          'scenario': result.scenario,
          if (id == 'AEG-R09')
            'phases': [
              for (final phase in ['untrusted', 'trusted'])
                if (data['phases'] case final List phases
                    when phases.contains(phase))
                  phase
            ]
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
      // The requested scenario finished when the baseline reached every pinned
      // endpoint, each interception phase it called for completed, and cleanup
      // restored the target without errors.
      final phases = data['phases'],
          reached = data['baseline_hosts'],
          errors = data['errors'];
      final finished = data['cleanup'] == true &&
          errors is List &&
          errors.isEmpty &&
          reached is List &&
          reached.isNotEmpty &&
          result.pinnedHosts.every(reached.contains) &&
          phases is List &&
          phases.contains('untrusted') &&
          (result.pinnedHosts.isEmpty || phases.contains('trusted'));
      if (!finished) {
        return RuleCheck.incompleteLocalized(
            En.extRuntimeIncomplete, Ar.extRuntimeIncomplete, out);
      }
      if (out.isNotEmpty) return RuleCheck(out);
      // No request may mean the UI never reached the request, routing failed, or
      // RASP stopped instrumentation. Never turn silence into a pinning pass:
      // a finished scenario without interception is review evidence only.
      return RuleCheck.evidenceOnly(
          En.extRuntimeNoInterception, Ar.extRuntimeNoInterception);
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
        storage is Map &&
        storage['limited'] == false &&
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
