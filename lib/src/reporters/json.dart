/// Machine-readable reports: JSON and SARIF 2.1.0.
library;

import 'dart:convert';

import '../baseline.dart';
import '../engine.dart';
import '../model.dart';
import '../probe/probe_model.dart';
import 'probe_view.dart';

Map<String, Object?> reportToJson(AuditReport r) => {
      'tool': 'aegis',
      'version': r.version,
      'generatedAt': r.generatedAt.toUtc().toIso8601String(),
      'project': r.projectName,
      'profile': r.profile.toString(),
      'complete': r.complete,
      'scannedPackages': r.scannedPackages,
      'securityEvidence': r.securityEvidence.map((e) => e.toJson()).toList(),
      if (r.binary != null) 'binary': r.binary!.toJson(),
      if (r.probe != null) 'probe': _probeJson(r.probe!),
      if (r.iosStatic != null) 'iosStaticAnalysis': r.iosStatic!.toJson(),
      'score': {
        'value': r.score.value,
        'grade': r.score.grade,
        'provisional': !r.complete,
        if (r.score.capReason != null) 'cappedBy': r.score.capReason,
        if (r.score.worst != null) ...{
          'worstSeverity': r.score.worst!.name,
          'band': [r.score.band!.$1, r.score.band!.$2 - 1],
          'blockingRules': r.score.blockingRules,
          'afterBlockingFixed': r.score.afterBlockingFixed,
          'penalty': double.parse(r.score.penalty.toStringAsFixed(2)),
          'gains': r.score.gains,
        },
        'categories': {
          for (final c in r.score.categories.values)
            c.category: {
              'score': c.score,
              'checkedRules': c.checked,
              'failedRules': c.failed,
              'failedRuleIds': c.failedRuleIds,
              if (c.worst != null) 'worstSeverity': c.worst!.name,
            }
        },
      },
      'coverage': {
        'percent': r.coverage.percent,
        'checked': r.coverage.checked,
        'inScope': r.coverage.inScope,
        'controls': [
          for (final c in r.coverage.controls)
            {
              'id': c.control.id,
              'status': c.status.name,
              'rules': c.ruleIds,
              'failedRules': c.failedRuleIds,
            }
        ],
      },
      'summary': {
        for (final s in Severity.values.reversed)
          s.name: r.failed.where((x) => x.severity == s).length,
        'passed': r.passed.length,
        'notApplicable': r.notApplicable.length,
        'evidenceOnly': r.evidenceOnly.length,
        'incomplete': r.incomplete.length,
        'suppressed': r.suppressed,
      },
      if (r.usesBaseline)
        'baseline': {
          'file': r.baselinePath,
          'known': r.knownFindingCount,
          'new': r.newFindingCount,
          'fixed': r.resolvedCount,
          'fixedFindings': [for (final e in r.baselineResolved) e.toJson()],
        },
      'rules': [
        for (final res in r.results)
          {
            'id': res.meta.id,
            'title': res.status == RuleStatus.passed
                ? res.meta.passTitle.en
                : res.meta.title.en,
            'status': res.status.name,
            'severity': res.severity.name,
            'masvs': res.meta.masvs,
            'maswe': res.meta.maswe,
            if (res.meta.cwe != null) 'cwe': res.meta.cwe,
            if (res.incomplete) 'incomplete': true,
            if (res.note != null) 'note': res.note,
            if (res.noteAr != null) 'noteAr': res.noteAr,
            'findings': [
              for (final f in res.findings)
                {...f.toJson(), 'fingerprint': Baseline.fingerprint(f)}
            ],
          }
      ],
      'manualChecks': [
        for (final m in r.manual)
          {'id': m.id, 'masvs': m.masvs, 'text': m.text.en}
      ],
    };

String renderJson(AuditReport r) =>
    const JsonEncoder.withIndent('  ').convert(reportToJson(r));

String _sarifLevel(Severity s) {
  switch (s) {
    case Severity.critical:
    case Severity.high:
      return 'error';
    case Severity.medium:
      return 'warning';
    case Severity.low:
    case Severity.info:
      return 'note';
  }
}

/// SARIF 2.1.0 for GitHub code scanning and other CI dashboards.
String renderSarif(AuditReport r) {
  final rules = r.results.where((x) => x.status == RuleStatus.failed).toList();
  final sarif = {
    r'$schema': 'https://json.schemastore.org/sarif-2.1.0.json',
    'version': '2.1.0',
    'runs': [
      {
        'tool': {
          'driver': {
            'name': 'aegis',
            'version': r.version,
            'informationUri': 'https://github.com/khaledSayedAbdellah/aegis',
            'rules': [
              for (final res in rules)
                {
                  'id': res.meta.id,
                  'name': res.meta.title.en,
                  'shortDescription': {'text': res.meta.title.en},
                  'fullDescription': {'text': res.meta.description.en},
                  'help': {'text': res.meta.fix.en},
                  'defaultConfiguration': {'level': _sarifLevel(res.severity)},
                  'properties': {
                    'tags': [
                      'security',
                      ...res.meta.masvs,
                      if (res.meta.cwe != null) res.meta.cwe!
                    ],
                    'security-severity': _securitySeverity(res.severity),
                  },
                }
            ],
          }
        },
        'results': [
          for (final res in rules)
            for (final f in res.findings)
              {
                'ruleId': res.meta.id,
                'level': _sarifLevel(res.severity),
                'message': {'text': f.message},
                'partialFingerprints': {'aegis/v1': Baseline.fingerprint(f)},
                if (r.usesBaseline)
                  'baselineState': f.baselined ? 'unchanged' : 'new',
                'locations': [
                  {
                    'physicalLocation': {
                      'artifactLocation': {'uri': f.file ?? 'pubspec.yaml'},
                      if (f.line != null) 'region': {'startLine': f.line},
                    }
                  }
                ],
              }
        ],
        'properties': {
          'complete': r.complete,
          'incompleteRules': r.incomplete.map((r) => r.meta.id).toList(),
          'score': r.score.value,
          'scoreProvisional': !r.complete,
          'grade': r.score.grade,
          'profile': r.profile.toString(),
        },
      }
    ],
  };
  return const JsonEncoder.withIndent('  ').convert(sarif);
}

String _securitySeverity(Severity s) {
  switch (s) {
    case Severity.critical:
      return '9.5';
    case Severity.high:
      return '8.0';
    case Severity.medium:
      return '5.5';
    case Severity.low:
      return '3.0';
    case Severity.info:
      return '0.0';
  }
}

/// The probe's outcome: what ran, each check's status and evidence, or why
/// it was skipped. The verdicts also appear as rules AEG-R01..R04.
Map<String, Object?> _probeJson(ProbeOutcome o) {
  final r = o.report;
  if (r == null) {
    return {
      'ran': false,
      'skipped': o.skipped,
      if (o.skippedAr != null) 'skippedAr': o.skippedAr
    };
  }
  return {
    'ran': true,
    if (r.platform != 'android') 'platform': r.platform,
    if (r.platformObserverAttempts.isNotEmpty)
      'platformObserverAttempts': r.platformObserverAttempts.toList()..sort(),
    'app': r.app.split(RegExp(r'[\\/]')).last,
    if (r.emulatorError != null) 'emulatorError': r.emulatorError,
    if (r.apkIdentity case final identity?)
      'companionApk': {
        'signatureVerified': true,
        'signerSha256': identity.signerSha256,
        if (identity.expectedSignerSha256 != null)
          'expectedSignerSha256': identity.expectedSignerSha256,
        'buildProvenance': 'userSupplied',
        if (identity.controlApks.isNotEmpty)
          'controlApks': identity.controlApks,
        if (identity.rootedApks.isNotEmpty) 'rootedApks': identity.rootedApks,
      },
    'baselineAlive': r.baselineAlive,
    if (r.baselineNote != null && r.baselineNote!.trim().isNotEmpty)
      'baselineNote': r.baselineNote,
    if (r.baselineNoteAr != null) 'baselineNoteAr': r.baselineNoteAr,
    'checks': [
      for (final x in r.scored)
        {
          'id': x.check.id,
          if (probeRuleIds[x.check.id] != null)
            'rule': probeRuleIds[x.check.id],
          'status': x.observedStatus.name,
          if (x.partialStatus != null) ...{
            'coverage': 'partial',
            'scope': 'ios-simulator',
            'fullConditionStatus': x.status.name,
            'partialStatus': x.partialStatus!.name,
            'environment': 'ios-simulator',
            'limitations': x.note,
            'limitationsAr': x.noteAr,
          },
          if (x.processOnly) 'scope': 'process',
          if (x.check.masvs != null) 'masvs': x.check.masvs,
          if (x.check.mastg != null) 'mastg': x.check.mastg,
          if (x.evidence.isNotEmpty) 'evidence': x.evidence,
          if (x.evidenceAr != null) 'evidenceAr': x.evidenceAr,
          if (x.note != null) 'note': x.note,
          if (x.noteAr != null) 'noteAr': x.noteAr,
        }
    ],
  };
}
