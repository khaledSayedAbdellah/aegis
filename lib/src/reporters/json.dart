/// Machine-readable reports: JSON and SARIF 2.1.0.
library;

import 'dart:convert';

import '../baseline.dart';
import '../engine.dart';
import '../model.dart';

Map<String, Object?> reportToJson(AuditReport r) => {
      'tool': 'aegis',
      'version': r.version,
      'generatedAt': r.generatedAt.toUtc().toIso8601String(),
      'project': r.projectName,
      'profile': r.profile.toString(),
      'scannedPackages': r.scannedPackages,
      if (r.binary != null) 'binary': r.binary!.toJson(),
      'score': {
        'value': r.score.value,
        'grade': r.score.grade,
        if (r.score.capReason != null) 'cappedBy': r.score.capReason,
        if (r.score.capReason != null) 'ceiling': r.score.ceiling,
        if (r.score.capReason != null) 'capRules': r.score.capRules,
        'uncapped': r.score.uncapped,
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
            if (res.note != null) 'note': res.note,
            'findings': [
              for (final f in res.findings)
                {...f.toJson(), 'fingerprint': Baseline.fingerprint(f)}
            ],
          }
      ],
      'manualChecks': [
        for (final m in r.manual) {'id': m.id, 'masvs': m.masvs, 'text': m.text.en}
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
                    'tags': ['security', ...res.meta.masvs, if (res.meta.cwe != null) res.meta.cwe!],
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
                if (r.usesBaseline) 'baselineState': f.baselined ? 'unchanged' : 'new',
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
          'score': r.score.value,
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
