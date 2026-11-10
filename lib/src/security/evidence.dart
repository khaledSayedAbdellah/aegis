import '../model.dart';

/// Informational evidence is deliberately outside findings/scoring/coverage.
class SecurityEvidence {
  const SecurityEvidence(this.ruleId, this.file, this.detail,
      {this.status = 'observed', this.data = const {}});
  final String ruleId;
  final String file;
  final Bilingual detail;
  final String status;
  final Map<String, Object?> data;
  Map<String, Object?> toJson() => {
        'ruleId': ruleId,
        'file': file,
        'status': status,
        'detail': detail.en,
        'detailAr': detail.ar,
        'data': data,
        'countsTowardScore': false,
        'provesMasvsCompliance': false,
      };
}
