/// Security audit for Flutter, React Native, KMP and native Android/iOS
/// apps.
///
/// ```dart
/// final report = await runAudit('path/to/app');
/// print(ConsoleReporter().render(report));
/// ```
///
/// Everything this library exports follows semantic versioning; code under
/// `package:aegis/src/` is internal and can change in any release. See
/// "Stability" in the README.
library;

export 'src/baseline.dart' show Baseline, BaselineEntry, defaultBaselineFile;
export 'src/changed_lines.dart' show ChangedLines;
export 'src/config.dart' show AegisConfig;
export 'src/rules/custom_rules.dart' show CustomRuleSpec;
export 'src/engine.dart'
    show AuditReport, BinaryInfo, CertificateInfo, runAudit;
export 'src/masvs.dart'
    show MasvsControl, ManualCheck, masvsControls, manualChecks;
export 'src/model.dart';
export 'src/probe/probe_model.dart'
    show
        ProbeApkIdentity,
        ProbeCheck,
        ProbeOutcome,
        ProbeReport,
        ProbeResult,
        ProbeStatus,
        probeChecks;
export 'src/reporters/azure.dart' show renderAzure;
export 'src/reporters/console.dart' show ConsoleReporter;
export 'src/reporters/html.dart' show renderHtml;
export 'src/reporters/json.dart' show renderJson, renderSarif, reportToJson;
export 'src/reporters/markdown.dart' show renderMarkdown;
export 'src/rules/registry.dart' show allRules, apkRules;
export 'src/rules/rule.dart' show Rule, RuleCheck;
export 'src/scoring.dart' show Score, Coverage, CategoryScore;
export 'src/version.dart' show aegisVersion;

export 'src/security/evidence.dart' show SecurityEvidence;
export 'src/security/runtime_security.dart' show RuntimeSecurityResult;
