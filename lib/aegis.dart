/// Security audit for Flutter apps.
///
/// ```dart
/// final report = await runAudit('path/to/app');
/// print(ConsoleReporter().render(report));
/// ```
library;

export 'src/baseline.dart' show Baseline, BaselineEntry, defaultBaselineFile;
export 'src/binary/apk.dart' show ApkContext;
export 'src/binary/locate.dart' show findBuiltBinary, findNewestBinary, flutterApkDir, flutterBundleDir;
export 'src/binary/signing.dart' show SigningCert;
export 'src/config.dart' show AegisConfig;
export 'src/engine.dart' show AuditReport, BinaryInfo, CertificateInfo, runAudit;
export 'src/masvs.dart' show MasvsControl, ManualCheck, masvsControls, manualChecks;
export 'src/model.dart';
export 'src/reporters/azure.dart' show renderAzure;
export 'src/reporters/console.dart' show ConsoleReporter;
export 'src/reporters/html.dart' show renderHtml;
export 'src/reporters/json.dart' show renderJson, renderSarif, reportToJson;
export 'src/reporters/markdown.dart' show renderMarkdown;
export 'src/rules/registry.dart' show allRules, apkRules;
export 'src/rules/rule.dart' show Rule, RuleCheck;
export 'src/scoring.dart' show Score, Coverage, CategoryScore;
export 'src/version.dart' show aegisVersion;
