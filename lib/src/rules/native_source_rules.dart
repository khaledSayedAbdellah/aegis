import 'dart:io';

import '../model.dart';
import '../project.dart';
import '../l10n/messages.g.dart';
import '../security/native_analysis.dart';
import '../security/script_analysis.dart';
import '../project/native_files.dart';
import 'package:path/path.dart' as p;
import '../util.dart';
import 'dart_rules.dart'
    show knownSecretPatterns, pemBodyFollows, isSecretName, jwtRole;
import 'rule.dart';

/// Language-independent lexical checks. These are source findings, not claims
/// that a runtime protection executed or that data flow was fully analyzed.
class NativeSourceRule extends Rule {
  const NativeSourceRule({this.logging = false});
  final bool logging;
  @override
  RuleMeta get meta => RuleMeta(
        id: logging ? 'AEG-N09' : 'AEG-N08',
        title: logging
            ? const Bilingual(En.nativeLoggingTitle, Ar.nativeLoggingTitle)
            : const Bilingual(En.nativeSecretsTitle, Ar.nativeSecretsTitle),
        passTitleText: logging
            ? const Bilingual(En.nativeLoggingPass, Ar.nativeLoggingPass)
            : const Bilingual(En.nativeSecretsPass, Ar.nativeSecretsPass),
        description: const Bilingual(
            En.nativeSourceDescription, Ar.nativeSourceDescription),
        fix: logging
            ? const Bilingual(En.nativeLoggingFix, Ar.nativeLoggingFix)
            : const Bilingual(En.nativeSecretsFix, Ar.nativeSecretsFix),
        severity: Severity.high,
        masvs: [logging ? 'MASVS-STORAGE-2' : 'MASVS-STORAGE-1'],
        maswe: [logging ? 'MASWE-0005' : 'MASWE-0004'],
        profiles: {MasProfile.l1},
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final files = [...project.nativeSources, ...project.scriptSources];
    final config = logging ? const <String>[] : _configFiles(project);
    if (files.isEmpty && config.isEmpty) return RuleCheck.notApplicable();
    final out = <Finding>[
      ...(logging ? const <Finding>[] : _configSecrets(project, config))
    ];
    var limited = false;
    for (final file in files) {
      final script = scriptExtensions.contains(p.extension(file.path))
          ? scanScript(file.text)
          : null;
      limited |= script?.limited ?? false;
      final native = script == null ? scanNative(file.text) : null;
      final scan = script == null
          ? native!
          : (
              comments: script.comments,
              code: script.code,
              literals: script.literals
            );
      if (!logging) {
        for (final literal in scan.literals) {
          final value = literal.value;
          String? kind;
          Severity? severity;
          for (final pattern in knownSecretPatterns) {
            final match = pattern.regExp.firstMatch(value);
            if (match != null &&
                (pattern.name != 'Private key' ||
                    pemBodyFollows(value, match.end))) {
              kind = pattern.name;
              severity = pattern.severity;
              break;
            }
          }
          if (kind == null && jwtRole(value) != null) kind = 'JWT';
          if (kind == null) {
            final prefix = scan.comments.substring(
                (literal.start - 512).clamp(0, literal.start), literal.start);
            final name = RegExp(
                    r'\b([A-Za-z_]\w*)\s*(?::\s*[\w?.<>]+)?\s*(?:=|:)\s*@?\s*$')
                .firstMatch(prefix)
                ?.group(1);
            if (name != null &&
                isSecretName(name) &&
                value.length >= 8 &&
                !RegExp(r'your|example|placeholder|changeme|dummy|sample|test|\$|\\\(|[\s<>]',
                        caseSensitive: false)
                    .hasMatch(value) &&
                shannonEntropy(value) >= 3.0 &&
                RegExp(r'[0-9!@#%^&*+=]').hasMatch(value)) {
              kind = name;
            }
          }
          if (kind != null) {
            out.add(inFile(file.path, lineAt(file.text, literal.start),
                En.nativeSecretFound(kind: kind),
                messageAr: Ar.nativeSecretFound(kind: kind),
                snippet: '[redacted]',
                severity: severity));
          }
        }
      } else {
        final calls = RegExp(
            r'\b(?:Log\.[dviwe]|NSLog|os_log|println|print|console\.(?:log|debug|info|warn|error)|logger\.(?:debug|info|warning|error))\s*\(');
        for (final match in calls.allMatches(scan.code)) {
          var depth = 1, end = match.end;
          while (
              end < scan.code.length && depth > 0 && end - match.end < 2000) {
            if (scan.code[end] == '(') depth++;
            if (scan.code[end] == ')') depth--;
            end++;
          }
          if (depth != 0) continue;
          final names = RegExp(r'\b[A-Za-z_]\w*\b')
              .allMatches(scan.code.substring(match.end, end))
              .map((m) => m[0]!)
              .toSet();
          for (final literal in scan.literals
              .where((s) => s.start >= match.end && s.end <= end)) {
            names.addAll(RegExp(r'\$\{?([A-Za-z_]\w*)|\\\(([A-Za-z_]\w*)')
                .allMatches(literal.value)
                .map((m) => m[1] ?? m[2]!));
          }
          final sensitive = names
              .where(isSecretName)
              .where((n) => !_usedAsFlag(scan.code, n))
              .toList();
          if (sensitive.isNotEmpty) {
            out.add(inFile(file.path, lineAt(file.text, match.start),
                En.nativeLogFound(names: sensitive.join(', ')),
                messageAr: Ar.nativeLogFound(names: sensitive.join(', '))));
          }
        }
      }
    }
    if (limited) {
      return RuleCheck.incompleteLocalized(
          En.scriptScopeLimited, Ar.scriptScopeLimited, out);
    }
    return RuleCheck(out);
  }
}

/// App configuration files that ship inside the app and can hold keys:
/// Android manifests and string resources, iOS `Info.plist`. Firebase's own
/// config files (`google-services.json`, `GoogleService-Info.plist`) are
/// public by design and left out, like `firebase_options.dart` in AEG-D01;
/// debug and test source sets and build output too.
List<String> _configFiles(Project project) => project.findFiles(
    '',
    (rel) =>
        RegExp(r'(?:^|/)(?:AndroidManifest\.xml|Info\.plist)$|/res/values[^/]*/[^/]+\.xml$')
            .hasMatch(rel) &&
        !RegExp(r'(?:^|/)(?:build|Pods|\.dart_tool|node_modules|\.gradle|DerivedData)/|/src/(?:debug|test|androidTest)/')
            .hasMatch(rel) &&
        !project.config.isExcluded(rel));

/// Known key formats in [files] (values redacted).
List<Finding> _configSecrets(Project project, List<String> files) {
  final out = <Finding>[];
  for (final rel in files) {
    String text;
    try {
      text = File(project.abs(rel)).readAsStringSync();
    } on FileSystemException {
      continue;
    } on FormatException {
      continue; // A binary plist.
    }
    // Comments out, line numbers kept.
    final code = text.replaceAllMapped(RegExp(r'<!--[\s\S]*?-->'),
        (m) => '\n' * '\n'.allMatches(m[0]!).length);
    for (final pattern in knownSecretPatterns) {
      if (pattern.name == 'Private key') continue;
      for (final m in pattern.regExp.allMatches(code)) {
        out.add(Finding(
            ruleId: 'AEG-N08',
            message: En.nativeSecretFound(kind: pattern.name),
            messageAr: Ar.nativeSecretFound(kind: pattern.name),
            file: rel,
            line: lineAt(code, m.start),
            snippet: '[redacted]',
            severity: pattern.severity));
      }
    }
  }
  return out;
}

/// Whether [code] uses [name] as a yes/no flag (`pin ? 'pin' : 'save'`,
/// `if (!pin)`, `pin: boolean`): then it holds no secret.
bool _usedAsFlag(String code, String name) {
  final n = RegExp.escape(name);
  return RegExp('\\b$n\\s*\\?(?![.?\\[])|!$n\\b|\\bif\\s*\\(\\s*!?$n\\s*\\)|'
          '\\b$n\\s*\\??:\\s*(?:boolean|Bool|Boolean|bool)\\b|\\b$n\\s*(?:&&|\\|\\|)')
      .hasMatch(code);
}
