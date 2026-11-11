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
        profiles: {MasProfile.l1},
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final files = [...project.nativeSources, ...project.scriptSources];
    if (files.isEmpty) return RuleCheck.notApplicable();
    final out = <Finding>[];
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
          for (final pattern in knownSecretPatterns) {
            final match = RegExp(pattern.re).firstMatch(value);
            if (match != null &&
                (pattern.name != 'Private key' ||
                    pemBodyFollows(value, match.end))) {
              kind = pattern.name;
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
                snippet: '[redacted]'));
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
          final sensitive = names.where(isSecretName).toList();
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
