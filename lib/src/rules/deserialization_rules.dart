/// Data from outside the app turned into arbitrary objects.
library;

import '../l10n/messages.g.dart';
import '../model.dart';
import '../project.dart';
import '../security/evidence.dart';
import '../security/native_analysis.dart' show withoutComments;
import '../security/native_flow.dart';
import 'rule.dart';

/// Data that comes from outside the app: another app (Intents, links), the
/// network, or shared storage that other apps can write.
final _outside = RegExp('${nativeLinkSource.pattern}|'
    r'\b\w*(?:[cC]onnection|[sS]ocket|[rR]esponse|[cC]onn)\w*\s*[.?]+\s*(?:inputStream|getInputStream\s*\(\s*\)|body\b)|'
    r'\.openStream\s*\(|\.byteStream\s*\(|'
    r'\bgetExternal(?:Storage|Files|Cache)Dir\w*\s*\(|Environment\.getExternalStorage|'
    // Swift: URLSession's data, `Data(contentsOf: url)` of a remote URL.
    r'\bdataTask\s*\(\s*with\b[^{]*\{\s*\(?\s*(\w+)\s*,|'
    r'\bUIPasteboard\.general\.(?:data|items)\b');

/// Calls that build any class the data names. Group 1 names the call.
final _sinks = RegExp(r'\b(ObjectInputStream|XMLDecoder|fromXML|'
    r'unarchiveObject|unarchiveTopLevelObjectWithData|unarchiveObjectWithData|'
    r'unarchiveObjectWithFile)\s*\(');

/// The same APIs without a source, for the evidence list.
final _unsafeApi = RegExp(r'\bObjectInputStream\s*\(|\bXMLDecoder\s*\(|'
    r'\.fromXML\s*\(|NSKeyedUnarchiver\s*\.\s*unarchiveObject|'
    r'unarchiveTopLevelObjectWithData|unarchiveObjectWithData|unarchiveObjectWithFile|'
    r'requiresSecureCoding\s*=\s*false|requiresSecureCoding\s*:\s*NO|'
    r'setRequiresSecureCoding\s*:\s*NO');

/// The class list is restricted.
final _filtered = RegExp(
    r'ObjectInputFilter|setObjectInputFilter|override\s+fun\s+resolveClass|'
    r'protected\s+Class<\?>\s+resolveClass|allowTypes|addPermission\s*\(');

class UnsafeDeserializationRule extends Rule {
  const UnsafeDeserializationRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-C05',
        title: Bilingual(En.deserializationTitle, Ar.deserializationTitle),
        passTitleText:
            Bilingual(En.deserializationPass, Ar.deserializationPass),
        description: Bilingual(
            En.deserializationDescription, Ar.deserializationDescription),
        fix: Bilingual(En.deserializationFix, Ar.deserializationFix),
        severity: Severity.high,
        masvs: ['MASVS-CODE-4'],
        maswe: ['MASWE-0050'],
        cwe: 'CWE-502',
        profiles: {MasProfile.l1, MasProfile.l2, MasProfile.r},
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final out = <Finding>[];
    final local = <String>[];
    var seen = false;
    for (final file in [...project.nativeSources, ...project.scriptSources]) {
      final ext = file.path.split('.').last;
      final code = withoutComments(file.text);
      if (const {'js', 'jsx', 'ts', 'tsx', 'mjs', 'cjs'}.contains(ext)) {
        _script(file, code, out);
        continue;
      }
      if (!const {'kt', 'java', 'swift', 'm', 'mm'}.contains(ext)) continue;
      seen = true;
      int lineOf(int offset) =>
          '\n'.allMatches(code.substring(0, offset)).length + 1;
      // Untyped getSerializableExtra(name): Android deserializes first and
      // checks the type after.
      for (final m
          in RegExp(r'\bgetSerializableExtra\s*\(\s*("[^"]*"|\w+)\s*\)')
              .allMatches(code)) {
        out.add(inFile(
            file.path, lineOf(m.start), En.deserializationUntypedExtra,
            messageAr: Ar.deserializationUntypedExtra));
      }
      for (final m in RegExp(
              r'\b(?:enableDefaultTyping|activateDefaultTyping)\s*\(|@JsonTypeInfo\s*\(\s*use\s*=\s*JsonTypeInfo\.Id\.CLASS')
          .allMatches(code)) {
        out.add(inFile(
            file.path, lineOf(m.start), En.deserializationDefaultTyping,
            messageAr: Ar.deserializationDefaultTyping));
      }
      if (_filtered.hasMatch(code)) continue;
      final hits = nativeFlows(code, sources: _outside, sinks: _sinks);
      for (final hit in hits) {
        final value = shorten(hit.value, 40);
        out.add(inFile(file.path, hit.line,
            En.deserializationFlow(value: value, api: hit.call),
            messageAr: Ar.deserializationFlow(value: value, api: hit.call)));
      }
      final reported = {for (final h in hits) h.line};
      for (final m in _unsafeApi.allMatches(code)) {
        final line = lineOf(m.start);
        if (!reported.contains(line)) local.add('${file.path}:$line');
      }
    }
    if (local.isNotEmpty) {
      final places = local.take(6).join(', ');
      project.securityEvidence.add(SecurityEvidence(
          meta.id,
          local.first,
          Bilingual(En.deserializationLocal(places: places),
              Ar.deserializationLocal(places: places)),
          status: 'facts',
          data: {'places': local}));
    }
    if (out.isEmpty && !seen && project.scriptSources.isEmpty) {
      return RuleCheck.notApplicable();
    }
    return RuleCheck(out);
  }

  /// `node-serialize` and `funcster` run code written inside the data.
  void _script(ProjectFile file, String code, List<Finding> out) {
    if (!RegExp(
            r'''require\(\s*['"](?:node-serialize|funcster|cryo)['"]|from\s+['"](?:node-serialize|funcster|cryo)['"]''')
        .hasMatch(code)) {
      return;
    }
    for (final m
        in RegExp(r'\b(?:unserialize|deepDeserialize)\s*\(').allMatches(code)) {
      out.add(inFile(
          file.path,
          '\n'.allMatches(code.substring(0, m.start)).length + 1,
          En.deserializationNodeSerialize,
          messageAr: Ar.deserializationNodeSerialize));
    }
  }
}
