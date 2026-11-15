/// Security decisions made only inside `assert`, which release builds drop.
library;

import '../dart_scanner.dart';
import '../l10n/messages.g.dart';
import '../model.dart';
import '../project.dart';
import 'rule.dart';

const _all = {MasProfile.l1, MasProfile.l2, MasProfile.r};

/// Names that decide access or integrity: `isAuthenticated`, `hasPermission`,
/// `verifySignature`, `isRooted`, `checkPin`...
final _securityName =
    RegExp(r'^(?:is(?:Authenticated|Authorized|LoggedIn|SignedIn|Admin|Rooted|'
        r'Jailbroken|Secure\w*|Verified|Trusted|Tampered|Emulator|Debugged)|'
        r'has(?:Permission|Access|Role|ValidSession)\w*|'
        r'verify\w*|validate\w*(?:Signature|Token|Certificate|Pin|Password)|'
        r'check(?:Pin|Password|Signature|Certificate|Permission|Integrity|Root|'
        r'Jailbreak)\w*|can(?:Access|Edit|Delete|View|Transfer|Pay)\w*)$');

class AssertOnlyCheckRule extends Rule {
  const AssertOnlyCheckRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-D14',
        title: Bilingual(En.assertCheckTitle, Ar.assertCheckTitle),
        passTitleText: Bilingual(En.assertCheckPass, Ar.assertCheckPass),
        description:
            Bilingual(En.assertCheckDescription, Ar.assertCheckDescription),
        fix: Bilingual(En.assertCheckFix, Ar.assertCheckFix),
        severity: Severity.medium,
        masvs: ['MASVS-CODE-4'],
        cwe: 'CWE-693',
        profiles: _all,
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final out = <Finding>[];
    for (final f in project.dartFiles) {
      final asserts = f.calls({'assert'});
      if (asserts.isEmpty) continue;
      bool insideAssert(int i) => asserts.any((a) => i > a.open && i < a.close);
      for (final a in asserts) {
        final args = f.args(a.open);
        if (args.isEmpty) continue;
        final condition = args.first;
        for (var i = condition.start; i <= condition.end; i++) {
          final t = f.tokens[i];
          if (!t.isIdent || !_securityName.hasMatch(t.text)) continue;
          if (_usedOutside(f, t.text, insideAssert)) break;
          out.add(at(f, i, En.assertCheck(check: t.text),
              messageAr: Ar.assertCheck(check: t.text)));
          break;
        }
      }
    }
    return RuleCheck(out);
  }

  /// [name] is also used in an expression outside every assert of [f]
  /// (not only declared there).
  static bool _usedOutside(
      DartFile f, String name, bool Function(int) insideAssert) {
    for (var i = 0; i < f.tokens.length; i++) {
      final t = f.tokens[i];
      if (!t.isIdent || t.text != name || insideAssert(i)) continue;
      final prev = i > 0 ? f.tokens[i - 1] : null;
      final declaration = prev != null &&
          (prev.isIdent || prev.isPunct('>') || prev.isPunct('?')) &&
          !const {
            'return',
            'await',
            'else',
            'yield',
            'throw',
            'case',
            'in',
            'is'
          }.contains(prev.text);
      if (!declaration) return true;
    }
    return false;
  }
}

const assertRules = <Rule>[AssertOnlyCheckRule()];
