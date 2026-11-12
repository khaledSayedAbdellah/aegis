/// Rules that analyze Dart source code.
library;

import '../l10n/messages.g.dart';

import 'dart:convert';

import '../dart_scanner.dart';
import '../model.dart';
import '../project.dart';
import '../util.dart';
import 'rule.dart';

const _all = {MasProfile.l1, MasProfile.l2, MasProfile.r};

/// Names that usually hold secrets or sensitive values.
final sensitiveName = RegExp(
    r'(secret|token|api_?key|apikey|passw(or)?d|passwd|pwd|private_?key|client_?secret|access_?key|credential|auth_?token|auth_?key|auth_?code|auth_?header|authorization|bearer|jwt|session|otp|pin_?code|\bpin\b|cvv|card_?number|creditcard|iban|ssn|national_?id)',
    caseSensitive: false);

/// Suffixes of names that mention a sensitive word but hold something else
/// (`tokenUrl`, `passwordHint`, `authService`, `tokenExpiry`...).
final _notSecretSuffix = RegExp(
    r'(url|uri|endpoint|path|route|label|hint|text|title|message|msg|error|type|field|param|placeholder|prefix|regex|pattern|format|name|service|repository|repo|provider|bloc|cubit|controller|manager|state|status|event|mode|enabled|required|button|screen|page|widget|dialog|view|model|response|request|result|callback|handler|listener|interceptor|client|api|expiry|expires|expiration|expiresat|timestamp|time|date|count|length|validator|visible|visibility|focus|node|icon|color|style|hash|hashes|digest|sha1|sha256|sha512|checksum|fingerprint)$');

/// Stems that make a trailing `key` a real secret (`apiKey`, `secretKey`),
/// as opposed to a storage key name (`tokenKey`, `passwordKey`).
final _secretKeyStem = RegExp(
    r'(api|secret|private|access|encryption|signing|client|aes|hmac|master|license|app|sdk|server|public)$');

/// Whether an identifier or map key name likely holds a secret value.
bool isSecretName(String rawName) {
  if (!sensitiveName.hasMatch(rawName)) return false;
  final name = rawName.split('.').last;
  if (RegExp(r'^_?(is|has|should|can|did|will|show|on)[A-Z_]').hasMatch(name)) {
    return false;
  }
  final lower = name.toLowerCase().replaceAll(RegExp(r'[_\-]'), '');
  if (_notSecretSuffix.hasMatch(lower)) return false;
  if (lower.endsWith('key') && lower.length > 3) {
    final stem = lower.substring(0, lower.length - 3);
    return _secretKeyStem.hasMatch(stem);
  }
  return sensitiveName.hasMatch(name);
}

bool _looksLikePlaceholder(String v) {
  final l = v.toLowerCase();
  return l.contains('your') ||
      l.contains('xxx') ||
      l.contains('example') ||
      l.contains('todo') ||
      l.contains('changeme') ||
      l.contains('replace') ||
      l.contains('placeholder') ||
      l.contains('<') ||
      l.contains('test') ||
      l.contains('dummy') ||
      l.contains('sample') ||
      RegExp(r'^(.)\1+$').hasMatch(v) ||
      RegExp(r'^[*•.\-_ ]+$').hasMatch(v);
}

bool _isWordLike(String v) =>
    RegExp(r'^[A-Za-z]+([_\-. ][A-Za-z]+)*$').hasMatch(v) ||
    RegExp(r'^[a-z][a-zA-Z0-9]*$').hasMatch(v) && !RegExp(r'\d').hasMatch(v);

class SecretPattern {
  const SecretPattern(this.name, this.re, this.severity);
  final String name;
  final String re;
  final Severity severity;
}

final _base64Body = RegExp(r'^[\s\\n]*[A-Za-z0-9+/]{40,}');

/// Whether a PEM private-key header at [headerEnd] in [text] is followed by
/// key data. A header on its own is just a constant inside a PEM parser
/// (pointycastle, basic_utils...), not a leaked key.
bool pemBodyFollows(String text, int headerEnd, {String? next}) {
  if (_base64Body.hasMatch(text.substring(headerEnd))) return true;
  return next != null && _base64Body.hasMatch(next);
}

/// Secret formats that are recognizable on their own.
const knownSecretPatterns = [
  SecretPattern(
      'AWS access key', r'\b(AKIA|ASIA)[0-9A-Z]{16}\b', Severity.critical),
  SecretPattern('Stripe live secret key', r'\b(sk|rk)_live_[0-9a-zA-Z]{20,}',
      Severity.critical),
  SecretPattern(
      'GitHub token',
      r'\b(ghp|gho|ghs|ghu)_[A-Za-z0-9]{36}\b|github_pat_[A-Za-z0-9_]{50,}',
      Severity.critical),
  SecretPattern(
      'Slack token', r'\bxox[baprs]-[A-Za-z0-9-]{10,}', Severity.critical),
  SecretPattern(
      'Anthropic API key', r'\bsk-ant-[A-Za-z0-9_\-]{20,}', Severity.critical),
  SecretPattern(
      'OpenAI API key', r'\bsk-(proj-)?[A-Za-z0-9_\-]{32,}', Severity.critical),
  SecretPattern('SendGrid API key',
      r'\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{30,}', Severity.critical),
  SecretPattern('Firebase Cloud Messaging server key',
      r'\bAAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{100,}', Severity.critical),
  SecretPattern('Mapbox secret token', r'\bsk\.eyJ[A-Za-z0-9_\-]{20,}',
      Severity.critical),
  SecretPattern('Private key', r'-----BEGIN ([A-Z]+ )?PRIVATE KEY-----',
      Severity.critical),
  SecretPattern(
      'Google API key', r'\bAIza[0-9A-Za-z_\-]{35}\b', Severity.medium),
];

class HardcodedSecretRule extends Rule {
  const HardcodedSecretRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-D01',
        title: Bilingual(En.dartRulesHardcodedSecretInDartCode,
            Ar.dartRulesHardcodedSecretInDartCode),
        description: Bilingual(
            En.dartRulesStringsAreStoredInPlainTextInsideLibappSo,
            Ar.dartRulesStringsAreStoredInPlainTextInsideLibappSo),
        fix: Bilingual(En.dartRulesMoveSecretsToYourBackendKeysThatMust,
            Ar.dartRulesMoveSecretsToYourBackendKeysThatMust),
        severity: Severity.high,
        masvs: ['MASVS-STORAGE-1'],
        maswe: ['MASWE-0004'],
        cwe: 'CWE-798',
        profiles: _all,
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final out = <Finding>[];
    final known = knownSecretPatterns.map((p) => (p, RegExp(p.re))).toList();
    for (final f in project.dartFiles) {
      final isFirebaseOptions = f.path.endsWith('firebase_options.dart');
      for (final i in f.stringIndexes()) {
        if (f.isDirectiveString(i)) continue;
        final v = f.tokens[i].value ?? '';
        if (v.length < 8) continue;

        var matchedKnown = false;
        for (final (pat, re) in known) {
          final m = re.firstMatch(v);
          if (m == null) continue;
          matchedKnown = true;
          if (pat.name == 'Google API key' && isFirebaseOptions) break;
          if (pat.name == 'Private key') {
            final next = f.at(i + 1);
            if (!pemBodyFollows(v, m.end,
                next: next != null && next.isString ? next.value : null)) {
              break;
            }
          }
          out.add(at(f, i, En.dartRulesFound(value1: pat.name),
              messageAr: Ar.dartRulesFound(value1: pat.name),
              snippet: redact(m.group(0)!)));
          break;
        }
        if (matchedKnown) continue;

        final jwt = jwtRole(v);
        if (jwt != null) {
          out.add(at(
              f,
              i,
              jwt == 'service_role'
                  ? 'Supabase service_role JWT found. It bypasses Row Level Security.'
                  : 'Hardcoded JWT found.',
              messageAr: jwt == 'service_role'
                  ? 'لقيت JWT من نوع service_role بتاع Supabase، وده بيتخطى Row Level Security.'
                  : 'لقيت JWT مكتوب في الكود.',
              snippet: redact(v)));
          continue;
        }

        final name = f.contextName(i);
        if (name == null || !isSecretName(name)) continue;
        if (f.tokens[i].interpolated) continue;
        if (v.contains(' ') || (v.contains('/') && !v.contains('+'))) continue;
        if (_looksLikePlaceholder(v) || _isWordLike(v)) continue;
        if (shannonEntropy(v) < 3.0) continue;
        out.add(at(f, i, En.dartRulesPossibleSecretAssignedTo(name: name),
            messageAr: Ar.dartRulesPossibleSecretAssignedTo(name: name),
            snippet: '$name = ${redact(v)}'));
      }
    }
    return RuleCheck(out);
  }
}

/// Returns the `role` claim of a JWT, `''` when it is a JWT without a
/// role, or null when [v] is not a JWT.
String? jwtRole(String v) {
  final m = RegExp(
          r'\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}')
      .firstMatch(v);
  if (m == null) return null;
  try {
    var payload = m.group(0)!.split('.')[1];
    payload = payload.padRight((payload.length + 3) ~/ 4 * 4, '=');
    final json = jsonDecode(utf8.decode(base64Url.decode(payload)));
    if (json is Map && json['role'] != null) return json['role'].toString();
  } catch (_) {
    // Not decodable: still a JWT-shaped string.
  }
  return '';
}

final _safeHttpHosts = RegExp(
    r'^http://(localhost|127\.|0\.0\.0\.0|10\.0\.2\.2|\[::1\]|example\.(com|org|net)|schemas\.|www\.w3\.org|xmlns\.|ns\.adobe\.com|www\.apache\.org|purl\.org|json-schema\.org)');

class CleartextUrlRule extends Rule {
  const CleartextUrlRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-D02',
        title: Bilingual(En.dartRulesCleartextHttpUrlInCode,
            Ar.dartRulesCleartextHttpUrlInCode),
        description: Bilingual(En.dartRulesRequestsToHttpUrlsCanBeReadAnd,
            Ar.dartRulesRequestsToHttpUrlsCanBeReadAnd),
        fix: Bilingual(En.dartRulesUseHttpsForEveryEndpoint,
            Ar.dartRulesUseHttpsForEveryEndpoint),
        severity: Severity.medium,
        l2Severity: Severity.high,
        masvs: ['MASVS-NETWORK-1'],
        maswe: ['MASWE-0026'],
        cwe: 'CWE-319',
        profiles: _all,
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final out = <Finding>[];
    for (final f in project.dartFiles) {
      for (final i in f.stringIndexes()) {
        final v = f.tokens[i].value ?? '';
        if (!v.startsWith('http://')) continue;
        // A bare scheme ('http://') is a prefix check, not a URL.
        if (v.length == 'http://'.length) continue;
        if (_safeHttpHosts.hasMatch(v)) continue;
        out.add(at(f, i, En.dartRulesCleartextUrl(value1: shorten(v, 80)),
            messageAr: Ar.dartRulesCleartextUrl(value1: shorten(v, 80))));
      }
    }
    return RuleCheck(out);
  }
}

class TlsBypassRule extends Rule {
  const TlsBypassRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-D03',
        title: Bilingual(En.dartRulesTlsCertificateValidationDisabled,
            Ar.dartRulesTlsCertificateValidationDisabled),
        description: Bilingual(
            En.dartRulesACertificateCallbackThatAlwaysReturnsTrueAccepts,
            Ar.dartRulesACertificateCallbackThatAlwaysReturnsTrueAccepts),
        fix: Bilingual(En.dartRulesRemoveTheCallbackForSelfSignedDevServersUse,
            Ar.dartRulesRemoveTheCallbackForSelfSignedDevServersUse),
        severity: Severity.critical,
        masvs: ['MASVS-NETWORK-1'],
        maswe: ['MASWE-0027'],
        cwe: 'CWE-295',
        profiles: _all,
      );

  static const _names = {
    'badCertificateCallback',
    'onBadCertificate',
    'validateCertificate'
  };

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final out = <Finding>[];
    for (final f in project.dartFiles) {
      for (var i = 0; i + 2 < f.tokens.length; i++) {
        final t = f.tokens[i];
        if (!t.isIdent || !_names.contains(t.text)) continue;
        final op = f.tokens[i + 1];
        if (!(op.isPunct('=') || op.isPunct(':'))) continue;
        if (alwaysReturnsTrue(f, i + 2)) {
          if (_guardedByDebug(f, i)) continue;
          out.add(at(f, i, En.dartRulesAcceptsEveryCertificate(value1: t.text),
              messageAr: Ar.dartRulesAcceptsEveryCertificate(value1: t.text)));
        }
      }
    }
    return RuleCheck(out);
  }
}

/// Whether the closure starting at token [start] always returns `true`.
bool alwaysReturnsTrue(DartFile f, int start) {
  final open = f.at(start);
  if (open == null || !open.isPunct('(')) return false;
  final close = f.matchOf(start);
  if (close == null) return false;
  // Parenthesized closure: `= ((cert, host, port) => true)`.
  final inner = f.at(start + 1);
  if (inner != null && inner.isPunct('(')) {
    final innerClose = f.matchOf(start + 1);
    final after = innerClose == null ? null : f.at(innerClose + 1);
    if (after != null && (after.isPunct('=>') || after.isPunct('{'))) {
      return alwaysReturnsTrue(f, start + 1);
    }
  }
  final next = f.at(close + 1);
  if (next == null) return false;
  if (next.isPunct('=>')) {
    final v = f.at(close + 2);
    final after = f.at(close + 3);
    return v != null &&
        v.isIdent &&
        v.text == 'true' &&
        (after == null ||
            after.isPunct(';') ||
            after.isPunct(',') ||
            after.isPunct(')'));
  }
  if (next.isPunct('{')) {
    final end = f.matchOf(close + 1);
    if (end == null) return false;
    final body = f.text(close + 1, end);
    final compact = body.replaceAll(RegExp(r'\s+'), ' ');
    final returnsTrue = RegExp(r'return true\s*;').hasMatch(compact);
    final returnsOther = RegExp(r'return (?!true\s*;)').hasMatch(compact);
    final checksSomething = RegExp(
            r'(sha|fingerprint|pem|der|==|contains|compare|pin|subject|issuer)',
            caseSensitive: false)
        .hasMatch(compact);
    return returnsTrue && !returnsOther && !checksSomething;
  }
  return false;
}

/// Conditions that keep debug-only code out of production builds:
/// `kDebugMode`, or flags such as `config.enableLogging` / `isDebug`.
final _debugFlag = RegExp(
    r'(kDebugMode|kProfileMode|[dD]ebugMode|isDebug|enableLog|[lL]ogging[A-Z]?\w*Enabled|[lL]ogEnabled|verbose|isDev\b)');

/// Whether the code at token [index] sits under a debug-only condition in
/// the 6 lines above it (`if (kDebugMode)`, `if (config.enableLogging)`,
/// `assert(...)`, `kDebugMode ? ... : ...`).
bool _guardedByDebug(DartFile f, int index) {
  final line = f.lineOfToken(index);
  for (var l = line; l >= 1 && l >= line - 6; l--) {
    final t = f.lineText(l);
    if (t.contains('kDebugMode') && !t.contains('!kDebugMode')) return true;
    if (t.contains('assert(')) return true;
    if (RegExp(r'\bif\s*\(').hasMatch(t) && _debugFlag.hasMatch(t)) return true;
  }
  return false;
}

class InsecureStorageRule extends Rule {
  const InsecureStorageRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-D04',
        title: Bilingual(En.dartRulesSensitiveDataInPlainStorage,
            Ar.dartRulesSensitiveDataInPlainStorage),
        description: Bilingual(
            En.dartRulesSharedpreferencesGetstorageAndPlainHiveBoxesAreUnencrypted,
            Ar.dartRulesSharedpreferencesGetstorageAndPlainHiveBoxesAreUnencrypted),
        fix: Bilingual(
            En.dartRulesStoreTokensPasswordsAndPinsInFlutterSecureStorageKeychain,
            Ar.dartRulesStoreTokensPasswordsAndPinsInFlutterSecureStorageKeychain),
        severity: Severity.medium,
        l2Severity: Severity.high,
        masvs: ['MASVS-STORAGE-1'],
        maswe: ['MASWE-0001'],
        cwe: 'CWE-312',
        profiles: _all,
      );

  // setBool is left out on purpose: a true/false flag such as
  // 'remember_session' is not a secret, whatever its key is called.
  static const _writers = {
    'setString', 'setStringList', 'setInt', 'setDouble', //
    'write', 'put', 'putAll', 'add',
  };

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final out = <Finding>[];
    for (final f in project.dartFiles) {
      for (final c in f.calls(_writers)) {
        final recv = c.receivers.join('.').toLowerCase();
        if (recv.isEmpty || recv.contains('secure')) continue;
        final isPlain = recv.contains('pref') ||
            recv.contains('getstorage') ||
            recv.contains('box') ||
            recv.contains('hive') ||
            (c.name.startsWith('set') && recv.contains('storage'));
        if (!isPlain) continue;
        if ((c.name == 'add' || c.name == 'putAll') && !recv.contains('box')) {
          continue;
        }
        final args = f.args(c.open);
        if (args.isEmpty) continue;
        final keyArg = args.first;
        String? keyName;
        final kt = f.tokens[keyArg.start];
        if (keyArg.start == keyArg.end && kt.isString) {
          keyName = kt.value;
        } else if (keyArg.start == keyArg.end && kt.isIdent) {
          keyName = kt.text;
        } else {
          keyName = f.text(keyArg.start, keyArg.end);
        }
        var valueName = '';
        if (args.length > 1) valueName = f.text(args[1].start, args[1].end);
        if (keyName == null) continue;
        final hit = isSecretName(keyName) ||
            (valueName.isNotEmpty && isSecretName(valueName));
        if (!hit) continue;
        out.add(at(f, c.nameIndex,
            'Sensitive value "${shorten(keyName, 40)}" written with ${c.receivers.isEmpty ? '' : '${c.receivers.first}.'}${c.name}().',
            messageAr:
                'قيمة حساسة "${shorten(keyName, 40)}" بتتخزن بـ ${c.name}() من غير تشفير.'));
      }
    }
    return RuleCheck(out);
  }
}

class WeakCryptoRule extends Rule {
  const WeakCryptoRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-D05',
        title: Bilingual(
            En.dartRulesWeakCryptography, Ar.dartRulesWeakCryptography),
        description: Bilingual(En.dartRulesMd5Sha1AreBrokenForSecurityUseAndEcb,
            Ar.dartRulesMd5Sha1AreBrokenForSecurityUseAndEcb),
        fix: Bilingual(En.dartRulesUseSha256OrBetterForHashingArgon2Pbkdf2For,
            Ar.dartRulesUseSha256OrBetterForHashingArgon2Pbkdf2For),
        severity: Severity.medium,
        masvs: ['MASVS-CRYPTO-1'],
        maswe: ['MASWE-0007', 'MASWE-0008'],
        cwe: 'CWE-327',
        profiles: _all,
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final out = <Finding>[];
    for (final f in project.dartFiles) {
      for (final c in f.calls({'convert'})) {
        final r = c.receiver;
        if (r == 'md5' || r == 'sha1') {
          out.add(at(f, c.nameIndex, En.dartRulesIsUsedForHashing(r: r),
              messageAr: Ar.dartRulesIsUsedForHashing(r: r)));
        }
      }
      for (var i = 0; i + 2 < f.tokens.length; i++) {
        final t = f.tokens[i];
        if (t.isIdent &&
            t.text == 'AESMode' &&
            f.tokens[i + 1].isPunct('.') &&
            f.tokens[i + 2].text == 'ecb') {
          out.add(at(f, i, En.dartRulesAesInEcbMode,
              messageAr: Ar.dartRulesAesInEcbMode));
        }
        if (t.isIdent &&
            (t.text == 'MD5Digest' ||
                t.text == 'SHA1Digest' ||
                t.text == 'DESedeEngine' ||
                t.text == 'DESEngine' ||
                t.text == 'RC4Engine')) {
          out.add(at(f, i, En.dartRulesIsAWeakAlgorithm(value1: t.text),
              messageAr: Ar.dartRulesIsAWeakAlgorithm(value1: t.text)));
        }
        if (t.isString) {
          final v = (t.value ?? '').toUpperCase();
          if (RegExp(r'^(AES/ECB|DES/|DESEDE/|RC4(/|$)|AES/CBC/NOPADDING)')
              .hasMatch(v)) {
            out.add(at(
                f, i, En.dartRulesWeakCipherTransformation(value1: t.value),
                messageAr:
                    Ar.dartRulesWeakCipherTransformation(value1: t.value)));
          }
        }
      }
    }
    return RuleCheck(out);
  }
}

class StaticKeyRule extends Rule {
  const StaticKeyRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-D06',
        title: Bilingual(En.dartRulesHardcodedEncryptionKeyOrIv,
            Ar.dartRulesHardcodedEncryptionKeyOrIv),
        description: Bilingual(En.dartRulesAKeyOrIvWrittenInTheCode,
            Ar.dartRulesAKeyOrIvWrittenInTheCode),
        fix: Bilingual(
            En.dartRulesGenerateKeysAtRuntimeKeyFromsecurerandomRandomSecureKeep,
            Ar.dartRulesGenerateKeysAtRuntimeKeyFromsecurerandomRandomSecureKeep),
        severity: Severity.high,
        masvs: ['MASVS-CRYPTO-2'],
        maswe: ['MASWE-0013', 'MASWE-0014'],
        cwe: 'CWE-321',
        profiles: _all,
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final out = <Finding>[];
    for (final f in project.dartFiles) {
      for (final c in f.calls({'fromUtf8', 'fromBase64', 'fromBase16'})) {
        final r = c.receiver;
        if (r != 'Key' && r != 'IV') continue;
        final args = f.args(c.open);
        if (args.isEmpty) continue;
        final a = args.first;
        if (a.start == a.end && f.tokens[a.start].isString) {
          out.add(at(f, c.nameIndex,
              En.dartRulesIsCalledWithALiteral(r: r, value2: c.name),
              messageAr: Ar.dartRulesIsCalledWithALiteral(r: r, value2: c.name),
              snippet:
                  '$r.${c.name}(${redact(f.tokens[a.start].value ?? '')})'));
        }
      }
      for (final c in f.calls({'IV'})) {
        final args = f.args(c.open);
        if (args.isEmpty) continue;
        final txt =
            f.text(args.first.start, args.first.end).replaceAll(' ', '');
        if (RegExp(r'^Uint8List\(\d+\)$').hasMatch(txt)) {
          out.add(at(f, c.nameIndex, En.dartRulesIvMadeOfZeroBytes(txt: txt),
              messageAr: Ar.dartRulesIvMadeOfZeroBytes(txt: txt)));
        }
      }
    }
    return RuleCheck(out);
  }
}

class InsecureRandomRule extends Rule {
  const InsecureRandomRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-D07',
        title: Bilingual(En.dartRulesPredictableRandomForSecurityValues,
            Ar.dartRulesPredictableRandomForSecurityValues),
        description: Bilingual(
            En.dartRulesRandomIsNotCryptographicallySecureTokensOtpsNonces,
            Ar.dartRulesRandomIsNotCryptographicallySecureTokensOtpsNonces),
        fix: Bilingual(En.dartRulesUseRandomSecureForAnythingSecurityRelated,
            Ar.dartRulesUseRandomSecureForAnythingSecurityRelated),
        severity: Severity.medium,
        masvs: ['MASVS-CRYPTO-1'],
        maswe: ['MASWE-0012'],
        cwe: 'CWE-338',
        profiles: _all,
      );

  static final _securityContext = RegExp(
      r'(token|otp|nonce|salt|\biv\b|key|passw|secret|pin|session|uuid|verifier|challenge)',
      caseSensitive: false);

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final out = <Finding>[];
    for (final f in project.dartFiles) {
      for (final c in f.calls({'Random'})) {
        if (c.receivers.isNotEmpty && c.receiver != 'math') continue;
        final line = f.lineOfToken(c.nameIndex);
        final window = [
          for (var l = line - 3; l <= line + 3; l++) f.lineText(l)
        ].join(' ');
        if (_securityContext.hasMatch(window)) {
          out.add(at(
              f, c.nameIndex, En.dartRulesRandomUsedNearSecuritySensitiveCode,
              messageAr: Ar.dartRulesRandomUsedNearSecuritySensitiveCode));
        }
      }
    }
    return RuleCheck(out);
  }
}

class SensitiveLoggingRule extends Rule {
  const SensitiveLoggingRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-D08',
        title: Bilingual(En.dartRulesSensitiveDataWrittenToLogs,
            Ar.dartRulesSensitiveDataWrittenToLogs),
        description: Bilingual(
            En.dartRulesLogsSurviveInLogcatCrashReportsAndDevice,
            Ar.dartRulesLogsSurviveInLogcatCrashReportsAndDevice),
        fix: Bilingual(En.dartRulesNeverLogSecretsWrapDebugLoggingInIf,
            Ar.dartRulesNeverLogSecretsWrapDebugLoggingInIf),
        severity: Severity.medium,
        masvs: ['MASVS-STORAGE-2'],
        maswe: ['MASWE-0005'],
        cwe: 'CWE-532',
        profiles: _all,
      );

  static const _loggers = {
    'print',
    'debugPrint',
    'log',
    'd',
    'i',
    'w',
    'e',
    'v',
    't',
    'info',
    'debug',
    'warning',
    'severe',
    'fine'
  };
  static final _loggerReceivers = RegExp(
      r'^(_?log(ger)?|developer|talker|_?logService)$',
      caseSensitive: false);

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final out = <Finding>[];
    for (final f in project.dartFiles) {
      for (final c in f.calls(_loggers)) {
        final r = c.receiver;
        final isBare =
            r == null && const {'print', 'debugPrint', 'log'}.contains(c.name);
        final isLogger = r != null && _loggerReceivers.hasMatch(r);
        if (!isBare && !isLogger) continue;
        final idents = <String>[];
        for (var k = c.open + 1; k < c.close; k++) {
          final t = f.tokens[k];
          if (t.isIdent) idents.add(t.text);
          if (t.isString) {
            final v = t.value ?? '';
            final m = RegExp(r'\$\{?([A-Za-z_][A-Za-z0-9_.]*)').allMatches(v);
            for (final mm in m) {
              idents.add(mm.group(1)!);
            }
          }
        }
        final hit = idents.firstWhere(isSecretName, orElse: () => '');
        if (hit.isEmpty) continue;
        if (_guardedByDebug(f, c.nameIndex)) continue;
        out.add(at(f, c.nameIndex,
            '"$hit" is passed to ${r == null ? '' : '$r.'}${c.name}().',
            messageAr: '"$hit" بيتبعت لـ ${c.name}() وبيتكتب في الـ logs.'));
      }
      for (final c in f.calls({'LogInterceptor', 'PrettyDioLogger'})) {
        if (_guardedByDebug(f, c.nameIndex)) continue;
        final args = f.text(c.open, c.close).replaceAll(' ', '');
        if (args.contains('requestHeader:false') &&
            args.contains('responseHeader:false') &&
            c.name == 'LogInterceptor') {
          continue;
        }
        out.add(at(f, c.nameIndex,
            En.dartRulesIsAddedWithoutAKdebugmodeGuardAnd(value1: c.name),
            messageAr:
                Ar.dartRulesIsAddedWithoutAKdebugmodeGuardAnd(value1: c.name)));
      }
    }
    return RuleCheck(out);
  }
}

/// File names that usually hold secrets.
final riskyAssetFile = RegExp(
    r'(^|/)(\.env(\.[a-z]+)?|.*service[-_]?account.*\.json|.*credentials.*\.json|.*\.(pem|p12|pfx|key|jks|keystore))$',
    caseSensitive: false);

/// Risky asset files declared in pubspec.yaml, as (path, folder) where
/// folder is the asset folder that pulled the file in, or null when the file
/// is listed directly.
List<(String, String?)> riskyAssetPaths(Project project) {
  final out = <(String, String?)>[];
  for (final a in project.assets) {
    if (riskyAssetFile.hasMatch(a)) {
      out.add((a, null));
    } else if (a.endsWith('/')) {
      for (final r in project.findFiles(
          a.substring(0, a.length - 1), riskyAssetFile.hasMatch)) {
        out.add((r, a));
      }
    }
  }
  return out;
}

class BundledSecretsRule extends Rule {
  const BundledSecretsRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-D09',
        title: Bilingual(En.dartRulesSecretFileBundledAsAnAsset,
            Ar.dartRulesSecretFileBundledAsAnAsset),
        description: Bilingual(En.dartRulesAssetsArePlainFilesInsideTheApkIpaA,
            Ar.dartRulesAssetsArePlainFilesInsideTheApkIpaA),
        fix: Bilingual(En.dartRulesRemoveTheFileFromFlutterAssetsUseDartDefine,
            Ar.dartRulesRemoveTheFileFromFlutterAssetsUseDartDefine),
        severity: Severity.high,
        masvs: ['MASVS-STORAGE-1'],
        maswe: ['MASWE-0004'],
        cwe: 'CWE-540',
        profiles: _all,
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final out = <Finding>[];
    for (final (path, folder) in riskyAssetPaths(project)) {
      if (folder == null) {
        out.add(inFile(
            'pubspec.yaml', null, En.dartRulesIsBundledAsAnAsset(path: path),
            messageAr: Ar.dartRulesIsBundledAsAnAsset(path: path)));
      } else {
        out.add(inFile(path, null,
            En.dartRulesIsBundledThroughTheAsset(path: path, folder: folder),
            messageAr: Ar.dartRulesIsBundledThroughTheAsset(
                path: path, folder: folder)));
      }
    }
    return RuleCheck(out);
  }
}

class WebViewRule extends Rule {
  const WebViewRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-D10',
        title: Bilingual(En.dartRulesWebviewExposesNativeBridgeOrDebugging,
            Ar.dartRulesWebviewExposesNativeBridgeOrDebugging),
        description: Bilingual(
            En.dartRulesAJavascriptChannelWithoutNavigationRestrictionsLetsAny,
            Ar.dartRulesAJavascriptChannelWithoutNavigationRestrictionsLetsAny),
        fix: Bilingual(
            En.dartRulesRestrictNavigationWithNavigationdelegateOnnavigationrequestOrShouldoverrideurlloadingToYour,
            Ar.dartRulesRestrictNavigationWithNavigationdelegateOnnavigationrequestOrShouldoverrideurlloadingToYour),
        severity: Severity.medium,
        masvs: ['MASVS-PLATFORM-2'],
        maswe: ['MASWE-0033', 'MASWE-0035'],
        cwe: 'CWE-749',
        profiles: _all,
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final out = <Finding>[];
    for (final f in project.dartFiles) {
      final bridges = f.calls({
        'addJavaScriptChannel',
        'JavascriptChannel',
        'addJavaScriptHandler',
        'addJavascriptChannel'
      });
      if (bridges.isNotEmpty) {
        final restricted = f.source.contains('onNavigationRequest') ||
            f.source.contains('shouldOverrideUrlLoading');
        if (!restricted) {
          out.add(at(
              f,
              bridges.first.nameIndex,
              En.dartRulesJavascriptBridgeWithoutNavigationRestrictions(
                  value1: bridges.first.name),
              messageAr:
                  Ar.dartRulesJavascriptBridgeWithoutNavigationRestrictions(
                      value1: bridges.first.name)));
        }
      }
      for (var i = 0; i + 2 < f.tokens.length; i++) {
        final t = f.tokens[i];
        if (!t.isIdent) continue;
        final isFlag = t.text == 'isInspectable' ||
            t.text == 'setWebContentsDebuggingEnabled';
        if (!isFlag) continue;
        final window = f.text(i, (i + 4).clamp(0, f.tokens.length - 1).toInt());
        if (window.contains('true') && !_guardedByDebug(f, i)) {
          out.add(at(
              f, i, En.dartRulesWebviewDebuggingIsEnabled(value1: t.text),
              messageAr:
                  Ar.dartRulesWebviewDebuggingIsEnabled(value1: t.text)));
        }
      }
    }
    for (final s in project.androidNativeSources) {
      final m = RegExp(r'setWebContentsDebuggingEnabled\s*\(\s*true\s*\)')
          .firstMatch(s.text);
      if (m != null && !s.text.contains('BuildConfig.DEBUG')) {
        out.add(inFile(s.path, lineAt(s.text, m.start),
            En.dartRulesWebviewSetwebcontentsdebuggingenabledTrueInNativeCode,
            messageAr: Ar
                .dartRulesWebviewSetwebcontentsdebuggingenabledTrueInNativeCode));
      }
    }
    return RuleCheck(out);
  }
}

const dartRules = <Rule>[
  HardcodedSecretRule(),
  CleartextUrlRule(),
  TlsBypassRule(),
  InsecureStorageRule(),
  WeakCryptoRule(),
  StaticKeyRule(),
  InsecureRandomRule(),
  SensitiveLoggingRule(),
  BundledSecretsRule(),
  WebViewRule(),
];

/// Shared with other rule files.
bool guardedByDebug(DartFile f, int index) => _guardedByDebug(f, index);
