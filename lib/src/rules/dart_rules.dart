/// Rules that analyze Dart source code.
library;

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
  SecretPattern('AWS access key', r'\b(AKIA|ASIA)[0-9A-Z]{16}\b', Severity.critical),
  SecretPattern('Stripe live secret key', r'\b(sk|rk)_live_[0-9a-zA-Z]{20,}', Severity.critical),
  SecretPattern('GitHub token', r'\b(ghp|gho|ghs|ghu)_[A-Za-z0-9]{36}\b|github_pat_[A-Za-z0-9_]{50,}', Severity.critical),
  SecretPattern('Slack token', r'\bxox[baprs]-[A-Za-z0-9-]{10,}', Severity.critical),
  SecretPattern('Anthropic API key', r'\bsk-ant-[A-Za-z0-9_\-]{20,}', Severity.critical),
  SecretPattern('OpenAI API key', r'\bsk-(proj-)?[A-Za-z0-9_\-]{32,}', Severity.critical),
  SecretPattern('SendGrid API key', r'\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{30,}', Severity.critical),
  SecretPattern('Firebase Cloud Messaging server key', r'\bAAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{100,}', Severity.critical),
  SecretPattern('Mapbox secret token', r'\bsk\.eyJ[A-Za-z0-9_\-]{20,}', Severity.critical),
  SecretPattern('Private key', r'-----BEGIN ([A-Z]+ )?PRIVATE KEY-----', Severity.critical),
  SecretPattern('Google API key', r'\bAIza[0-9A-Za-z_\-]{35}\b', Severity.medium),
];

class HardcodedSecretRule extends Rule {
  const HardcodedSecretRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-D01',
        title: Bilingual('Hardcoded secret in Dart code', 'سر (secret) مكتوب في كود Dart'),
        description: Bilingual(
            'Strings are stored in plain text inside libapp.so. --obfuscate does not hide them; `strings` on the APK reveals them in seconds.',
            'الـ strings بتتخزن زي ما هي جوه libapp.so. الـ --obfuscate مش بيخفيها، وأمر strings على الـ APK بيطلعها في ثواني.'),
        fix: Bilingual(
            'Move secrets to your backend. Keys that must ship (Maps, Firebase) should be restricted by package name/SHA-1 and bundle id in their console.',
            'انقل الأسرار للـ backend. والمفاتيح اللي لازم تكون في التطبيق (Maps أو Firebase) اقفلها على الـ package name والـ SHA-1 والـ bundle id من الـ console بتاعها.'),
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
            if (!pemBodyFollows(v, m.end, next: next != null && next.isString ? next.value : null)) break;
          }
          out.add(at(f, i, '${pat.name} found.',
              messageAr: 'لقيت ${pat.name}.',
              snippet: redact(m.group(0)!)));
          break;
        }
        if (matchedKnown) continue;

        final jwt = jwtRole(v);
        if (jwt != null) {
          out.add(at(f, i,
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
        out.add(at(f, i, 'Possible secret assigned to "$name".',
            messageAr: 'غالباً ده سر متخزن في "$name".',
            snippet: '$name = ${redact(v)}'));
      }
    }
    return RuleCheck(out);
  }
}

/// Returns the `role` claim of a JWT, `''` when it is a JWT without a
/// role, or null when [v] is not a JWT.
String? jwtRole(String v) {
  final m = RegExp(r'\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}')
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
        title: Bilingual('Cleartext http:// URL in code', 'لينك http:// غير مشفر في الكود'),
        description: Bilingual(
            'Requests to http:// URLs can be read and modified by anyone on the same network.',
            'أي request لـ http:// ممكن يتقرا ويتعدل من أي حد على نفس الشبكة.'),
        fix: Bilingual('Use https:// for every endpoint.', 'استخدم https:// لكل الـ endpoints.'),
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
        out.add(at(f, i, 'Cleartext URL: ${shorten(v, 80)}',
            messageAr: 'لينك غير مشفر: ${shorten(v, 80)}'));
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
        title: Bilingual('TLS certificate validation disabled', 'التحقق من شهادة TLS مقفول'),
        description: Bilingual(
            'A certificate callback that always returns true accepts any certificate, so any proxy (Burp, mitmproxy) can read all traffic.',
            'الـ callback اللي بيرجع true دايماً بيقبل أي شهادة، يعني أي proxy (زي Burp أو mitmproxy) يقدر يقرا كل الترافيك.'),
        fix: Bilingual(
            'Remove the callback. For self-signed dev servers use a debug-only override guarded by kDebugMode, or pin the expected certificate.',
            'شيل الـ callback ده. لو عندك سيرفر تطوير بشهادة self-signed، خليه في الـ debug بس بشرط kDebugMode، أو اعمل pinning للشهادة المتوقعة.'),
        severity: Severity.critical,
        masvs: ['MASVS-NETWORK-1'],
        maswe: ['MASWE-0027'],
        cwe: 'CWE-295',
        profiles: _all,
      );

  static const _names = {'badCertificateCallback', 'onBadCertificate', 'validateCertificate'};

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
          out.add(at(f, i, '${t.text} accepts every certificate.',
              messageAr: '${t.text} بيقبل أي شهادة.'));
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
        title: Bilingual('Sensitive data in plain storage', 'بيانات حساسة متخزنة من غير تشفير'),
        description: Bilingual(
            'SharedPreferences, GetStorage and plain Hive boxes are unencrypted files. On a rooted device or through a backup they can be read directly.',
            'الـ SharedPreferences و GetStorage و Hive العادي ملفات مش متشفرة. على جهاز rooted أو من الـ backup ممكن تتقري على طول.'),
        fix: Bilingual(
            'Store tokens, passwords and PINs in flutter_secure_storage (Keychain / Keystore), or an encrypted Hive box with a key kept in secure storage.',
            'خزّن الـ tokens والباسوردات والـ PIN في flutter_secure_storage (Keychain و Keystore)، أو Hive متشفر والمفتاح بتاعه في الـ secure storage.'),
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
            messageAr: 'قيمة حساسة "${shorten(keyName, 40)}" بتتخزن بـ ${c.name}() من غير تشفير.'));
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
        title: Bilingual('Weak cryptography', 'تشفير ضعيف'),
        description: Bilingual(
            'MD5/SHA-1 are broken for security use, and ECB mode leaks patterns of the plaintext.',
            'MD5 و SHA-1 مكسورين لأي استخدام أمني، و ECB mode بيكشف أنماط البيانات الأصلية.'),
        fix: Bilingual(
            'Use SHA-256 or better for hashing, Argon2/PBKDF2 for passwords and AES-GCM for encryption.',
            'استخدم SHA-256 أو أقوى للـ hashing، و Argon2 أو PBKDF2 للباسوردات، و AES-GCM للتشفير.'),
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
          out.add(at(f, c.nameIndex, '$r is used for hashing.',
              messageAr: 'مستخدم $r في الـ hashing.'));
        }
      }
      for (var i = 0; i + 2 < f.tokens.length; i++) {
        final t = f.tokens[i];
        if (t.isIdent && t.text == 'AESMode' && f.tokens[i + 1].isPunct('.') &&
            f.tokens[i + 2].text == 'ecb') {
          out.add(at(f, i, 'AES in ECB mode.', messageAr: 'AES بنظام ECB.'));
        }
        if (t.isIdent && (t.text == 'MD5Digest' || t.text == 'SHA1Digest' || t.text == 'DESedeEngine' || t.text == 'DESEngine' || t.text == 'RC4Engine')) {
          out.add(at(f, i, '${t.text} is a weak algorithm.',
              messageAr: '${t.text} خوارزمية ضعيفة.'));
        }
        if (t.isString) {
          final v = (t.value ?? '').toUpperCase();
          if (RegExp(r'^(AES/ECB|DES/|DESEDE/|RC4(/|$)|AES/CBC/NOPADDING)').hasMatch(v)) {
            out.add(at(f, i, 'Weak cipher transformation "${t.value}".',
                messageAr: 'تشفير ضعيف "${t.value}".'));
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
        title: Bilingual('Hardcoded encryption key or IV', 'مفتاح تشفير أو IV ثابت في الكود'),
        description: Bilingual(
            'A key or IV written in the code is the same in every install and can be extracted from the binary, so the encryption protects nothing.',
            'المفتاح أو الـ IV المكتوب في الكود واحد في كل الأجهزة وممكن يتطلع من الـ binary، يعني التشفير مش بيحمي حاجة.'),
        fix: Bilingual(
            'Generate keys at runtime (Key.fromSecureRandom / Random.secure()), keep them in flutter_secure_storage, and use a fresh random IV for every encryption.',
            'اعمل المفاتيح وقت التشغيل (Key.fromSecureRandom أو Random.secure())، وخزنها في flutter_secure_storage، واستخدم IV عشوائي جديد مع كل عملية تشفير.'),
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
          out.add(at(f, c.nameIndex, '$r.${c.name}() is called with a literal.',
              messageAr: '$r.${c.name}() متنادي بقيمة ثابتة.',
              snippet: '$r.${c.name}(${redact(f.tokens[a.start].value ?? '')})'));
        }
      }
      for (final c in f.calls({'IV'})) {
        final args = f.args(c.open);
        if (args.isEmpty) continue;
        final txt = f.text(args.first.start, args.first.end).replaceAll(' ', '');
        if (RegExp(r'^Uint8List\(\d+\)$').hasMatch(txt)) {
          out.add(at(f, c.nameIndex, 'IV made of zero bytes ($txt).',
              messageAr: 'الـ IV كله أصفار ($txt).'));
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
        title: Bilingual('Predictable random for security values', 'أرقام عشوائية متوقعة لقيم أمنية'),
        description: Bilingual(
            'Random() is not cryptographically secure; tokens, OTPs, nonces or keys made with it can be predicted.',
            'Random() مش آمن للتشفير، والـ tokens أو الـ OTP أو المفاتيح اللي بتتعمل بيه ممكن تتوقع.'),
        fix: Bilingual('Use Random.secure() for anything security-related.',
            'استخدم Random.secure() لأي حاجة ليها علاقة بالأمان.'),
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
        final window = [for (var l = line - 3; l <= line + 3; l++) f.lineText(l)].join(' ');
        if (_securityContext.hasMatch(window)) {
          out.add(at(f, c.nameIndex,
              'Random() used near security-sensitive code.',
              messageAr: 'Random() مستخدم جنب كود حساس أمنياً.'));
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
        title: Bilingual('Sensitive data written to logs', 'بيانات حساسة بتتكتب في الـ logs'),
        description: Bilingual(
            'Logs survive in logcat, crash reports and device logs. Tokens and passwords printed there leak to anyone with USB access or to third-party SDKs. Dio\'s LogInterceptor prints Authorization headers.',
            'الـ logs بتفضل في logcat وتقارير الـ crash. أي token أو باسورد بيتطبع فيها بيتسرب لأي حد عنده USB أو لأي SDK تاني. والـ LogInterceptor بتاع Dio بيطبع الـ Authorization header.'),
        fix: Bilingual(
            'Never log secrets. Wrap debug logging in `if (kDebugMode)` and add LogInterceptor only in debug builds.',
            'متطبعش أسرار في الـ logs أبداً. حط أي logging جوه `if (kDebugMode)`، وضيف LogInterceptor في الـ debug بس.'),
        severity: Severity.medium,
        masvs: ['MASVS-STORAGE-2'],
        maswe: ['MASWE-0005'],
        cwe: 'CWE-532',
        profiles: _all,
      );

  static const _loggers = {'print', 'debugPrint', 'log', 'd', 'i', 'w', 'e', 'v', 't', 'info', 'debug', 'warning', 'severe', 'fine'};
  static final _loggerReceivers = RegExp(r'^(_?log(ger)?|developer|talker|_?logService)$', caseSensitive: false);

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final out = <Finding>[];
    for (final f in project.dartFiles) {
      for (final c in f.calls(_loggers)) {
        final r = c.receiver;
        final isBare = r == null && const {'print', 'debugPrint', 'log'}.contains(c.name);
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
        out.add(at(f, c.nameIndex, '"$hit" is passed to ${r == null ? '' : '$r.'}${c.name}().',
            messageAr: '"$hit" بيتبعت لـ ${c.name}() وبيتكتب في الـ logs.'));
      }
      for (final c in f.calls({'LogInterceptor', 'PrettyDioLogger'})) {
        if (_guardedByDebug(f, c.nameIndex)) continue;
        final args = f.text(c.open, c.close).replaceAll(' ', '');
        if (args.contains('requestHeader:false') && args.contains('responseHeader:false') && c.name == 'LogInterceptor') {
          continue;
        }
        out.add(at(f, c.nameIndex,
            '${c.name} is added without a kDebugMode guard and logs headers (Authorization).',
            messageAr: '${c.name} متضاف من غير شرط kDebugMode وبيطبع الـ headers (زي Authorization).'));
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
      for (final r in project.findFiles(a.substring(0, a.length - 1), riskyAssetFile.hasMatch)) {
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
        title: Bilingual('Secret file bundled as an asset', 'ملف أسرار متضاف كـ asset'),
        description: Bilingual(
            'Assets are plain files inside the APK/IPA. A bundled .env, service-account JSON or private key can be unzipped by anyone.',
            'الـ assets ملفات عادية جوه الـ APK/IPA. أي ملف .env أو service-account أو private key متضاف ممكن أي حد يفك الضغط ويقراه.'),
        fix: Bilingual(
            'Remove the file from flutter: assets. Use --dart-define for non-secret config and keep real secrets on the server.',
            'شيل الملف من flutter: assets. استخدم --dart-define للإعدادات العادية، وخلي الأسرار الحقيقية على السيرفر.'),
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
        out.add(inFile('pubspec.yaml', null, '$path is bundled as an asset.',
            messageAr: '$path متضاف كـ asset.'));
      } else {
        out.add(inFile(path, null, '$path is bundled through the "$folder" asset folder.',
            messageAr: '$path متضاف عن طريق فولدر الـ assets "$folder".'));
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
        title: Bilingual('WebView exposes native bridge or debugging', 'الـ WebView بيفتح bridge أو debugging'),
        description: Bilingual(
            'A JavaScript channel without navigation restrictions lets any page the WebView reaches call into your app. Enabled WebView debugging lets anyone inspect it over USB.',
            'الـ JavaScript channel من غير قيود على التنقل بيخلي أي صفحة يوصلها الـ WebView تنادي على كود التطبيق. وتفعيل الـ debugging بيخلي أي حد يفحص الـ WebView عن طريق USB.'),
        fix: Bilingual(
            'Restrict navigation with NavigationDelegate.onNavigationRequest (or shouldOverrideUrlLoading) to your own hosts, and enable WebView debugging only under kDebugMode.',
            'اقفل التنقل على السيرفرات بتاعتك بـ onNavigationRequest أو shouldOverrideUrlLoading، وفعّل الـ debugging في الـ debug بس.'),
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
      final bridges = f.calls({'addJavaScriptChannel', 'JavascriptChannel', 'addJavaScriptHandler', 'addJavascriptChannel'});
      if (bridges.isNotEmpty) {
        final restricted = f.source.contains('onNavigationRequest') ||
            f.source.contains('shouldOverrideUrlLoading');
        if (!restricted) {
          out.add(at(f, bridges.first.nameIndex,
              'JavaScript bridge (${bridges.first.name}) without navigation restrictions.',
              messageAr: 'JavaScript bridge (${bridges.first.name}) من غير قيود على التنقل.'));
        }
      }
      for (var i = 0; i + 2 < f.tokens.length; i++) {
        final t = f.tokens[i];
        if (!t.isIdent) continue;
        final isFlag = t.text == 'isInspectable' || t.text == 'setWebContentsDebuggingEnabled';
        if (!isFlag) continue;
        final window = f.text(i, (i + 4).clamp(0, f.tokens.length - 1).toInt());
        if (window.contains('true') && !_guardedByDebug(f, i)) {
          out.add(at(f, i, 'WebView debugging is enabled (${t.text}).',
              messageAr: 'الـ debugging بتاع الـ WebView مفعّل (${t.text}).'));
        }
      }
    }
    for (final s in project.androidNativeSources) {
      final m = RegExp(r'setWebContentsDebuggingEnabled\s*\(\s*true\s*\)').firstMatch(s.text);
      if (m != null && !s.text.contains('BuildConfig.DEBUG')) {
        out.add(inFile(s.path, lineAt(s.text, m.start),
            'WebView.setWebContentsDebuggingEnabled(true) in native code.',
            messageAr: 'WebView.setWebContentsDebuggingEnabled(true) في الكود الـ native.'));
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
