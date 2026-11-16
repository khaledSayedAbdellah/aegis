/// Sensitive data leaking through the UI and local storage: the keyboard
/// cache, the clipboard, notifications, accessibility services, Keychain
/// options and crypto keys kept in plain storage.
library;

import 'dart:io';

import 'package:path/path.dart' as p;

import '../dart_scanner.dart';
import '../l10n/messages.g.dart';
import '../model.dart';
import '../project.dart';
import '../security/native_analysis.dart' show withoutComments;
import 'dart_rules.dart' show guardedByDebug, isSecretName;
import 'rule.dart';

const _all = {MasProfile.l1, MasProfile.l2, MasProfile.r};

/// Text fields: Material, form and Cupertino.
const _fields = {'TextField', 'TextFormField', 'CupertinoTextField'};

/// Labels and hints of fields that hold secrets a keyboard must not learn.
final _secretLabel = RegExp(
    r'pass(?:word|code|phrase)|\bpin\b|cvv|cvc|card ?(?:number|no)|iban|'
    r'\bssn\b|social security|national id|secret|security code|كلمة (?:السر|المرور)|الرقم السري',
    caseSensitive: false);

/// Labels of fields an accessibility service should not read aloud or log.
final _privateLabel = RegExp(
    r'cvv|cvc|card ?(?:number|no)|iban|\bssn\b|social security|national id',
    caseSensitive: false);

String _labels(DartFile f, CallSite c) {
  final text = f.text(c.open, c.close);
  return RegExp(
          r'''(?:labelText|hintText|helperText|placeholder|label|hint)\s*:\s*(?:const\s+)?(?:Text\(\s*)?(['"])(.*?)\1''')
      .allMatches(text)
      .map((m) => m[2]!)
      .join(' ');
}

String? _named(DartFile f, CallSite c, String name) {
  final arg = f.namedArg(f.args(c.open), name);
  return arg == null ? null : f.text(arg.start, arg.end).trim();
}

/// A text field holding a password, PIN, card number or similar.
bool _secretField(DartFile f, CallSite c) {
  // `passwordController` -> `password`: the controller holds that value.
  final controller = (_named(f, c, 'controller') ?? '')
      .split('.')
      .last
      .replaceFirst(
          RegExp(r'(?:Text)?(?:Editing)?(?:Controller|Ctrl|Ctl)$'), '');
  final keyboard = _named(f, c, 'keyboardType') ?? '';
  return _secretLabel.hasMatch(_labels(f, c)) ||
      (controller.isNotEmpty &&
          isSecretName(controller) &&
          !RegExp('otp', caseSensitive: false).hasMatch(controller)) ||
      keyboard.contains('visiblePassword');
}

bool _obscured(DartFile f, CallSite c) {
  final v = _named(f, c, 'obscureText');
  return v != null && v != 'false';
}

/// Line number (1-based) of [offset] in [text].
int _lineAt(String text, int offset) =>
    '\n'.allMatches(text.substring(0, offset)).length + 1;

/// The last identifier of an expression: `session.accessToken` -> `accessToken`.
/// The name that says what [expression] holds: `_secret.text` is
/// `_secret`, `token.trim()` is `token`.
String _lastName(String expression) =>
    RegExp(r'[A-Za-z_]\w*')
        .allMatches(expression)
        .map((m) => m[0]!)
        .where((n) => !_accessors.contains(n))
        .lastOrNull ??
    expression;

const _accessors = {
  'text', 'value', 'data', 'string', 'toString', 'trim', 'getText', //
  'toUpperCase', 'toLowerCase', 'this', 'widget',
};

class KeyboardCacheRule extends Rule {
  const KeyboardCacheRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-D15',
        title: Bilingual(En.keyboardCacheTitle, Ar.keyboardCacheTitle),
        passTitleText: Bilingual(En.keyboardCachePass, Ar.keyboardCachePass),
        description:
            Bilingual(En.keyboardCacheDescription, Ar.keyboardCacheDescription),
        fix: Bilingual(En.keyboardCacheFix, Ar.keyboardCacheFix),
        severity: Severity.medium,
        masvs: ['MASVS-STORAGE-2'],
        maswe: ['MASWE-0036'],
        cwe: 'CWE-524',
        profiles: _all,
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final out = <Finding>[];
    for (final f in project.dartFiles) {
      for (final c in f.calls(_fields)) {
        if (!_secretField(f, c) || _obscured(f, c)) continue;
        if (_named(f, c, 'enableSuggestions') == 'false' &&
            _named(f, c, 'autocorrect') == 'false') {
          continue;
        }
        out.add(at(f, c.nameIndex, En.keyboardCache(field: c.name),
            messageAr: Ar.keyboardCache(field: c.name)));
      }
    }
    out.addAll(_native(project));
    return RuleCheck(out);
  }

  static final _secretLabel = RegExp(
      r'password|passcode|\bpin\b|\botp\b|one.?time|verification|cvv|card.?number|secret',
      caseSensitive: false);

  /// Jetpack Compose text fields and XML `EditText`s for secrets that keep
  /// suggestions on.
  List<Finding> _native(Project project) {
    final out = <Finding>[];
    for (final file in [
      ...project.androidNativeSources,
      ...project.sharedNativeSources,
    ]) {
      if (!file.path.endsWith('.kt') ||
          !RegExp(r'\b(?:Outlined)?TextField\s*\(').hasMatch(file.text)) {
        continue;
      }
      final f = DartFile(file.path, file.text);
      for (final c in f
          .calls(const {'TextField', 'OutlinedTextField', 'BasicTextField'})) {
        final text = f.text(c.open, c.close);
        if (!_secretLabel.hasMatch(text)) continue;
        if (RegExp(
                r'KeyboardType\.(?:Number)?Password|autoCorrect(?:Enabled)?\s*=\s*false|PasswordVisualTransformation')
            .hasMatch(text)) {
          continue;
        }
        out.add(at(f, c.nameIndex, En.nativeKeyboardCache(field: c.name),
            messageAr: Ar.nativeKeyboardCache(field: c.name)));
      }
    }
    final layouts = project.findFiles(
        '',
        (r) =>
            r.contains('/res/layout') &&
            r.endsWith('.xml') &&
            !r.contains('/build/'));
    for (final rel in layouts) {
      final text = File(project.abs(rel)).readAsStringSync();
      for (final m in RegExp(
              r'<(?:\w+\.)*(?:EditText|TextInputEditText|AppCompatEditText)\b[^>]*>')
          .allMatches(text)) {
        final tag = m[0]!;
        final hint =
            RegExp(r'android:(?:hint|id|contentDescription)\s*=\s*"([^"]*)"')
                .allMatches(tag)
                .map((h) => h[1]!)
                .join(' ');
        if (!_secretLabel.hasMatch(hint)) continue;
        final type =
            RegExp(r'android:inputType\s*=\s*"([^"]*)"').firstMatch(tag)?[1] ??
                '';
        if (RegExp(r'[pP]assword|textNoSuggestions').hasMatch(type)) continue;
        out.add(inFile(
            rel,
            '\n'.allMatches(text.substring(0, m.start)).length + 1,
            En.nativeKeyboardCache(field: 'EditText'),
            messageAr: Ar.nativeKeyboardCache(field: 'EditText')));
      }
    }
    return out;
  }
}

class ClipboardRule extends Rule {
  const ClipboardRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-D16',
        title: Bilingual(En.clipboardTitle, Ar.clipboardTitle),
        passTitleText: Bilingual(En.clipboardPass, Ar.clipboardPass),
        description:
            Bilingual(En.clipboardDescription, Ar.clipboardDescription),
        fix: Bilingual(En.clipboardFix, Ar.clipboardFix),
        severity: Severity.medium,
        masvs: ['MASVS-PLATFORM-3'],
        maswe: ['MASWE-0030'],
        cwe: 'CWE-200',
        profiles: _all,
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final out = <Finding>[];
    for (final f in project.dartFiles) {
      for (final c in f.calls({'setData'})) {
        if (c.receiver != 'Clipboard') continue;
        final m = RegExp(r'text\s*:\s*([\w.$!?]+)')
            .firstMatch(f.text(c.open, c.close));
        if (m == null) continue;
        final value = m[1]!.replaceAll(RegExp(r'[!?]'), '');
        final name = _lastName(value);
        if (!isSecretName(name)) continue;
        out.add(at(f, c.nameIndex, En.clipboard(value: value),
            messageAr: Ar.clipboard(value: value)));
      }
    }
    // Swift / Objective-C and Kotlin / Java.
    final native = RegExp(
        r'(?:UIPasteboard\.general|generalPasteboard\])\.string\s*=\s*([\w.]+)|'
        r'UIPasteboard\.general\.setValue\(\s*([\w.]+)|'
        r'ClipData\.newPlainText\([^,]*,\s*([\w.]+)');
    for (final file in project.nativeSources) {
      final code = withoutComments(file.text);
      for (final m in native.allMatches(code)) {
        final value = m[1] ?? m[2] ?? m[3]!;
        if (!isSecretName(_lastName(value))) continue;
        out.add(inFile(
            file.path, _lineAt(code, m.start), En.clipboard(value: value),
            messageAr: Ar.clipboard(value: value)));
      }
    }
    return RuleCheck(out);
  }
}

class NotificationLeakRule extends Rule {
  const NotificationLeakRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-D17',
        title: Bilingual(En.notificationLeakTitle, Ar.notificationLeakTitle),
        passTitleText:
            Bilingual(En.notificationLeakPass, Ar.notificationLeakPass),
        description: Bilingual(
            En.notificationLeakDescription, Ar.notificationLeakDescription),
        fix: Bilingual(En.notificationLeakFix, Ar.notificationLeakFix),
        severity: Severity.low,
        masvs: ['MASVS-PLATFORM-3'],
        maswe: ['MASWE-0037'],
        cwe: 'CWE-200',
        profiles: _all,
      );

  static final _sensitive = RegExp(
      r'otp|passcode|password|\bpin\b|verification code|balance|token|cvv',
      caseSensitive: false);

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final places = <String>[..._native(project)];
    if (!project.usesPackage('flutter_local_notifications') && places.isEmpty) {
      return RuleCheck.notApplicable();
    }
    for (final f in project.dartFiles) {
      if (!f.importsPackage('flutter_local_notifications')) continue;
      if (RegExp(r'NotificationVisibility\.(?:secret|private)')
          .hasMatch(f.source)) {
        continue;
      }
      for (final c in f.calls({'show'})) {
        final args = f.args(c.open).where((a) => a.name == null).toList();
        if (args.length < 3) continue;
        final shown = '${f.text(args[1].start, args[1].end)} '
            '${f.text(args[2].start, args[2].end)}';
        final names =
            RegExp(r'[A-Za-z_]\w*').allMatches(shown).map((m) => m[0]!);
        if (!_sensitive.hasMatch(shown) && !names.any(isSecretName)) continue;
        places.add('${f.path}:${f.lineOfToken(c.nameIndex)}');
      }
    }
    if (places.isEmpty) return RuleCheck([]);
    final list = places.take(5).join(', ');
    return RuleCheck.evidenceOnly(
        En.notificationLeak(places: list), Ar.notificationLeak(places: list));
  }

  /// Android `setContentText`/`setContentTitle`/`bigText` and iOS
  /// `content.body`/`content.title` with codes or tokens, unless the file
  /// hides them on the lock screen.
  static List<String> _native(Project project) {
    final out = <String>[];
    final shown = RegExp(
        r'\.(?:setContentText|setContentTitle|bigText|setTicker)\s*\(([^\n]*)|'
        r'\b\w*[cC]ontent\.(?:body|title|subtitle)\s*=\s*([^\n]*)');
    for (final file in project.nativeSources) {
      if (!RegExp(r'\.(?:kt|java|swift|m)$').hasMatch(file.path)) continue;
      final code = withoutComments(file.text);
      if (RegExp(
              r'VISIBILITY_(?:SECRET|PRIVATE)|setPublicVersion|hiddenPreviewsBodyPlaceholder')
          .hasMatch(code)) {
        continue;
      }
      for (final m in shown.allMatches(code)) {
        final value = m[1] ?? m[2]!;
        final names =
            RegExp(r'[A-Za-z_]\w*').allMatches(value).map((n) => n[0]!);
        if (!_sensitive.hasMatch(value) && !names.any(isSecretName)) continue;
        out.add('${file.path}:${_lineAt(code, m.start)}');
      }
    }
    return out;
  }
}

class SecureStorageOptionsRule extends Rule {
  const SecureStorageOptionsRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-D18',
        title: Bilingual(En.keychainOptionsTitle, Ar.keychainOptionsTitle),
        passTitleText:
            Bilingual(En.keychainOptionsPass, Ar.keychainOptionsPass),
        description: Bilingual(
            En.keychainOptionsDescription, Ar.keychainOptionsDescription),
        fix: Bilingual(En.keychainOptionsFix, Ar.keychainOptionsFix),
        severity: Severity.low,
        masvs: ['MASVS-STORAGE-1'],
        maswe: ['MASWE-0001'],
        cwe: 'CWE-312',
        profiles: _all,
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    if (!project.usesPackage('flutter_secure_storage')) {
      return RuleCheck.notApplicable();
    }
    final out = <Finding>[];
    for (final f in project.dartFiles) {
      for (var i = 0; i + 2 < f.tokens.length; i++) {
        final t = f.tokens[i];
        if (!t.isIdent) continue;
        String? option;
        if (t.text == 'KeychainAccessibility' &&
            f.tokens[i + 1].isPunct('.') &&
            const {'unlocked', 'first_unlock'}.contains(f.tokens[i + 2].text)) {
          option = 'KeychainAccessibility.${f.tokens[i + 2].text}';
        } else if (t.text == 'synchronizable' &&
            f.tokens[i + 1].isPunct(':') &&
            f.tokens[i + 2].text == 'true') {
          option = 'synchronizable: true';
        }
        if (option == null) continue;
        out.add(at(f, i, En.keychainOptions(option: option),
            messageAr: Ar.keychainOptions(option: option)));
      }
    }
    return RuleCheck(out);
  }
}

class PlainKeyStorageRule extends Rule {
  const PlainKeyStorageRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-D20',
        title: Bilingual(En.plainKeyTitle, Ar.plainKeyTitle),
        passTitleText: Bilingual(En.plainKeyPass, Ar.plainKeyPass),
        description: Bilingual(En.plainKeyDescription, Ar.plainKeyDescription),
        fix: Bilingual(En.plainKeyFix, Ar.plainKeyFix),
        severity: Severity.medium,
        l2Severity: Severity.high,
        masvs: ['MASVS-STORAGE-1'],
        maswe: ['MASWE-0003'],
        cwe: 'CWE-320',
        profiles: _all,
      );

  /// Variables that hold a key the app generated.
  static final _generated = RegExp(
      r'\b(\w+)\s*=\s*(?:await\s+)?(?:Key\.fromSecureRandom|Key\.fromLength|'
      r'SecretKey\(|SecretKeyData\(|\w+\.newSecretKey\(|\w+\.newKeyPair\(|'
      r'generateKey\(|\w+\.generateKeyPair\()');

  /// Key names [isSecretName] doesn't already cover (those are AEG-D04).
  static final _keyName = RegExp(
      r'(?:cipher|crypt|db|database|wrap|wrapping|kek|dek|data|storage)_?key|keybytes|rawkey|keymaterial',
      caseSensitive: false);

  /// Native variables holding raw key bytes: `val raw = key.encoded`,
  /// `let data = SecKeyCopyExternalRepresentation(key, nil)`,
  /// `let raw = symmetricKey.rawRepresentation`.
  static final _nativeKeyBytes = RegExp(
      r'\b(?:val|var|let|byte\[\])\s+(\w+)\s*(?::\s*[\w<>?\[\]]+\s*)?=\s*'
      r'(?:[\w.]+\.encoded\b|SecKeyCopyExternalRepresentation\(|[\w.]+\.rawRepresentation\b|'
      r'SecretKeySpec\(|keyGenerator\.generateKey\(\)|KeyGenerator\.getInstance)');

  /// Native writes to plain storage, one line each.
  static final _nativeWrite =
      RegExp(r'[^\n]*?\b(putString|putStringSet|writeBytes|writeText|'
          r'UserDefaults\.standard\.set|setObject|write\(to)\b[^\n]*');

  static const _writers = {
    'setString', 'setStringList', 'write', 'put', 'putAll', 'writeAsString', //
    'writeAsBytes', 'writeAsStringSync', 'writeAsBytesSync',
  };

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final out = <Finding>[];
    for (final f in project.dartFiles) {
      final generated = {
        for (final m in _generated.allMatches(f.source)) m[1]!,
      };
      for (final c in f.calls(_writers)) {
        final recv = c.receivers.join('.').toLowerCase();
        if (recv.contains('secure') || recv.contains('keychain')) continue;
        final text = f.text(c.open, c.close);
        final names =
            RegExp(r'[A-Za-z_]\w*').allMatches(text).map((m) => m[0]!);
        final key = names.where(generated.contains).firstOrNull ??
            names
                .where((n) => _keyName.hasMatch(n) && !isSecretName(n))
                .firstOrNull ??
            RegExp(r'''['"](\w+)['"]''')
                .allMatches(text)
                .map((m) => m[1]!)
                .where((n) => _keyName.hasMatch(n) && !isSecretName(n))
                .firstOrNull;
        if (key == null || guardedByDebug(f, c.nameIndex)) continue;
        out.add(at(f, c.nameIndex, En.plainKey(key: key, call: c.name),
            messageAr: Ar.plainKey(key: key, call: c.name)));
      }
    }
    for (final file in project.nativeSources) {
      final code = withoutComments(file.text);
      // Values that are raw key bytes.
      final keys = {
        for (final m in _nativeKeyBytes.allMatches(code)) m[1]!,
      };
      for (final m in _nativeWrite.allMatches(code)) {
        final line = m[0]!;
        final key = keys
                .where((k) => RegExp('\\b$k\\b').hasMatch(line))
                .firstOrNull ??
            (RegExp(r'\.encoded\b|SecKeyCopyExternalRepresentation|\.rawRepresentation')
                    .hasMatch(line)
                ? _lastName(line.split('(').skip(1).join('('))
                : null);
        if (key == null) continue;
        final call = m[1]!;
        out.add(inFile(file.path, _lineAt(code, m.start),
            En.plainKey(key: key, call: call),
            messageAr: Ar.plainKey(key: key, call: call)));
      }
    }
    return RuleCheck(out);
  }
}

class AccessibilityLeakRule extends Rule {
  const AccessibilityLeakRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-P14',
        title: Bilingual(En.a11yLeakTitle, Ar.a11yLeakTitle),
        passTitleText: Bilingual(En.a11yLeakPass, Ar.a11yLeakPass),
        description: Bilingual(En.a11yLeakDescription, Ar.a11yLeakDescription),
        fix: Bilingual(En.a11yLeakFix, Ar.a11yLeakFix),
        severity: Severity.low,
        masvs: ['MASVS-PLATFORM-3'],
        maswe: ['MASWE-0040'],
        cwe: 'CWE-200',
        profiles: _all,
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final places = <String>[];
    for (final f in project.dartFiles) {
      if (f.source.contains('ExcludeSemantics')) continue;
      for (final c in f.calls(_fields)) {
        if (_obscured(f, c) || !_privateLabel.hasMatch(_labels(f, c))) {
          continue;
        }
        places.add('${f.path}:${f.lineOfToken(c.nameIndex)}');
      }
    }
    for (final (file, line) in _androidFields(project)) {
      places.add('$file:$line');
    }
    if (places.isEmpty) return RuleCheck([]);
    final list = places.take(5).join(', ');
    return RuleCheck.evidenceOnly(
        En.a11yLeak(places: list), Ar.a11yLeak(places: list));
  }

  /// `EditText` views in Android layouts that hold card or identity numbers
  /// and don't hide them from accessibility services.
  static List<(String, int)> _androidFields(Project project) {
    final out = <(String, int)>[];
    final res = Directory(project.abs('android/app/src/main/res'));
    if (!res.existsSync()) return out;
    for (final e in res.listSync(recursive: true)) {
      if (e is! File || !e.path.endsWith('.xml')) continue;
      if (!p.split(e.path).any((s) => s.startsWith('layout'))) continue;
      final String text;
      try {
        text = e.readAsStringSync();
      } catch (_) {
        continue;
      }
      for (final m
          in RegExp(r'<(?:\w+\.)*\w*EditText\b[^>]*>').allMatches(text)) {
        final tag = m[0]!;
        if (!_privateLabel.hasMatch(tag.replaceAll('_', ' '))) continue;
        if (tag.contains('textPassword') ||
            tag.contains('importantForAccessibility="no"') ||
            tag.contains('accessibilityDataSensitive="yes"')) {
          continue;
        }
        out.add((
          project.rel(e.path),
          '\n'.allMatches(text.substring(0, m.start)).length + 1
        ));
      }
    }
    return out;
  }
}

const uiLeakRules = <Rule>[
  KeyboardCacheRule(),
  ClipboardRule(),
  NotificationLeakRule(),
  SecureStorageOptionsRule(),
  PlainKeyStorageRule(),
  AccessibilityLeakRule(),
];
