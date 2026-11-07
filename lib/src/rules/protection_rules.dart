/// Rules that verify protections are wired correctly, not just installed.
///
/// This is what makes aegis different from a plain checklist scanner: it
/// checks whether your RASP is started, configured for *your* app, and whether
/// a detected threat triggers a real reaction.
library;

import 'dart:io';

import 'package:xml/xml.dart';

import '../dart_scanner.dart';
import '../model.dart';
import '../project.dart';
import '../util.dart';
import 'dart_rules.dart' show guardedByDebug;
import 'rule.dart';

const _all = {MasProfile.l1, MasProfile.l2, MasProfile.r};
const _r = {MasProfile.r};
const _l2 = {MasProfile.l2};
const _l2r = {MasProfile.l2, MasProfile.r};

const raspPackages = [
  'freerasp',
  'safe_device',
  'flutter_jailbreak_detection',
  'jailbreak_root_detection',
  'flutter_neo_shield',
  'flutter_app_security',
  'trust_fall',
];

/// Dart files that import [package].
List<DartFile> filesImporting(Project p, String package) =>
    p.dartFiles.where((f) => f.importsPackage(package)).toList();

/// Calls to [name] whose receiver chain contains all of [receivers].
List<(DartFile, CallSite)> findCalls(Project p, Set<String> names,
    {List<String> receivers = const []}) {
  final out = <(DartFile, CallSite)>[];
  for (final f in p.dartFiles) {
    for (final c in f.calls(names)) {
      if (receivers.every(c.receivers.contains)) out.add((f, c));
    }
  }
  return out;
}

final _localLogging = RegExp(
    r'^(await\s+)?(print|debugPrint|log|developer\s*\.\s*log|_?log(ger)?\s*\.\s*\w+|Logger\s*\(\s*\)\s*\.\s*\w+|debugger|assert)\s*\(');

/// Whether the callback value at [a] does nothing but local logging.
/// Returns null when it cannot be decided (e.g. a tear-off defined elsewhere).
bool? isTrivialReaction(Project p, DartFile f, Arg a) {
  final first = f.tokens[a.start];
  if (a.start == a.end) {
    if (first.isIdent && first.text == 'null') return true;
    if (first.isIdent) {
      // Tear-off: look for the function body in the same or other files.
      for (final file in [f, ...p.dartFiles.where((x) => x != f)]) {
        final body = file.functionBody(first.text);
        if (body != null) return _trivialBody(file, body.start, body.end);
      }
      return null;
    }
  }
  if (first.isPunct('(')) {
    final close = f.matchOf(a.start);
    if (close == null || close >= a.end) return null;
    var b = close + 1;
    final asyncTok = f.at(b);
    if (asyncTok != null && asyncTok.isIdent && asyncTok.text == 'async') b++;
    return _trivialBody(f, b, a.end);
  }
  return null;
}

bool _trivialBody(DartFile f, int start, int end) {
  final t = f.at(start);
  if (t == null) return true;
  if (t.isPunct('=>')) {
    final expr = f.text(start + 1, end).trim();
    if (expr.isEmpty || expr == 'null' || expr == '{}') return true;
    return _localLogging.hasMatch(expr);
  }
  if (t.isPunct('{')) {
    final close = f.matchOf(start) ?? end;
    if (close == start + 1) return true; // empty block
    final statements = <String>[];
    var s = start + 1;
    var k = start + 1;
    while (k < close) {
      final tk = f.tokens[k];
      if (tk.isPunct('{') || tk.isPunct('(') || tk.isPunct('[')) {
        final m = f.matchOf(k);
        if (m != null && m < close) {
          k = m + 1;
          continue;
        }
      }
      if (tk.isPunct(';')) {
        statements.add(f.text(s, k - 1).trim());
        s = k + 1;
      }
      k++;
    }
    if (s < close) statements.add(f.text(s, close - 1).trim());
    return statements
        .where((st) => st.isNotEmpty && st != 'return')
        .every(_localLogging.hasMatch);
  }
  return false;
}

/// `applicationId` from the app Gradle file.
String? androidApplicationId(Project p) {
  final g = p.appGradle;
  if (g == null) return null;
  final m = RegExp(r'''applicationId\s*(=\s*)?["']([^"']+)["']''')
      .firstMatch(stripCComments(g.text));
  return m?.group(2);
}

/// `PRODUCT_BUNDLE_IDENTIFIER` values of the Runner target.
Set<String> iosBundleIds(Project p) {
  final f = File(p.abs('ios/Runner.xcodeproj/project.pbxproj'));
  if (!f.existsSync()) return const {};
  final ids = <String>{};
  for (final m in RegExp(r'PRODUCT_BUNDLE_IDENTIFIER\s*=\s*"?([^";]+)"?;')
      .allMatches(f.readAsStringSync())) {
    final id = m.group(1)!.trim();
    if (id.endsWith('RunnerTests') || id.contains(r'$(')) continue;
    ids.add(id);
  }
  return ids;
}

List<String> _stringList(DartFile f, Arg a) {
  final out = <String>[];
  for (var k = a.start; k <= a.end; k++) {
    final t = f.tokens[k];
    if (t.isString) out.add(t.value ?? '');
  }
  return out;
}

// ---------------------------------------------------------------------------

class RaspPresenceRule extends Rule {
  const RaspPresenceRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-P01',
        title: Bilingual('No runtime protection (RASP)', 'مفيش حماية وقت التشغيل (RASP)'),
        description: Bilingual(
            'Without RASP the app cannot tell when it runs on a rooted/jailbroken device, under a debugger, with Frida hooks, or after being repackaged.',
            'من غير RASP التطبيق مش هيعرف لو شغال على جهاز rooted أو jailbroken، أو عليه debugger أو Frida، أو لو حد عدّل عليه وأعاد توقيعه.'),
        fix: Bilingual(
            'Add a RASP SDK such as freerasp, start it in main(), and react to threats (block sensitive features, wipe secrets, notify the backend).',
            'ضيف RASP SDK زي freerasp، وشغّله في main()، واعمل رد فعل حقيقي (اقفل الخصائص الحساسة، امسح الأسرار، بلّغ السيرفر).'),
        severity: Severity.high,
        masvs: ['MASVS-RESILIENCE-1', 'MASVS-RESILIENCE-4'],
        maswe: ['MASWE-0051', 'MASWE-0064', 'MASWE-0065'],
        cwe: 'CWE-919',
        profiles: _r,
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    if (!project.isFlutterApp) return RuleCheck.notApplicable();
    final has = raspPackages.any(project.usesPackage);
    if (has) return RuleCheck([]);
    return RuleCheck([
      inFile('pubspec.yaml', null, 'No RASP package found in dependencies.',
          messageAr: 'مفيش أي مكتبة RASP في الـ dependencies.')
    ]);
  }
}

class FreeRaspWiringRule extends Rule {
  const FreeRaspWiringRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-P02',
        title: Bilingual('freeRASP is installed but not running', 'freeRASP متثبت بس مش شغال'),
        description: Bilingual(
            'freeRASP only protects the app after Talsec.instance.start(config) runs and a ThreatCallback is attached. Otherwise it is dead weight that gives a false sense of security.',
            'freeRASP مش بيحمي غير بعد ما Talsec.instance.start(config) يتنادى ويتربط ThreatCallback. غير كده هو مجرد مكتبة زيادة بتدي إحساس كاذب بالأمان.'),
        fix: Bilingual(
            'In main(): WidgetsFlutterBinding.ensureInitialized(); Talsec.instance.attachListener(callback); await Talsec.instance.start(config);',
            'في main(): نادي WidgetsFlutterBinding.ensureInitialized()، وبعدين Talsec.instance.attachListener(callback)، وبعدين await Talsec.instance.start(config).'),
        severity: Severity.critical,
        masvs: ['MASVS-RESILIENCE-1'],
        maswe: ['MASWE-0051'],
        cwe: 'CWE-693',
        profiles: _all,
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    if (!project.usesPackage('freerasp')) {
      return RuleCheck.notApplicable('freerasp not used');
    }
    final out = <Finding>[];
    final starts = findCalls(project, {'start'}, receivers: ['instance', 'Talsec']);
    if (starts.isEmpty) {
      out.add(inFile('pubspec.yaml', null,
          'freerasp is a dependency but Talsec.instance.start() is never called.',
          messageAr: 'freerasp موجود في الـ dependencies بس Talsec.instance.start() مش بيتنادى خالص.'));
    }
    final listeners = findCalls(project, {'attachListener'}, receivers: ['instance', 'Talsec']);
    if (listeners.isEmpty) {
      out.add(inFile(
          starts.isEmpty ? 'pubspec.yaml' : starts.first.$1.path,
          starts.isEmpty ? null : starts.first.$1.lineOfToken(starts.first.$2.nameIndex),
          'No ThreatCallback is attached (Talsec.instance.attachListener is never called), so detected threats are ignored.',
          messageAr: 'مفيش ThreatCallback متربط (Talsec.instance.attachListener مش بيتنادى)، يعني أي تهديد هيتكشف وهيتجاهل.'));
    }
    return RuleCheck(out);
  }
}

class FreeRaspConfigRule extends Rule {
  const FreeRaspConfigRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-P03',
        title: Bilingual('freeRASP is misconfigured', 'إعدادات freeRASP غلط'),
        description: Bilingual(
            'freeRASP checks the app against the package name, signing certificate hashes and bundle ids you give it. Wrong, empty or copied-from-docs values make tamper detection fire on everyone or on no one, and isProd=false switches to dev mode in release.',
            'freeRASP بيقارن التطبيق بالـ package name والـ signing hashes والـ bundle ids اللي بتديهاله. لو القيم غلط أو فاضية أو منقولة من الـ docs، كشف التعديل هيشتغل على الكل أو مش هيشتغل خالص. و isProd=false بيخليه في وضع التطوير في الـ release.'),
        fix: Bilingual(
            'Use your real applicationId / bundle ids, the Base64 SHA-256 of your upload AND Play App Signing certificates, your Apple team id, and isProd: kReleaseMode.',
            'استخدم الـ applicationId والـ bundle ids الحقيقيين، والـ SHA-256 بصيغة Base64 لشهادة الـ upload وشهادة Play App Signing، والـ team id بتاعك، و isProd: kReleaseMode.'),
        severity: Severity.high,
        masvs: ['MASVS-RESILIENCE-2'],
        maswe: ['MASWE-0057'],
        cwe: 'CWE-693',
        profiles: _all,
      );

  /// Values copied from the freeRASP documentation/example.
  static const _docValues = ['aheaditec', 'freeraspExample', 'AKoRuyLMM91E7lX/Zqp3u4jMmd0A7hH/Iqozu0TMVd0='];

  bool _placeholder(String v) {
    final l = v.toLowerCase();
    return v.trim().isEmpty ||
        _docValues.any((d) => v.contains(d)) ||
        l.contains('your') ||
        l.contains('xxx') ||
        l.contains('todo') ||
        l.contains('replace') ||
        l == 'hash' ||
        l.contains('...');
  }

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    if (!project.usesPackage('freerasp')) return RuleCheck.notApplicable();
    final out = <Finding>[];
    final configs = findCalls(project, {'TalsecConfig'});
    if (configs.isEmpty) return RuleCheck.notApplicable('No TalsecConfig found');
    for (final (f, c) in configs) {
      final args = f.args(c.open);
      final isProd = f.namedArg(args, 'isProd');
      if (isProd != null) {
        final v = f.text(isProd.start, isProd.end).replaceAll(' ', '');
        if (v == 'false' || v == 'kDebugMode' || v == '!kReleaseMode' || v == 'kProfileMode') {
          out.add(at(f, isProd.start, 'isProd is "$v", so release builds run freeRASP in dev mode.',
              messageAr: 'isProd قيمته "$v"، يعني الـ release هيشغّل freeRASP في وضع التطوير.'));
        }
      }
    }

    final appId = androidApplicationId(project);
    for (final (f, c) in findCalls(project, {'AndroidConfig'})) {
      final args = f.args(c.open);
      final pkg = f.namedArg(args, 'packageName');
      if (pkg != null) {
        final values = _stringList(f, pkg);
        final v = values.isEmpty ? '' : values.first;
        if (values.isNotEmpty && _placeholder(v)) {
          out.add(at(f, pkg.start, 'packageName "$v" looks like a placeholder or the freeRASP example.',
              messageAr: 'packageName "$v" شكله قيمة مؤقتة أو منقول من مثال freeRASP.'));
        } else if (values.isNotEmpty && appId != null && v != appId) {
          out.add(at(f, pkg.start, 'packageName "$v" does not match applicationId "$appId".',
              messageAr: 'packageName "$v" مش مطابق للـ applicationId "$appId".'));
        }
      }
      final hashes = f.namedArg(args, 'signingCertHashes');
      if (hashes == null) {
        out.add(at(f, c.nameIndex, 'AndroidConfig has no signingCertHashes.',
            messageAr: 'AndroidConfig مفيهوش signingCertHashes.'));
      } else {
        final hs = _stringList(f, hashes);
        final isLiteralList = f.tokens[hashes.start].isPunct('[');
        if (isLiteralList && hs.isEmpty) {
          out.add(at(f, hashes.start, 'signingCertHashes is empty.',
              messageAr: 'signingCertHashes فاضية.'));
        }
        for (final h in hs) {
          if (_placeholder(h)) {
            out.add(at(f, hashes.start, 'signingCertHashes contains a placeholder or the documentation example.',
                messageAr: 'signingCertHashes فيها قيمة مؤقتة أو منقولة من الـ docs.'));
            break;
          }
          if (RegExp(r'^[0-9A-Fa-f:]{40,}$').hasMatch(h)) {
            out.add(at(f, hashes.start, 'A signing hash is in hex; freeRASP expects Base64 of the SHA-256.',
                messageAr: 'فيه hash مكتوب hex، و freeRASP محتاج SHA-256 بصيغة Base64.'));
            break;
          }
        }
        if (isLiteralList && hs.length == 1 && profile.resilience) {
          out.add(at(f, hashes.start,
              'Only one signing hash is configured. Apps on Google Play need both the upload key and the Play App Signing key hashes.',
              messageAr: 'فيه signing hash واحد بس. التطبيقات على Google Play محتاجة hash الـ upload key و hash الـ Play App Signing الاتنين.'));
        }
      }
    }

    final bundleIds = iosBundleIds(project);
    for (final (f, c) in findCalls(project, {'IOSConfig', 'IosConfig'})) {
      final args = f.args(c.open);
      final ids = f.namedArg(args, 'bundleIds') ?? f.namedArg(args, 'bundleId');
      if (ids != null) {
        final values = _stringList(f, ids);
        for (final v in values) {
          if (_placeholder(v)) {
            out.add(at(f, ids.start, 'bundleIds contains placeholder "$v".',
                messageAr: 'bundleIds فيها قيمة مؤقتة "$v".'));
          } else if (bundleIds.isNotEmpty && !bundleIds.contains(v)) {
            out.add(at(f, ids.start, 'bundle id "$v" is not one of the Runner bundle ids (${bundleIds.join(', ')}).',
                messageAr: 'الـ bundle id "$v" مش من الـ bundle ids بتاعة Runner (${bundleIds.join(', ')}).'));
          }
        }
      }
      final team = f.namedArg(args, 'teamId');
      if (team != null) {
        final values = _stringList(f, team);
        if (values.isNotEmpty && (_placeholder(values.first) || values.first.length != 10)) {
          out.add(at(f, team.start, 'teamId "${values.first}" is not a valid 10-character Apple team id.',
              messageAr: 'teamId "${values.first}" مش team id صحيح (لازم 10 حروف).'));
        }
      }
    }
    return RuleCheck(out);
  }
}

class FreeRaspReactionRule extends Rule {
  const FreeRaspReactionRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-P04',
        title: Bilingual('Threats are detected but nothing happens', 'التهديدات بتتكشف بس مفيش رد فعل'),
        description: Bilingual(
            'Detection without reaction is not protection. Callbacks that are missing, empty, or only print/log mean a rooted device, Frida or a repackaged app keeps full access.',
            'الكشف من غير رد فعل مش حماية. لو الـ callbacks مش موجودة أو فاضية أو بتعمل print بس، الجهاز الـ rooted أو Frida أو التطبيق المعدّل هيفضل ليه كل الصلاحيات.'),
        fix: Bilingual(
            'For onPrivilegedAccess, onHooks, onAppIntegrity and onDebug: block sensitive features, wipe tokens from secure storage, report to your backend, or exit.',
            'في onPrivilegedAccess و onHooks و onAppIntegrity و onDebug: اقفل الخصائص الحساسة، امسح الـ tokens من الـ secure storage، بلّغ السيرفر، أو اقفل التطبيق.'),
        severity: Severity.medium,
        l2Severity: Severity.high,
        masvs: ['MASVS-RESILIENCE-1', 'MASVS-RESILIENCE-2', 'MASVS-RESILIENCE-4'],
        maswe: ['MASWE-0051', 'MASWE-0058', 'MASWE-0064', 'MASWE-0065'],
        cwe: 'CWE-693',
        profiles: _all,
      );

  static const critical = ['onPrivilegedAccess', 'onHooks', 'onAppIntegrity', 'onDebug'];
  static const recommended = ['onSimulator', 'onUnofficialStore', 'onObfuscationIssues', 'onDeviceBinding'];

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    if (!project.usesPackage('freerasp')) return RuleCheck.notApplicable();
    final callbacks = findCalls(project, {'ThreatCallback'});
    if (callbacks.isEmpty) {
      return RuleCheck.notApplicable('No ThreatCallback (reported by AEG-P02)');
    }
    final out = <Finding>[];
    for (final (f, c) in callbacks) {
      final args = f.args(c.open);
      final names = args.map((a) => a.name).whereType<String>().toSet();
      final wanted = profile.resilience || profile.isL2
          ? [...critical, ...recommended]
          : critical;
      final missing = wanted.where((n) => !names.contains(n)).toList();
      if (missing.isNotEmpty) {
        out.add(at(f, c.nameIndex, 'ThreatCallback does not handle: ${missing.join(', ')}.',
            messageAr: 'الـ ThreatCallback مش بيتعامل مع: ${missing.join(', ')}.'));
      }
      final trivial = <String>[];
      for (final a in args) {
        if (a.name == null || !critical.contains(a.name)) continue;
        if (isTrivialReaction(project, f, a) == true) trivial.add(a.name!);
      }
      if (trivial.isNotEmpty) {
        out.add(at(f, c.nameIndex,
            'These callbacks only log or do nothing: ${trivial.join(', ')}.',
            messageAr: 'الـ callbacks دي بتعمل log بس أو مش بتعمل حاجة: ${trivial.join(', ')}.'));
      }
    }
    return RuleCheck(out);
  }
}

class AppCheckMissingRule extends Rule {
  const AppCheckMissingRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-P05',
        title: Bilingual('Firebase used without App Check', 'Firebase مستخدم من غير App Check'),
        description: Bilingual(
            'Without App Check, scripts and modified apps can call your Firestore, Storage, Functions and Auth with the keys inside your APK.',
            'من غير App Check، أي script أو تطبيق معدّل يقدر ينادي Firestore و Storage و Functions و Auth بتوعك باستخدام المفاتيح اللي جوه الـ APK.'),
        fix: Bilingual(
            'Add firebase_app_check with Play Integrity (Android) and App Attest with DeviceCheck fallback (iOS), monitor metrics, then enable enforcement.',
            'ضيف firebase_app_check بـ Play Integrity على Android و App Attest مع DeviceCheck على iOS، راقب الأرقام، وبعدين فعّل الـ enforcement.'),
        severity: Severity.medium,
        masvs: ['MASVS-RESILIENCE-2'],
        maswe: ['MASWE-0056', 'MASWE-0054'],
        cwe: 'CWE-346',
        profiles: _l2r,
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    if (!project.usesPackage('firebase_core')) {
      return RuleCheck.notApplicable('Firebase not used');
    }
    if (project.usesPackage('firebase_app_check')) return RuleCheck([]);
    return RuleCheck([
      inFile('pubspec.yaml', null, 'firebase_core is used but firebase_app_check is not.',
          messageAr: 'firebase_core مستخدم بس firebase_app_check مش موجود.')
    ]);
  }
}

class AppCheckDebugProviderRule extends Rule {
  const AppCheckDebugProviderRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-P06',
        title: Bilingual('App Check debug provider can reach release', 'الـ debug provider بتاع App Check ممكن يوصل للـ release'),
        description: Bilingual(
            'The debug provider skips device attestation. If it is not limited to debug builds, App Check protects nothing in production.',
            'الـ debug provider بيتخطى الـ attestation. لو مش محصور في الـ debug بس، App Check مش هيحمي حاجة في الـ production.'),
        fix: Bilingual(
            'Select the provider with kDebugMode, e.g. androidProvider: kDebugMode ? AndroidProvider.debug : AndroidProvider.playIntegrity.',
            'اختار الـ provider حسب kDebugMode، مثلاً: androidProvider: kDebugMode ? AndroidProvider.debug : AndroidProvider.playIntegrity.'),
        severity: Severity.high,
        masvs: ['MASVS-RESILIENCE-2'],
        maswe: ['MASWE-0056'],
        cwe: 'CWE-489',
        profiles: _all,
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    if (!project.usesPackage('firebase_app_check')) {
      return RuleCheck.notApplicable('firebase_app_check not used');
    }
    final out = <Finding>[];
    for (final f in project.dartFiles) {
      for (var i = 0; i + 2 < f.tokens.length; i++) {
        final t = f.tokens[i];
        if (!t.isIdent) continue;
        final isEnumDebug = (t.text == 'AndroidProvider' || t.text == 'AppleProvider') &&
            f.tokens[i + 1].isPunct('.') &&
            f.tokens[i + 2].text == 'debug';
        final isClassDebug = (t.text == 'AndroidDebugProvider' || t.text == 'AppleDebugProvider') &&
            f.tokens[i + 1].isPunct('(');
        if (!isEnumDebug && !isClassDebug) continue;
        final line = f.lineOfToken(i);
        final window = [for (var l = line - 2; l <= line + 2; l++) f.lineText(l)].join(' ');
        if (RegExp(r'k(Debug|Release|Profile)Mode').hasMatch(window)) continue;
        if (guardedByDebug(f, i)) continue;
        out.add(at(f, i, '${t.text}${isEnumDebug ? '.debug' : '()'} is used without a kDebugMode guard.',
            messageAr: '${t.text}${isEnumDebug ? '.debug' : '()'} مستخدم من غير شرط kDebugMode.'));
      }
    }
    return RuleCheck(out);
  }
}

class PinningRule extends Rule {
  const PinningRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-P07',
        title: Bilingual('No effective certificate pinning', 'مفيش certificate pinning فعّال'),
        description: Bilingual(
            'Without pinning, a user-installed or compromised CA lets an attacker read and modify API traffic. Pinning that still trusts system roots can be bypassed the same way.',
            'من غير pinning، أي CA متثبتة أو مخترقة تسمح للمهاجم يقرا ويعدّل الـ API traffic. والـ pinning اللي لسه بيثق في شهادات النظام ممكن يتخطى بنفس الطريقة.'),
        fix: Bilingual(
            'Pin your API hosts: a <pin-set> in network_security_config.xml plus NSPinnedDomains on iOS, or a Dart HttpClient with SecurityContext(withTrustedRoots: false) loaded with your certificate.',
            'اعمل pinning للسيرفرات بتاعتك: <pin-set> في network_security_config.xml و NSPinnedDomains على iOS، أو HttpClient بـ SecurityContext(withTrustedRoots: false) ومعاه الشهادة بتاعتك.'),
        severity: Severity.medium,
        masvs: ['MASVS-NETWORK-2'],
        maswe: ['MASWE-0028'],
        cwe: 'CWE-295',
        profiles: _l2,
      );

  static const _pinningPackages = [
    'http_certificate_pinning',
    'ssl_pinning_plugin',
    'certificate_pinning_httpclient',
    'dio_certificate_pinning',
    'flutter_ssl_pinning',
  ];
  static const _networkPackages = ['http', 'dio', 'chopper', 'retrofit', 'graphql', 'graphql_flutter', 'web_socket_channel', 'grpc'];

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final usesNetwork = _networkPackages.any(project.dependsOn) ||
        project.dartFiles.any((f) => f.source.contains('HttpClient('));
    if (!usesNetwork) return RuleCheck.notApplicable('No HTTP client found');

    final out = <Finding>[];
    var evidence = false;
    final nsc = project.networkSecurityConfigXml;
    if (nsc != null) {
      final now = DateTime.now();
      final active = nsc.findAllElements('pin-set').where((s) {
        final exp = DateTime.tryParse(s.getAttribute('expiration') ?? '');
        return exp == null || exp.isAfter(now);
      });
      if (active.isNotEmpty) evidence = true;
    }
    final ats = project.infoPlistData?['NSAppTransportSecurity'];
    if (ats is Map && ats['NSPinnedDomains'] != null) evidence = true;
    if (_pinningPackages.any(project.usesPackage)) evidence = true;

    for (final f in project.dartFiles) {
      if (f.source.contains('CertPinShield')) evidence = true;
      for (final c in f.calls({'SecurityContext'})) {
        final args = f.args(c.open);
        final roots = f.namedArg(args, 'withTrustedRoots');
        final rootsOff = roots != null && f.text(roots.start, roots.end).trim() == 'false';
        final loadsCert = f.source.contains('setTrustedCertificates');
        if (loadsCert && rootsOff) {
          evidence = true;
        } else if (loadsCert && !rootsOff) {
          out.add(at(f, c.nameIndex,
              'SecurityContext loads your certificate but keeps trusting system roots (withTrustedRoots is not false), so any trusted CA still works.',
              messageAr: 'الـ SecurityContext بيحمّل الشهادة بتاعتك بس لسه بيثق في شهادات النظام (withTrustedRoots مش false)، فأي CA موثوقة هتشتغل.'));
          evidence = true;
        }
      }
      for (var i = 0; i + 2 < f.tokens.length; i++) {
        final t = f.tokens[i];
        if (!t.isIdent || !(t.text == 'badCertificateCallback' || t.text == 'validateCertificate')) continue;
        final body = f.text(i, (i + 60).clamp(0, f.tokens.length - 1).toInt());
        if (RegExp(r'(sha256|sha1|fingerprint|\.der|pem)', caseSensitive: false).hasMatch(body)) {
          evidence = true;
        }
      }
    }
    if (!evidence) {
      out.add(inFile(null, null, 'No certificate pinning found for an app that makes network calls.',
          messageAr: 'مفيش certificate pinning في تطبيق بيعمل network calls.'));
    }
    return RuleCheck(out);
  }
}

class LocalAuthRule extends Rule {
  const LocalAuthRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-P08',
        title: Bilingual('Biometric check is only a boolean', 'البصمة مجرد true/false'),
        description: Bilingual(
            'local_auth returns true/false. With Frida that result is flipped in one line, so biometrics that do not unlock a Keystore/Keychain key can be bypassed.',
            'local_auth بيرجع true أو false بس. بـ Frida النتيجة دي بتتقلب في سطر واحد، فالبصمة اللي مش بتفتح مفتاح في الـ Keystore أو الـ Keychain ممكن تتخطى.'),
        fix: Bilingual(
            'Bind biometrics to a key: use biometric_storage or flutter_secure_storage with authentication-required options so the secret is only released after a real biometric match.',
            'اربط البصمة بمفتاح تشفير: استخدم biometric_storage أو flutter_secure_storage مع خيار authentication required، عشان السر ميطلعش غير بعد بصمة حقيقية.'),
        severity: Severity.medium,
        masvs: ['MASVS-AUTH-2'],
        maswe: ['MASWE-0020', 'MASWE-0021'],
        cwe: 'CWE-287',
        profiles: _l2,
      );

  static const _cryptoBound = ['biometric_storage', 'flutter_locker', 'biometric_signature', 'flutter_biometric_storage'];

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    if (!project.usesPackage('local_auth')) return RuleCheck.notApplicable('local_auth not used');
    final out = <Finding>[];
    final calls = <(DartFile, CallSite)>[];
    for (final f in filesImporting(project, 'local_auth')) {
      calls.addAll(f.calls({'authenticate'}).map((c) => (f, c)));
    }
    if (calls.isEmpty) {
      return RuleCheck.notApplicable(
          'local_auth is a dependency but no authenticate() call was found in the scanned code');
    }
    final bound = _cryptoBound.any(project.usesPackage);
    if (!bound) {
      final (f, c) = calls.first;
      out.add(at(f, c.nameIndex, 'Biometric result is used as a plain boolean (no key bound to it).',
          messageAr: 'نتيجة البصمة مستخدمة كـ true/false بس (مش مربوطة بمفتاح).'));
    }
    for (final (f, c) in calls) {
      final txt = f.text(c.open, c.close).replaceAll(RegExp(r'\s+'), '');
      if (!txt.contains('biometricOnly:true')) {
        out.add(at(f, c.nameIndex,
            'authenticate() allows falling back to device PIN/passcode (biometricOnly is not true).',
            messageAr: 'authenticate() بيسمح بالرجوع للـ PIN بتاع الجهاز (biometricOnly مش true).'));
      }
    }
    return RuleCheck(out);
  }
}

class ScreenProtectionRule extends Rule {
  const ScreenProtectionRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-P09',
        title: Bilingual('No screenshot / recording protection', 'مفيش حماية من الـ screenshots والتسجيل'),
        description: Bilingual(
            'Sensitive screens (balances, OTPs, cards) can be captured by screenshots, screen recording, casting and the app switcher thumbnail.',
            'الشاشات الحساسة (الرصيد، الـ OTP، الكروت) ممكن تتصور screenshot أو تتسجل أو تظهر في صورة الـ app switcher.'),
        fix: Bilingual(
            'Set FLAG_SECURE on Android (e.g. screen_protector or freeRASP blockScreenCapture) and hide content in the iOS app switcher.',
            'فعّل FLAG_SECURE على Android (مثلاً بـ screen_protector أو blockScreenCapture بتاع freeRASP)، وخبّي المحتوى في الـ app switcher على iOS.'),
        severity: Severity.low,
        masvs: ['MASVS-PLATFORM-3'],
        maswe: ['MASWE-0038'],
        cwe: 'CWE-200',
        profiles: _l2,
      );

  static const _packages = [
    'screen_protector',
    'flutter_windowmanager',
    'flutter_windowmanager_plus',
    'no_screenshot',
    'secure_application',
    'flutter_prevent_screenshot',
    'screen_capture_event',
  ];

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    if (!project.isFlutterApp) return RuleCheck.notApplicable();
    if (_packages.any(project.usesPackage)) return RuleCheck([]);
    if (project.androidNativeSources.any((s) => s.text.contains('FLAG_SECURE'))) {
      return RuleCheck([]);
    }
    for (final f in project.dartFiles) {
      if (f.source.contains('blockScreenCapture') ||
          f.source.contains('ScreenShield') ||
          f.source.contains('FLAG_SECURE')) {
        return RuleCheck([]);
      }
    }
    return RuleCheck([
      inFile(null, null, 'No screen capture protection found.',
          messageAr: 'مفيش أي حماية من تصوير الشاشة.')
    ]);
  }
}

class ObfuscationBuildRule extends Rule {
  const ObfuscationBuildRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-P10',
        title: Bilingual('Release builds without --obfuscate', 'بيلد الـ release من غير --obfuscate'),
        description: Bilingual(
            'Without --obfuscate, class and method names in libapp.so are readable, which makes finding and patching your security checks easy.',
            'من غير --obfuscate، أسماء الكلاسات والـ methods في libapp.so بتبقى مقروءة، وده بيسهّل إن حد يلاقي فحوصات الأمان ويعطلها.'),
        fix: Bilingual(
            'Build releases with --obfuscate --split-debug-info=build/symbols and keep the symbols to read crash reports.',
            'اعمل بيلد الـ release بـ --obfuscate --split-debug-info=build/symbols، واحتفظ بالـ symbols عشان تقرا تقارير الـ crash.'),
        severity: Severity.medium,
        masvs: ['MASVS-RESILIENCE-3'],
        maswe: ['MASWE-0059'],
        cwe: 'CWE-656',
        profiles: _r,
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final re = RegExp(r'flutter\s+build\s+(apk|appbundle|aab|ipa|ios)\b[^\n]*');
    final out = <Finding>[];
    var found = false;
    for (final s in project.buildScripts) {
      // Join shell line continuations so flags on the next line count.
      final text = s.text.replaceAll(RegExp(r'\\\r?\n\s*'), ' ');
      for (final m in re.allMatches(text)) {
        found = true;
        if (!m.group(0)!.contains('--obfuscate')) {
          final head = m.group(0)!;
          final key = head.length > 18 ? head.substring(0, 18) : head;
          final line = lineOfFirst(s.text, key) ?? lineAt(text, m.start);
          out.add(inFile(s.path, line, '"${shorten(m.group(0)!.trim(), 70)}" has no --obfuscate.',
              messageAr: '"${shorten(m.group(0)!.trim(), 70)}" من غير --obfuscate.'));
        }
      }
    }
    if (!found) {
      return RuleCheck.notApplicable('No release build command found in CI files (see manual check AEG-M05)');
    }
    return RuleCheck(out);
  }
}

const protectionRules = <Rule>[
  RaspPresenceRule(),
  FreeRaspWiringRule(),
  FreeRaspConfigRule(),
  FreeRaspReactionRule(),
  AppCheckMissingRule(),
  AppCheckDebugProviderRule(),
  PinningRule(),
  LocalAuthRule(),
  ScreenProtectionRule(),
  ObfuscationBuildRule(),
];
