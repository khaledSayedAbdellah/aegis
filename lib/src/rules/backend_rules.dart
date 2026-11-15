/// Rules for the app's backend configuration kept in the repository:
/// Firebase security rules for Cloud Firestore, Cloud Storage and the
/// Realtime Database.
library;

import 'dart:convert';
import 'dart:io';

import 'package:path/path.dart' as p;

import '../l10n/messages.g.dart';
import '../model.dart';
import '../project.dart';
import '../project/native_files.dart' show nativeIgnoredDirectories;
import 'rule.dart';

const _all = {MasProfile.l1, MasProfile.l2, MasProfile.r};

/// One `allow` statement, or one `.read`/`.write` of the Realtime Database.
class FirebaseGrant {
  FirebaseGrant(this.service, this.file, this.line, this.path, this.ops,
      this.condition, this.text);

  /// `Cloud Firestore`, `Cloud Storage` or `Realtime Database`.
  final String service;
  final String file;
  final int line;

  /// The match path below the service root (`/{document=**}`,
  /// `/users/{uid}`), or the JSON path for the Realtime Database (`/`).
  final String path;

  /// `read`, `write` or both.
  final Set<String> ops;

  /// The condition without spaces; empty when the statement has none.
  final String condition;

  /// The statement as written, for the message.
  final String text;

  bool get everything =>
      path == '/' || RegExp(r'^/\{\w+=\*\*\}$').hasMatch(path);

  bool get public => condition.isEmpty || condition == 'true' || until != null;

  /// For the test-mode rule `request.time < timestamp.date(y, m, d)`: that
  /// date. Null for other conditions.
  DateTime? get until {
    final m = RegExp(
            r'^request\.time<timestamp\.date\((\d{4}),(\d{1,2}),(\d{1,2})\)$')
        .firstMatch(condition);
    if (m == null) return null;
    return DateTime.utc(int.parse(m[1]!), int.parse(m[2]!), int.parse(m[3]!));
  }

  bool get anySignedIn => const {
        'request.auth!=null',
        'null!=request.auth',
        'request.auth.uid!=null',
        'auth!=null',
        'null!=auth',
      }.contains(condition);
}

class FirebaseRules {
  final List<FirebaseGrant> grants = [];
  final List<String> files = [];
  final List<(String file, String reason)> unreadable = [];
}

/// Finds and parses the Firebase rules files of [project]: those named in
/// `firebase.json`, and files with the standard names near the root.
FirebaseRules readFirebaseRules(Project project) {
  final out = FirebaseRules();
  final paths = <String, String>{}; // relative path -> service
  void add(Object? rules, String service, String base) {
    if (rules is! String || rules.isEmpty) return;
    paths[p.normalize(p.join(base, rules))] = service;
  }

  for (final config in _find(project.root, {'firebase.json'})) {
    final base = p.dirname(project.rel(config.path));
    Object? json;
    try {
      json = jsonDecode(config.readAsStringSync());
    } catch (_) {
      out.unreadable.add((project.rel(config.path), 'not valid JSON'));
      continue;
    }
    if (json is! Map) continue;
    for (final (key, service) in const [
      ('firestore', 'Cloud Firestore'),
      ('storage', 'Cloud Storage'),
      ('database', 'Realtime Database'),
    ]) {
      final entry = json[key];
      for (final e in entry is List ? entry : [entry]) {
        if (e is Map) add(e['rules'], service, base);
      }
    }
  }
  for (final f in _find(project.root,
      {'firestore.rules', 'storage.rules', 'database.rules.json'})) {
    final name = p.basename(f.path);
    paths.putIfAbsent(
        project.rel(f.path),
        () => name == 'firestore.rules'
            ? 'Cloud Firestore'
            : name == 'storage.rules'
                ? 'Cloud Storage'
                : 'Realtime Database');
  }

  for (final e in paths.entries) {
    final file = File(project.abs(e.key));
    if (!file.existsSync()) continue;
    if (project.config.isExcluded(e.key)) continue;
    final String text;
    try {
      text = file.readAsStringSync();
    } catch (_) {
      out.unreadable.add((e.key, 'not readable'));
      continue;
    }
    out.files.add(e.key);
    if (e.value == 'Realtime Database') {
      _database(e.key, text, out);
    } else {
      out.grants.addAll(parseSecurityRules(e.value, e.key, text));
    }
  }
  return out;
}

/// Files named [names] within three folders of [root].
List<File> _find(String root, Set<String> names) {
  final out = <File>[];
  void visit(Directory dir, int depth) {
    final List<FileSystemEntity> entries;
    try {
      entries = dir.listSync(followLinks: false)
        ..sort((a, b) => a.path.compareTo(b.path));
    } on FileSystemException {
      return;
    }
    for (final e in entries) {
      final name = p.basename(e.path);
      if (e is File && names.contains(name)) out.add(e);
      if (e is Directory &&
          depth < 3 &&
          !nativeIgnoredDirectories.contains(name) &&
          !const {'node_modules', 'Pods', 'build', 'functions'}
              .contains(name)) {
        visit(e, depth + 1);
      }
    }
  }

  visit(Directory(root), 0);
  return out;
}

/// Replaces comments with spaces, keeping offsets and line numbers.
String _withoutComments(String text) => text.replaceAllMapped(
    RegExp(r'//[^\n]*|/\*[\s\S]*?\*/'),
    (m) => m[0]!.replaceAll(RegExp(r'[^\n]'), ' '));

/// The `allow` statements of a Firestore or Storage rules file, with the
/// match path each applies to.
List<FirebaseGrant> parseSecurityRules(
    String service, String file, String source) {
  final text = _withoutComments(source);
  final out = <FirebaseGrant>[];
  final stack = <String>[]; // path segment per open block ('' when not a match)
  final token = RegExp(
      r'\bmatch\s+(\S+)\s*\{|\ballow\s+([a-z,\s]+?)\s*(?::\s*if\s+([^;]*?))?\s*;|\{|\}');
  for (final m in token.allMatches(text)) {
    final t = m[0]!;
    if (t.startsWith('match')) {
      stack.add(m[1]!);
    } else if (t.startsWith('allow')) {
      final full = stack.join();
      final path = full
          .replaceFirst(RegExp(r'^/databases/\{[^}]+\}/documents'), '')
          .replaceFirst(RegExp(r'^/b/\{[^}]+\}/o'), '');
      final ops = <String>{
        for (final op in m[2]!.split(RegExp(r'[\s,]+')))
          if (const {'read', 'get', 'list'}.contains(op))
            'read'
          else if (const {'write', 'create', 'update', 'delete'}.contains(op))
            'write'
      };
      if (ops.isEmpty) continue;
      out.add(FirebaseGrant(
          service,
          file,
          '\n'.allMatches(text.substring(0, m.start)).length + 1,
          path.isEmpty ? '/' : path,
          ops,
          _condition(m[3] ?? ''),
          t.replaceAll(RegExp(r'\s+'), ' ').trim()));
    } else if (t == '{') {
      stack.add('');
    } else if (t == '}' && stack.isNotEmpty) {
      stack.removeLast();
    }
  }
  return out;
}

String _condition(String c) {
  var s = c.replaceAll(RegExp(r'\s+'), '');
  while (s.startsWith('(') &&
      s.endsWith(')') &&
      _balanced(s.substring(1, s.length - 1))) {
    s = s.substring(1, s.length - 1);
  }
  return s;
}

bool _balanced(String s) {
  var depth = 0;
  for (final c in s.codeUnits) {
    if (c == 0x28) depth++;
    if (c == 0x29 && --depth < 0) return false;
  }
  return depth == 0;
}

/// `.read` and `.write` rules of a Realtime Database rules file.
void _database(String file, String source, FirebaseRules out) {
  final text = _withoutComments(source);
  Object? json;
  try {
    json = jsonDecode(text);
  } catch (_) {
    out.unreadable.add((file, 'not valid JSON'));
    return;
  }
  final rules = json is Map ? json['rules'] : null;
  if (rules is! Map) return;
  int lineOf(String key) {
    final i = text.indexOf('"$key"');
    return i < 0 ? 1 : '\n'.allMatches(text.substring(0, i)).length + 1;
  }

  void visit(Map node, String path) {
    for (final e in node.entries) {
      final key = e.key.toString();
      if (key == '.read' || key == '.write') {
        final v = e.value;
        final condition = v == true || v == 'true'
            ? 'true'
            : v is String
                ? _condition(v)
                : 'false';
        out.grants.add(FirebaseGrant('Realtime Database', file, lineOf(key),
            path, {key.substring(1)}, condition, '"$key": ${jsonEncode(v)}'));
      } else if (e.value is Map && !key.startsWith('.')) {
        visit(e.value as Map, '${path == '/' ? '' : path}/$key');
      }
    }
  }

  visit(rules, '/');
}

String _access(Set<String> ops) =>
    ops.length == 2 ? 'read and write' : ops.single;

String _accessAr(Set<String> ops) => ops.length == 2
    ? 'يقرا ويكتب'
    : ops.single == 'read'
        ? 'يقرا'
        : 'يكتب';

/// Services whose rules matter when the app uses them.
List<String> _usedServices(Project project) {
  String? packageJson;
  try {
    final f = File(project.abs('package.json'));
    if (f.existsSync()) packageJson = f.readAsStringSync();
  } catch (_) {}
  bool uses(String dart, String npm) =>
      project.usesPackage(dart) || (packageJson?.contains(npm) ?? false);
  return [
    if (uses('cloud_firestore', '@react-native-firebase/firestore'))
      'Cloud Firestore',
    if (uses('firebase_storage', '@react-native-firebase/storage'))
      'Cloud Storage',
    if (uses('firebase_database', '@react-native-firebase/database'))
      'Realtime Database',
  ];
}

class FirebasePublicRulesRule extends Rule {
  const FirebasePublicRulesRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-P12',
        title: Bilingual(En.backendPublicTitle, Ar.backendPublicTitle),
        passTitleText: Bilingual(En.backendPublicPass, Ar.backendPublicPass),
        description:
            Bilingual(En.backendPublicDescription, Ar.backendPublicDescription),
        fix: Bilingual(En.backendPublicFix, Ar.backendPublicFix),
        severity: Severity.critical,
        masvs: ['MASVS-AUTH-1'],
        cwe: 'CWE-862',
        profiles: _all,
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final rules = readFirebaseRules(project);
    if (rules.files.isEmpty) {
      final used = _usedServices(project);
      if (used.isEmpty) return RuleCheck.notApplicable();
      final names = used.join(', ');
      return RuleCheck.evidenceOnly(En.backendRulesMissing(services: names),
          Ar.backendRulesMissing(services: names));
    }
    final now = DateTime.now().toUtc();
    final out = <Finding>[];
    for (final g in rules.grants) {
      if (!g.everything || !g.public) continue;
      final until = g.until;
      if (until != null && !until.isAfter(now)) continue;
      final (en, ar) = until != null
          ? (
              En.backendPublicUntil(
                  service: g.service,
                  access: _access(g.ops),
                  date: until.toIso8601String().substring(0, 10),
                  rule: g.text),
              Ar.backendPublicUntil(
                  service: g.service,
                  access: _accessAr(g.ops),
                  date: until.toIso8601String().substring(0, 10),
                  rule: g.text)
            )
          : (
              En.backendPublic(
                  service: g.service, access: _access(g.ops), rule: g.text),
              Ar.backendPublic(
                  service: g.service, access: _accessAr(g.ops), rule: g.text)
            );
      out.add(inFile(g.file, g.line, en, messageAr: ar));
    }
    return _withUnreadable(out, rules);
  }
}

class FirebaseBroadRulesRule extends Rule {
  const FirebaseBroadRulesRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-P15',
        title: Bilingual(En.backendBroadTitle, Ar.backendBroadTitle),
        passTitleText: Bilingual(En.backendBroadPass, Ar.backendBroadPass),
        description:
            Bilingual(En.backendBroadDescription, Ar.backendBroadDescription),
        fix: Bilingual(En.backendBroadFix, Ar.backendBroadFix),
        severity: Severity.medium,
        l2Severity: Severity.high,
        masvs: ['MASVS-AUTH-1'],
        cwe: 'CWE-285',
        profiles: _all,
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final rules = readFirebaseRules(project);
    if (rules.files.isEmpty) return RuleCheck.notApplicable();
    final now = DateTime.now().toUtc();
    final out = <Finding>[];
    for (final g in rules.grants) {
      if (g.everything && g.anySignedIn) {
        out.add(inFile(
            g.file,
            g.line,
            En.backendAnyUser(
                service: g.service, access: _access(g.ops), rule: g.text),
            messageAr: Ar.backendAnyUser(
                service: g.service, access: _accessAr(g.ops), rule: g.text)));
      } else if (!g.everything && g.public && g.ops.contains('write')) {
        final until = g.until;
        if (until != null && !until.isAfter(now)) continue;
        out.add(inFile(
            g.file,
            g.line,
            En.backendPublicWrite(
                service: g.service, path: g.path, rule: g.text),
            messageAr: Ar.backendPublicWrite(
                service: g.service, path: g.path, rule: g.text)));
      }
    }
    return _withUnreadable(out, rules);
  }
}

RuleCheck _withUnreadable(List<Finding> out, FirebaseRules rules) {
  if (rules.unreadable.isEmpty) return RuleCheck(out);
  final files = rules.unreadable.map((u) => '${u.$1} (${u.$2})').join(', ');
  return RuleCheck.incompleteLocalized(En.backendRulesUnreadable(files: files),
      Ar.backendRulesUnreadable(files: files), out);
}

const backendRules = <Rule>[
  FirebasePublicRulesRule(),
  FirebaseBroadRulesRule(),
];
