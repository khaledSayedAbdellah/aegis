/// Rules a team writes in `aegis.yaml` under `custom_rules:`.
///
/// ```yaml
/// custom_rules:
///   - id: X-HTTP-URL
///     title: Plain HTTP URL in the app
///     severity: medium
///     files: ["lib/**/*.dart"]
///     pattern: "http://(?!localhost)"
///     message: "Plain HTTP URL: {match}"
///     fix: Use https.
///   - id: X-LAUNCH-EXTERNAL
///     title: Links opened outside the app
///     severity: low
///     call: launchUrl
///     args:
///       - name: mode
///         matches: externalApplication
///     message: "{call}() opens the link in another app."
///     fix: Open links in the in-app browser.
/// ```
library;

import 'dart:io';

import 'package:path/path.dart' as p;

import '../dart_scanner.dart';
import '../model.dart';
import '../project.dart';
import '../util.dart';
import 'rule.dart';

/// One condition on an argument of a `call:` rule.
class ArgCondition {
  ArgCondition(
      {this.index,
      this.name,
      this.matches,
      this.notMatches,
      this.absent = false});

  /// Position among the positional arguments, from 0.
  final int? index;

  /// Name of a named argument.
  final String? name;

  /// The argument's source text must match.
  final RegExp? matches;

  /// The argument's source text must not match.
  final RegExp? notMatches;

  /// The argument must be missing.
  final bool absent;
}

class CustomRuleSpec {
  CustomRuleSpec({
    required this.id,
    required this.title,
    required this.severity,
    required this.message,
    required this.fix,
    this.titleAr,
    this.messageAr,
    this.fixAr,
    this.description,
    this.files = const [],
    this.pattern,
    this.call,
    this.receiver,
    this.args = const [],
    this.masvs = const [],
    this.cwe,
  });

  final String id;
  final String title;
  final String? titleAr;
  final Severity severity;
  final String message;
  final String? messageAr;
  final String fix;
  final String? fixAr;
  final String? description;

  /// Globs relative to the project root; empty means the default.
  final List<String> files;
  final RegExp? pattern;
  final String? call;
  final RegExp? receiver;
  final List<ArgCondition> args;
  final List<String> masvs;
  final String? cwe;

  static final _id = RegExp(r'^X-[A-Z0-9][A-Z0-9_-]*$');

  /// Reads the `custom_rules:` list of aegis.yaml.
  static List<CustomRuleSpec> parseAll(Object? value) {
    if (value == null) return const [];
    if (value is! List) {
      throw const FormatException('custom_rules must be a list.');
    }
    final out = <CustomRuleSpec>[];
    final ids = <String>{};
    for (final (i, e) in value.indexed) {
      if (e is! Map) {
        throw FormatException('custom_rules[$i] must be a map.');
      }
      final spec = parse(e, i);
      if (!ids.add(spec.id)) {
        throw FormatException('custom_rules: ${spec.id} is defined twice.');
      }
      out.add(spec);
    }
    return out;
  }

  static CustomRuleSpec parse(Map e, int i) {
    final id = e['id']?.toString().trim().toUpperCase() ?? '';
    final where = id.isEmpty ? 'custom_rules[$i]' : 'custom_rules $id';
    if (!_id.hasMatch(id)) {
      throw FormatException(
          '$where: id must start with X- and use letters, digits, - or _ (for example X-HTTP-URL).');
    }
    String need(String key) {
      final v = e[key]?.toString().trim();
      if (v == null || v.isEmpty) {
        throw FormatException('$where: $key is required.');
      }
      return v;
    }

    String? opt(String key) {
      final v = e[key]?.toString().trim();
      return v == null || v.isEmpty ? null : v;
    }

    RegExp? regex(Object? v, String key) {
      if (v == null) return null;
      try {
        return RegExp(v.toString(), multiLine: true);
      } on FormatException catch (x) {
        throw FormatException(
            '$where: $key is not a valid regex: ${x.message}');
      }
    }

    final severity = Severity.tryParse(need('severity'));
    if (severity == null) {
      throw FormatException(
          '$where: severity must be critical, high, medium, low or info.');
    }
    final pattern = regex(e['pattern'], 'pattern');
    final call = opt('call');
    if ((pattern == null) == (call == null)) {
      throw FormatException('$where: give either pattern or call.');
    }
    List<String> list(Object? v) => v == null
        ? const []
        : v is List
            ? [for (final x in v) x.toString()]
            : [v.toString()];
    final args = <ArgCondition>[];
    final rawArgs = e['args'];
    if (rawArgs != null) {
      if (call == null) throw FormatException('$where: args needs call.');
      if (rawArgs is! List) {
        throw FormatException('$where: args must be a list.');
      }
      for (final a in rawArgs) {
        if (a is! Map) {
          throw FormatException('$where: each of args must be a map.');
        }
        final index = a['index'] == null ? null : int.tryParse('${a['index']}');
        final name = a['name']?.toString();
        if ((index == null) == (name == null)) {
          throw FormatException('$where: each of args needs index or name.');
        }
        final absent = a['absent'] == true;
        final matches = regex(a['matches'], 'args.matches');
        final notMatches = regex(a['not_matches'], 'args.not_matches');
        if (!absent && matches == null && notMatches == null) {
          throw FormatException(
              '$where: each of args needs matches, not_matches or absent: true.');
        }
        args.add(ArgCondition(
            index: index,
            name: name,
            matches: matches,
            notMatches: notMatches,
            absent: absent));
      }
    }
    return CustomRuleSpec(
      id: id,
      title: need('title'),
      titleAr: opt('title_ar'),
      severity: severity,
      message: need('message'),
      messageAr: opt('message_ar'),
      fix: need('fix'),
      fixAr: opt('fix_ar'),
      description: opt('description'),
      files: list(e['files']),
      pattern: pattern,
      call: call,
      receiver: regex(e['receiver'], 'receiver'),
      args: args,
      masvs: [for (final m in list(e['masvs'])) m.toUpperCase()],
      cwe: opt('cwe'),
    );
  }
}

/// Folders a `pattern:` rule never reads.
final _skippedDir = RegExp(
    r'(?:^|/)(?:build|\.dart_tool|\.git|node_modules|Pods|\.gradle|\.idea|DerivedData)/');

class CustomRule extends Rule {
  CustomRule(this.spec);

  final CustomRuleSpec spec;

  @override
  RuleMeta get meta => RuleMeta(
        id: spec.id,
        title: Bilingual(spec.title, spec.titleAr ?? spec.title),
        passTitleText: Bilingual(spec.title, spec.titleAr ?? spec.title),
        description: Bilingual(spec.description ?? spec.message,
            spec.description ?? spec.messageAr ?? spec.message),
        fix: Bilingual(spec.fix, spec.fixAr ?? spec.fix),
        severity: spec.severity,
        masvs: spec.masvs,
        cwe: spec.cwe,
        profiles: const {MasProfile.l1, MasProfile.l2, MasProfile.r},
      );

  late final List<RegExp> _globs = [
    for (final g in spec.files.isEmpty
        ? [spec.call != null ? '**/*.dart' : '**']
        : spec.files)
      globToRegExp(g)
  ];

  bool _wanted(String rel) => _globs.any((g) => g.hasMatch(rel));

  String _text(String template, Map<String, String> values) => template
      .replaceAllMapped(RegExp(r'\{(\w+)\}'), (m) => values[m[1]] ?? m[0]!);

  Finding _finding(String file, int line, Map<String, String> values) =>
      inFile(file, line, _text(spec.message, values),
          messageAr:
              spec.messageAr == null ? null : _text(spec.messageAr!, values));

  @override
  RuleCheck check(Project project, ProfileSet profile) =>
      RuleCheck(spec.call != null ? _calls(project) : _pattern(project));

  List<Finding> _calls(Project project) {
    final out = <Finding>[];
    for (final f in project.dartFiles) {
      if (!_wanted(f.path)) continue;
      for (final c in f.calls({spec.call!})) {
        if (spec.receiver != null &&
            !spec.receiver!.hasMatch(c.receivers.reversed.join('.'))) {
          continue;
        }
        final args = f.args(c.open);
        if (!spec.args.every((a) => _holds(f, args, a))) continue;
        out.add(_finding(f.path, f.lineOfToken(c.nameIndex), {
          'call': c.name,
          'match': shorten(f.text(c.nameIndex, c.close), 80),
        }));
      }
    }
    return out;
  }

  bool _holds(DartFile f, List<Arg> args, ArgCondition a) {
    final Arg? arg;
    if (a.name != null) {
      arg = f.namedArg(args, a.name!);
    } else {
      final positional = args.where((x) => x.name == null).toList();
      arg = a.index! < positional.length ? positional[a.index!] : null;
    }
    if (a.absent) return arg == null;
    if (arg == null) return false;
    final text = f.text(arg.start, arg.end);
    if (a.matches != null && !a.matches!.hasMatch(text)) return false;
    if (a.notMatches != null && a.notMatches!.hasMatch(text)) return false;
    return true;
  }

  List<Finding> _pattern(Project project) {
    final out = <Finding>[];
    final files = project.findFiles(
        '', (rel) => !_skippedDir.hasMatch(rel) && _wanted(rel));
    for (final rel in files..sort()) {
      final file = File(p.join(project.root, rel));
      String text;
      try {
        if (file.lengthSync() > 2 * 1024 * 1024) continue;
        text = file.readAsStringSync();
      } on FileSystemException {
        continue;
      } on FormatException {
        continue; // Not text.
      }
      if (text.contains('\u0000')) continue;
      final lineStarts = [0];
      for (var i = 0; i < text.length; i++) {
        if (text.codeUnitAt(i) == 0x0A) lineStarts.add(i + 1);
      }
      int lineOf(int offset) {
        var lo = 0, hi = lineStarts.length - 1;
        while (lo < hi) {
          final mid = (lo + hi + 1) >> 1;
          if (lineStarts[mid] <= offset) {
            lo = mid;
          } else {
            hi = mid - 1;
          }
        }
        return lo + 1;
      }

      for (final m in spec.pattern!.allMatches(text)) {
        out.add(_finding(rel, lineOf(m.start),
            {'match': shorten(m[0]!.trim(), 80), 'file': rel}));
        if (out.length >= 500) return out;
      }
    }
    return out;
  }
}
