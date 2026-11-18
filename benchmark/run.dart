/// Audits public, intentionally vulnerable apps and compares the result with
/// what aegis is expected to find in each (benchmark/apps.yaml).
///
///     dart run benchmark/run.dart                 # every app
///     dart run benchmark/run.dart --app dvma      # one app
///     dart run benchmark/run.dart --update        # save the results as the
///                                                 # snapshot regressions are
///                                                 # measured against
///
/// Apps are downloaded at the pinned commit into ~/.cache/aegis-benchmark
/// (or AEGIS_BENCHMARK_CACHE), outside the repository. Each app keeps its own license; nothing from
/// them is copied into aegis. Exits with code 1 when an expected finding is
/// missing or a rule that failed in the snapshot no longer does.
library;

import 'dart:convert';
import 'dart:io';

import 'package:aegis/aegis.dart';
import 'package:crypto/crypto.dart';
import 'package:aegis/src/util.dart' show globToRegExp;
import 'package:path/path.dart' as p;
import 'package:yaml/yaml.dart';

final _here = p.dirname(p.fromUri(Platform.script));

/// Downloads live outside the repository, so audits of aegis itself and its
/// tests never see the apps' code.
final _cache = Platform.environment['AEGIS_BENCHMARK_CACHE'] ??
    p.join(Platform.environment['HOME'] ?? Directory.systemTemp.path, '.cache',
        'aegis-benchmark');
final _snapshotFile = p.join(_here, 'results.json');

class App {
  App(this.name, Map m, Map all)
      : from = m['from'] as String?,
        url = m['url'] as String?,
        sha256 = m['sha256'] as String?,
        repo = (m['repo'] ?? (all[m['from']] as Map?)?['repo'] ?? '') as String,
        commit = (m['commit'] ?? (all[m['from']] as Map?)?['commit'] ?? '')
            as String,
        path = (m['path'] ?? '') as String,
        sparse = [
          for (final s in (m['sparse'] ??
              (all[m['from']] as Map?)?['sparse'] ??
              const []) as List)
            '$s'
        ],
        apk = m['apk'] as String?,
        ipa = m['ipa'] as String?,
        units = m['units'] as String?,
        clean = m['clean'] == true,
        allowed = {
          for (final e in (m['allowed'] ?? const []) as List)
            (e as Map)['rule'] as String: (e['why'] ?? '') as String
        },
        expected = {
          for (final e in (m['expected'] ?? const []) as List)
            (e as Map)['rule'] as String: (e['why'] ?? '') as String
        };

  final String name;

  /// Another app whose download this one reuses.
  final String? from;

  /// A released binary to download instead of the source, checked against
  /// [sha256].
  final String? url;
  final String? sha256;
  final String repo;
  final String commit;
  final String path;
  final List<String> sparse;

  /// An APK or IPA in the download to audit on its own, without source.
  final String? apk;
  final String? ipa;

  /// A glob of folders that each hold one planted weakness (MASTG demos):
  /// the run lists the ones without any finding.
  final String? units;

  /// A well-kept app: every rule that fails must be listed in [allowed],
  /// so a new false positive fails the benchmark.
  final bool clean;
  final Map<String, String> allowed;
  final Map<String, String> expected;

  String get dir =>
      url != null ? p.join(_cache, 'releases') : p.join(_cache, from ?? name);
}

Future<void> main(List<String> argv) async {
  final only = argv.contains('--app') ? argv[argv.indexOf('--app') + 1] : null;
  final update = argv.contains('--update');
  final doc =
      loadYaml(File(p.join(_here, 'apps.yaml')).readAsStringSync()) as Map;
  final all = doc['apps'] as Map;
  final apps = [
    for (final e in all.entries)
      if (only == null || e.key == only)
        App(e.key as String, e.value as Map, all)
  ];
  if (apps.isEmpty) {
    stderr.writeln('No app named $only in benchmark/apps.yaml.');
    exit(2);
  }
  final snapshot = File(_snapshotFile).existsSync()
      ? jsonDecode(File(_snapshotFile).readAsStringSync()) as Map
      : <String, Object?>{};
  final results = <String, Object?>{...snapshot};
  var expectedTotal = 0, found = 0;
  final problems = <String>[];

  for (final app in apps) {
    if (app.url != null) {
      _fetch(app);
    } else {
      _download(
          app.from == null ? app : App(app.from!, all[app.from] as Map, all));
    }
    final artifact = app.apk != null || app.ipa != null;
    // An artifact is audited on its own, from an empty folder.
    final empty =
        artifact ? Directory.systemTemp.createTempSync('aegis_') : null;
    final root = empty?.path ?? p.join(app.dir, app.path);
    final report = await runAudit(root,
        offline: true,
        apkPath: app.apk == null ? null : p.join(app.dir, app.apk!),
        ipaPath: app.ipa == null ? null : p.join(app.dir, app.ipa!));
    empty?.deleteSync(recursive: true);
    // Every report format must render (the JSON alone hid a crash in the
    // HTML evidence view until 0.17.2).
    for (final lang in const ['en', 'ar']) {
      try {
        renderHtml(report, lang: lang);
        renderMarkdown(report, lang: lang);
        ConsoleReporter(lang: lang, color: false).render(report);
        renderSarif(report);
        renderJson(report);
      } catch (e) {
        stdout.writeln('  report failed to render ($lang): $e');
        problems.add('${app.name}: report failed to render ($lang)');
      }
    }
    final failed = {
      for (final r in report.failed) r.meta.id: r.findings.length,
    };
    final hit = app.expected.keys.where(failed.containsKey).toList();
    final missed = app.expected.keys.where((k) => !failed.containsKey(k));
    expectedTotal += app.expected.length;
    found += hit.length;
    final before = (snapshot[app.name] as Map?)?['failed'] as Map?;
    final lost = before == null
        ? const <String>[]
        : [
            for (final id in before.keys)
              if (!failed.containsKey(id)) id as String
          ];
    final gained = before == null
        ? const <String>[]
        : [
            for (final id in failed.keys)
              if (!before.containsKey(id)) id
          ];
    stdout.writeln('${app.name}: ${hit.length}/${app.expected.length} expected'
        ' · score ${report.score.value} · ${failed.length} rules failed');
    List<String>? covered;
    if (app.units != null) {
      final glob = globToRegExp(app.units!);
      final units = [
        for (final e in Directory(root).listSync(recursive: true))
          if (e is Directory && glob.hasMatch(p.relative(e.path, from: root)))
            p.relative(e.path, from: root)
      ]..sort();
      final files = {
        for (final r in report.failed)
          for (final f in r.findings)
            if (f.file != null) f.file!
      };
      covered = [
        for (final u in units)
          if (files.any((f) => f.startsWith('$u/'))) u
      ];
      stdout
          .writeln('  ${covered.length}/${units.length} units have a finding');
      final before =
          ((snapshot[app.name] as Map?)?['covered'] as List?)?.toSet();
      for (final u in units) {
        if (covered.contains(u)) continue;
        final lost = before?.contains(u) ?? false;
        stdout.writeln(
            '  ${lost ? 'lost  ' : 'none  '}  $u  ${_title(p.join(root, u))}');
        if (lost) problems.add('${app.name}: $u no longer has a finding');
      }
    }
    for (final id in missed) {
      stdout.writeln('  missed   $id  ${app.expected[id]}');
      problems.add('${app.name}: missed $id');
    }
    for (final id in lost) {
      stdout.writeln('  stopped  $id  (failed in the snapshot)');
      problems.add('${app.name}: $id no longer fails');
    }
    for (final id in gained) {
      stdout.writeln('  new      $id  (${failed[id]} findings; review it)');
    }
    if (app.clean) {
      for (final id in failed.keys) {
        if (app.allowed.containsKey(id) || app.expected.containsKey(id)) {
          continue;
        }
        stdout.writeln(
            '  unexpected  $id  (${failed[id]} findings in a clean app)');
        for (final r in report.failed.where((r) => r.meta.id == id)) {
          for (final f in r.findings.take(3)) {
            stdout.writeln('      ${f.location}  ${f.message}');
          }
        }
        problems.add('${app.name}: unexpected $id');
      }
    }
    results[app.name] = {
      'commit': app.commit,
      'score': report.score.value,
      if (covered != null) 'covered': covered,
      'failed': Map.fromEntries(
          failed.entries.toList()..sort((a, b) => a.key.compareTo(b.key))),
    };
  }

  final rate = expectedTotal == 0 ? 100 : (found * 100 / expectedTotal).round();
  stdout.writeln('\nDetection rate: $found/$expectedTotal ($rate%)');
  if (update) {
    File(_snapshotFile).writeAsStringSync(
        '${const JsonEncoder.withIndent('  ').convert(results)}\n');
    stdout.writeln('Snapshot written to benchmark/results.json.');
  }
  if (problems.isNotEmpty && !update) exit(1);
}

/// Downloads the released binary of [app] once and checks its hash.
void _fetch(App app) {
  final file = File(p.join(app.dir, app.apk ?? app.ipa!));
  String hash() => sha256.convert(file.readAsBytesSync()).toString();
  if (file.existsSync() && hash() == app.sha256) return;
  stdout.writeln('Downloading ${app.url}…');
  file.parent.createSync(recursive: true);
  final r = Process.runSync('curl', ['-sSfL', '-o', file.path, app.url!]);
  if (r.exitCode != 0) {
    stderr.writeln('Download failed: ${r.stderr}');
    exit(2);
  }
  if (hash() != app.sha256) {
    file.deleteSync();
    stderr.writeln('${app.url} does not match its sha256 in apps.yaml.');
    exit(2);
  }
}

/// The `title:` of the Markdown file describing a MASTG demo.
String _title(String dir) {
  for (final e in Directory(dir).listSync()) {
    if (e is File && e.path.endsWith('.md')) {
      final m = RegExp(r'^title:\s*(.+)$', multiLine: true)
          .firstMatch(e.readAsStringSync());
      if (m != null) return m[1]!.trim();
    }
  }
  return '';
}

/// Fetches [app] at its pinned commit, only once.
void _download(App app) {
  final marker = File(p.join(app.dir, '.aegis-commit'));
  if (marker.existsSync() && marker.readAsStringSync().trim() == app.commit) {
    return;
  }
  stdout.writeln('Downloading ${app.repo} at ${app.commit.substring(0, 12)}…');
  final dir = Directory(app.dir);
  if (dir.existsSync()) dir.deleteSync(recursive: true);
  dir.createSync(recursive: true);
  void git(List<String> args) {
    final r = Process.runSync('git', args, workingDirectory: app.dir);
    if (r.exitCode != 0) {
      stderr.writeln('git ${args.join(' ')} failed:\n${r.stderr}');
      exit(2);
    }
  }

  git(['init', '-q']);
  git(['remote', 'add', 'origin', 'https://github.com/${app.repo}.git']);
  if (app.sparse.isNotEmpty) {
    git(['sparse-checkout', 'set', '--no-cone', ...app.sparse]);
  }
  git([
    '-c', 'advice.detachedHead=false', 'fetch', '-q', '--depth', '1', //
    '--filter=blob:none', 'origin', app.commit,
  ]);
  git(['-c', 'advice.detachedHead=false', 'checkout', '-q', 'FETCH_HEAD']);
  marker.writeAsStringSync(app.commit);
}
