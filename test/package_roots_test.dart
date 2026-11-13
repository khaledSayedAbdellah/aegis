import 'dart:convert';
import 'dart:io';

import 'package:aegis/src/project/package_roots.dart';
import 'package:path/path.dart' as p;
import 'package:test/test.dart';

void main() {
  late Directory root;
  late Directory cache;
  void put(String path, String text, {Directory? under}) =>
      File(p.join((under ?? root).path, path))
        ..parent.createSync(recursive: true)
        ..writeAsStringSync(text);

  void config(Map<String, String> packages) => put(
      '.dart_tool/package_config.json',
      jsonEncode({
        'configVersion': 2,
        'packages': [
          for (final e in packages.entries)
            {
              'name': e.key,
              'rootUri': Uri.directory(e.value).toString(),
              'packageUri': 'lib/'
            }
        ],
      }));

  setUp(() {
    root = Directory.systemTemp.createTempSync('aegis-roots-');
    cache = Directory.systemTemp.createTempSync('aegis-pub-cache-');
    addTearDown(() => root.deleteSync(recursive: true));
    addTearDown(() => cache.deleteSync(recursive: true));
    put('pubspec.yaml',
        'name: app\ndependencies:\n  flutter:\n    sdk: flutter\n');
  });

  Future<PackageRoots> resolve(Set<String> needed,
          {bool pubGet = false, bool offline = false, PubRunner? run}) =>
      resolvePackageRoots(root.path, needed,
          pubGet: pubGet,
          offline: offline,
          environment: {'PUB_CACHE': cache.path},
          run: run ?? (_, __, ___) async => fail('pub get must not run'));

  test('package_config.json is used when it has the packages', () async {
    put('lib/a.dart', '', under: cache);
    config({'guard': cache.path});
    final found = await resolve({'guard'}, pubGet: true);
    expect(found.roots['guard'], isNotNull);
    expect(found.command, isNull);
    expect(found.issue, isNull);
  });

  test('without it, locked versions are read from the pub cache', () async {
    put('hosted/pub.dev/guard-1.2.3/lib/guard.dart', '', under: cache);
    put('git/tools-0123abc/packages/shield/lib/shield.dart', '', under: cache);
    put('../local_pkg/lib/local.dart', '', under: cache);
    put('pubspec.lock', '''
packages:
  guard:
    dependency: "direct main"
    description:
      name: guard
      url: "https://pub.dev"
    source: hosted
    version: "1.2.3"
  shield:
    dependency: "direct main"
    description:
      path: "packages/shield"
      ref: main
      resolved-ref: "0123abc"
      url: "https://github.com/acme/tools.git"
    source: git
    version: "0.1.0"
  local_pkg:
    dependency: "direct main"
    description:
      path: "${p.join(cache.parent.path, 'local_pkg')}"
      relative: false
    source: path
    version: "0.0.1"
''');
    addTearDown(() => Directory(p.join(cache.parent.path, 'local_pkg'))
        .deleteSync(recursive: true));
    final found = await resolve({'guard', 'shield', 'local_pkg'}, pubGet: true);
    expect(found.roots['guard'],
        p.join(cache.path, 'hosted', 'pub.dev', 'guard-1.2.3'));
    expect(found.roots['shield'],
        p.join(cache.path, 'git', 'tools-0123abc', 'packages', 'shield'));
    expect(found.roots['local_pkg'], p.join(cache.parent.path, 'local_pkg'));
    expect(found.command, isNull, reason: 'nothing left for pub get');
  });

  test('pub get runs with the lock file enforced when packages are missing',
      () async {
    put('pubspec.lock', 'packages: {}\n');
    final calls = <String>[];
    final found = await resolve({'guard'}, pubGet: true, offline: true,
        run: (tool, arguments, directory) async {
      calls.add('$tool ${arguments.join(' ')} in $directory');
      put('lib/guard.dart', '', under: cache);
      config({'guard': cache.path});
      return (0, '');
    });
    expect(calls,
        ['flutter pub get --enforce-lockfile --offline in ${root.path}']);
    expect(found.command, 'flutter pub get --enforce-lockfile --offline');
    expect(found.created, isFalse);
    expect(found.issue, isNull);
    expect(found.roots['guard'], isNotNull);
  });

  test('a Dart project without a lock file gets one from dart pub get',
      () async {
    put('pubspec.yaml', 'name: tool\ndependencies:\n  guard: any\n');
    final found = await resolve({'guard'}, pubGet: true,
        run: (tool, arguments, directory) async {
      put('pubspec.lock', 'packages: {}\n');
      config({'guard': cache.path});
      return (0, '');
    });
    expect(found.command, 'dart pub get');
    expect(found.created, isTrue);
  });

  test('pub get is not run unless it is allowed', () async {
    final found = await resolve({'guard'});
    expect(found.roots, isEmpty);
    expect(found.issue, 'not-resolved');
    expect(found.command, isNull);
  });

  test('a missing tool and a failed run are reported', () async {
    final missing =
        await resolve({'guard'}, pubGet: true, run: (_, __, ___) async => null);
    expect(missing.issue, 'tool-missing');
    expect(missing.command, 'flutter pub get');

    final failed = await resolve({'guard'},
        pubGet: true,
        run: (_, __, ___) async => (65, 'version solving failed'));
    expect(failed.issue, 'failed');
    expect(failed.roots, isEmpty);
  });
}
