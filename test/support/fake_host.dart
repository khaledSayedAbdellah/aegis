import 'package:aegis/src/probe/host.dart';
import 'package:crypto/crypto.dart' as crypto;
import 'package:path/path.dart' as p;

/// An in-memory computer for the toolchain tests: no real files, programs or
/// network. Paths are POSIX.
class FakeHost implements Host {
  FakeHost({
    this.home = '/Users/dev',
    this.os = 'macos',
    this.arch = 'arm64',
    Map<String, String>? env,
    this.free,
  }) : envs = env ?? {};

  @override
  final String? home;
  @override
  final String os;
  @override
  final String arch;
  final Map<String, String> envs;

  /// What [freeBytes] answers.
  int? free;

  /// File path -> content. A folder exists when it was added to [dirs] or
  /// holds a file.
  final files = <String, List<int>>{};
  final dirs = <String>{};
  final executable = <String>{};

  /// `"exe arg1 arg2"` -> result. A program with no entry is not installed
  /// (run returns null), unless [installed] lists it.
  final commands = <String, Proc>{};

  /// Programs that exist but have no canned answer: they exit 0, no output.
  final installed = <String>{};

  /// Exit codes for [runAttached], by `"exe arg1 arg2"` (default 0 when the
  /// program is [installed] or has a [commands] entry for any args).
  final attachedExit = <String, int>{};

  /// URL -> bytes served. A URL with no entry fails.
  final downloads = <String, List<int>>{};

  /// Everything that ran or was downloaded, in order:
  /// `run: …`, `attached: …`, `download: <url>`.
  final log = <String>[];

  /// Environments passed to run/runAttached, by command line.
  final envOf = <String, Map<String, String>?>{};

  /// stdin passed to run, by command line.
  final inputOf = <String, String?>{};

  /// Called after a successful [runAttached], to simulate what the program
  /// installed (e.g. sdkmanager creating folders).
  final effects = <String, void Function()>{};

  /// Called after a successful [run] of a program, with the environment it
  /// got, to simulate what it wrote (e.g. avdmanager creating an AVD).
  final runEffects =
      <String, void Function(List<String> args, Map<String, String>? env)>{};

  /// Environments passed to [spawn], by command line.
  final spawnEnvOf = <String, Map<String, String>?>{};

  void addFile(String path, [String content = '']) {
    files[path] = content.codeUnits;
    _addParents(path);
  }

  void addDir(String path) {
    dirs.add(path);
    _addParents(path);
  }

  /// [exe] answers [args] with [stdout]/[stderr] and [code].
  void answer(String exe, List<String> args,
      {String stdout = '', String stderr = '', int code = 0}) {
    commands[[exe, ...args].join(' ')] = Proc(code, stdout, stderr);
  }

  void _addParents(String path) {
    var d = p.posix.dirname(path);
    while (d != '/' && d != '.' && dirs.add(d)) {
      d = p.posix.dirname(d);
    }
  }

  bool _knows(String exe) =>
      installed.contains(exe) ||
      commands.keys.any((k) => k == exe || k.startsWith('$exe '));

  @override
  String? env(String name) => envs[name];

  @override
  bool fileExists(String path) => files.containsKey(path);

  @override
  bool dirExists(String path) => dirs.contains(path);

  @override
  List<String> listDir(String dir) => [
        for (final f in files.keys)
          if (p.posix.dirname(f) == dir) f,
        for (final d in dirs)
          if (p.posix.dirname(d) == dir) d,
      ];

  @override
  void mkdirs(String dir) => addDir(dir);

  @override
  String readText(String path) => String.fromCharCodes(files[path]!);

  @override
  void writeText(String path, String text) => addFile(path, text);

  @override
  List<int> readBytes(String path) => files[path]!;

  @override
  void writeBytes(String path, List<int> bytes) {
    files[path] = List.of(bytes);
    _addParents(path);
  }

  @override
  void deleteFile(String path) => files.remove(path);

  @override
  void deletePath(String path) {
    files.removeWhere((k, _) => k == path || p.isWithin(path, k));
    dirs.removeWhere((d) => d == path || p.isWithin(path, d));
  }

  @override
  String sha256File(String path) =>
      crypto.sha256.convert(files[path]!).toString();

  @override
  void rename(String from, String to) {
    files[to] = files.remove(from)!;
    _addParents(to);
  }

  @override
  void makeExecutable(String path) => executable.add(path);

  @override
  Future<int?> freeBytes(String path) async => free;

  @override
  Future<Proc?> run(String exe, List<String> args,
      {Map<String, String>? environment,
      String? input,
      Duration? timeout}) async {
    final line = [exe, ...args].join(' ');
    log.add('run: $line');
    envOf[line] = environment;
    inputOf[line] = input;
    final result =
        commands[line] ?? (installed.contains(exe) ? Proc(0, '', '') : null);
    if (result != null && result.ok) runEffects[exe]?.call(args, environment);
    return result;
  }

  @override
  Future<int?> runAttached(String exe, List<String> args,
      {Map<String, String>? environment}) async {
    final line = [exe, ...args].join(' ');
    log.add('attached: $line');
    envOf[line] = environment;
    final code = attachedExit[line] ?? (_knows(exe) ? 0 : null);
    if (code == 0) effects[line]?.call();
    return code;
  }

  @override
  Future<void> spawn(String exe, List<String> args,
      {Map<String, String>? environment, String? logPath}) async {
    final line = [exe, ...args].join(' ');
    log.add('spawn: $line');
    spawnEnvOf[line] = environment;
  }

  @override
  Future<String?> download(String url, String dest,
      {void Function(int received, int? total)? progress}) async {
    log.add('download: $url');
    final bytes = downloads[url];
    if (bytes == null) return 'HTTP 404 for $url';
    progress?.call(bytes.length, bytes.length);
    writeBytes(dest, bytes);
    return null;
  }

  /// Commands that ran, without the `run: `/`attached: ` prefix.
  List<String> get ran => [
        for (final l in log)
          if (!l.startsWith('download: ')) l.substring(l.indexOf(': ') + 2),
      ];
}
