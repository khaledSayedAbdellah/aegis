/// Everything `aegis doctor` / `aegis setup` touch on the computer, behind one
/// interface so the logic can be tested with a fake machine
/// (`test/support/fake_host.dart`).
///
/// This is the only file in `lib/src/probe/` that imports `dart:io`.
library;

import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart' as crypto;

import '../version.dart';

/// A finished process.
class Proc {
  Proc(this.exitCode, this.stdout, this.stderr);
  final int exitCode;
  final String stdout;
  final String stderr;
  bool get ok => exitCode == 0;

  /// Trimmed stdout.
  String get out => stdout.trim();

  /// stdout and stderr together, trimmed (`java -version` writes to stderr).
  String get text => '$stdout\n$stderr'.trim();
}

abstract class Host {
  String? env(String name);

  /// The user's home folder, or null when unknown.
  String? get home;

  /// `macos`, `linux` or `windows`.
  String get os;

  /// `arm64` or `x86_64`: the machine, not the Dart binary (an x86_64 Dart
  /// under Rosetta still reports `arm64` on Apple Silicon).
  String get arch;

  bool fileExists(String path);
  bool dirExists(String path);

  /// Full paths of the entries of [dir]; empty when it does not exist.
  List<String> listDir(String dir);

  void mkdirs(String dir);
  String readText(String path);
  void writeText(String path, String text);
  List<int> readBytes(String path);
  void writeBytes(String path, List<int> bytes);

  /// Deletes a file; nothing when it is missing. Never deletes folders.
  void deleteFile(String path);

  /// Deletes a file or a folder (recursively); nothing when it is missing.
  void deletePath(String path);
  void rename(String from, String to);
  void makeExecutable(String path);

  /// The SHA-256 of the file at [path], lowercase hex.
  String sha256File(String path);

  /// Free bytes on the disk that holds [path], or null when unknown.
  Future<int?> freeBytes(String path);

  /// Runs a program and captures its output. Null when it can't be started
  /// (not installed). [input] is written to its stdin.
  Future<Proc?> run(String exe, List<String> args,
      {Map<String, String>? environment, String? input});

  /// Runs a program on the person's terminal, so they see its output and
  /// answer its questions (sdkmanager's license prompt). Returns the exit
  /// code, or null when it can't be started.
  Future<int?> runAttached(String exe, List<String> args,
      {Map<String, String>? environment});

  /// Starts a long-running program detached and returns at once, without
  /// waiting for it to exit (the emulator, which runs for the whole probe).
  Future<void> spawn(String exe, List<String> args,
      {Map<String, String>? environment});

  /// Downloads [url] to [dest] through `<dest>.part`, so a failed download
  /// leaves nothing at [dest]. Returns null on success, else the reason.
  Future<String?> download(String url, String dest,
      {void Function(int received, int? total)? progress});
}

class SystemHost implements Host {
  @override
  String? env(String name) => Platform.environment[name];

  @override
  String? get home => env('HOME') ?? env('USERPROFILE');

  @override
  String get os => Platform.isMacOS
      ? 'macos'
      : Platform.isWindows
          ? 'windows'
          : 'linux';

  String? _arch;

  @override
  String get arch => _arch ??= _detectArch();

  String _detectArch() {
    if (Platform.isMacOS) {
      try {
        final r = Process.runSync('sysctl', ['-n', 'hw.optional.arm64']);
        if ('${r.stdout}'.trim() == '1') return 'arm64';
      } catch (_) {}
    }
    final v = Platform.version.toLowerCase();
    return v.contains('arm64') || v.contains('aarch64') ? 'arm64' : 'x86_64';
  }

  @override
  bool fileExists(String path) => File(path).existsSync();
  @override
  bool dirExists(String path) => Directory(path).existsSync();

  @override
  List<String> listDir(String dir) {
    final d = Directory(dir);
    if (!d.existsSync()) return const [];
    try {
      return [for (final e in d.listSync()) e.path];
    } on FileSystemException {
      return const [];
    }
  }

  @override
  void mkdirs(String dir) => Directory(dir).createSync(recursive: true);

  @override
  String readText(String path) => File(path).readAsStringSync();

  @override
  void writeText(String path, String text) {
    final f = File(path);
    f.parent.createSync(recursive: true);
    f.writeAsStringSync(text, flush: true);
  }

  @override
  List<int> readBytes(String path) => File(path).readAsBytesSync();

  @override
  void writeBytes(String path, List<int> bytes) {
    final f = File(path);
    f.parent.createSync(recursive: true);
    f.writeAsBytesSync(bytes, flush: true);
  }

  @override
  void deleteFile(String path) {
    final f = File(path);
    if (f.existsSync()) f.deleteSync();
  }

  @override
  void deletePath(String path) {
    final d = Directory(path);
    if (d.existsSync()) {
      d.deleteSync(recursive: true);
      return;
    }
    final f = File(path);
    if (f.existsSync()) f.deleteSync();
  }

  @override
  String sha256File(String path) =>
      crypto.sha256.convert(File(path).readAsBytesSync()).toString();

  @override
  void rename(String from, String to) => File(from).renameSync(to);

  @override
  void makeExecutable(String path) {
    if (Platform.isWindows) return;
    Process.runSync('chmod', ['755', path]);
  }

  @override
  Future<int?> freeBytes(String path) async {
    if (Platform.isWindows) return null;
    try {
      // POSIX output: header line, then "<fs> <blocks> <used> <avail> ...".
      final r = await Process.run('df', ['-Pk', path]);
      final lines = '${r.stdout}'.trim().split('\n');
      if (r.exitCode != 0 || lines.length < 2) return null;
      final cols = lines.last.trim().split(RegExp(r'\s+'));
      final kb = cols.length > 3 ? int.tryParse(cols[3]) : null;
      return kb == null ? null : kb * 1024;
    } catch (_) {
      return null;
    }
  }

  @override
  Future<Proc?> run(String exe, List<String> args,
      {Map<String, String>? environment, String? input}) async {
    final Process p;
    try {
      p = await Process.start(exe, args, environment: environment);
    } on ProcessException {
      return null;
    }
    final out = p.stdout.transform(const Utf8Decoder(allowMalformed: true)).join();
    final err = p.stderr.transform(const Utf8Decoder(allowMalformed: true)).join();
    try {
      if (input != null) p.stdin.write(input);
      await p.stdin.close();
    } catch (_) {
      // The program does not read stdin.
    }
    final code = await p.exitCode;
    return Proc(code, await out, await err);
  }

  @override
  Future<int?> runAttached(String exe, List<String> args,
      {Map<String, String>? environment}) async {
    try {
      final p = await Process.start(exe, args,
          environment: environment, mode: ProcessStartMode.inheritStdio);
      return await p.exitCode;
    } on ProcessException {
      return null;
    }
  }

  @override
  Future<void> spawn(String exe, List<String> args,
      {Map<String, String>? environment}) async {
    try {
      // Detached: it keeps running on its own and we never await its exit.
      await Process.start(exe, args,
          environment: environment, mode: ProcessStartMode.detached);
    } on ProcessException {
      // Left for the caller's boot check to report as "not booting".
    }
  }

  @override
  Future<String?> download(String url, String dest,
      {void Function(int received, int? total)? progress}) async {
    // GitHub's release CDN sometimes answers 502/503/504 or drops the
    // connection; those are retried, a 404 is not.
    const attempts = 3;
    for (var i = 1;; i++) {
      final (error, retry) = await _downloadOnce(url, dest, progress);
      if (error == null || !retry || i == attempts) return error;
      await Future<void>.delayed(Duration(seconds: 2 * i));
    }
  }

  Future<(String?, bool)> _downloadOnce(String url, String dest,
      void Function(int received, int? total)? progress) async {
    final client = HttpClient()..userAgent = 'aegis/$aegisVersion';
    final part = File('$dest.part');
    try {
      final resp = await (await client.getUrl(Uri.parse(url))).close();
      if (resp.statusCode != HttpStatus.ok) {
        await resp.drain<void>();
        return ('HTTP ${resp.statusCode} for $url', resp.statusCode >= 500);
      }
      part.parent.createSync(recursive: true);
      final sink = part.openWrite();
      final total = resp.contentLength >= 0 ? resp.contentLength : null;
      var got = 0;
      try {
        await for (final chunk in resp) {
          sink.add(chunk);
          got += chunk.length;
          progress?.call(got, total);
        }
      } finally {
        await sink.close();
      }
      if (total != null && got != total) {
        part.deleteSync();
        return ('incomplete download ($got of $total bytes) from $url', true);
      }
      part.renameSync(dest);
      return (null, false);
    } catch (e) {
      if (part.existsSync()) part.deleteSync();
      return ('download failed: $url ($e)', true);
    } finally {
      client.close(force: true);
    }
  }
}
