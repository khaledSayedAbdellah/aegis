/// Finds the tools the resilience probe will need (doc/plans/probe-toolchain.md
/// §3–4). Android SDK and Java are resolved in the same order Flutter uses, so
/// aegis works with exactly the tools the app is built with.
///
/// Everything goes through [Host]; this file does no I/O of its own.
library;

import 'dart:convert';

import 'package:path/path.dart' as p;

import 'host.dart';
import 'pins.dart' as pins;

enum ToolState {
  /// Found and good enough. `aegis setup` skips it.
  present,

  /// Missing or the wrong version; `aegis setup` installs it.
  installable,

  /// Missing; the person installs it (the message says how).
  manual,

  /// Not needed now (bundletool without `--aab`).
  optional,
}

/// Why a tool is not plainly present; rendered in en/ar by `messages.dart`.
enum Issue {
  flutterMissing,
  javaMissing,
  javaOld,
  sdkMissing,
  cmdlineMissing,
  missing,
  buildToolsOld,
  pythonMissing,
  pythonOld,
  pythonNoVenv,
  fridaOtherVersion,
  xcodeMissing,
  optionalAab,
}

class ToolCheck {
  ToolCheck(
    this.id,
    this.state, {
    this.path,
    this.version,
    this.issue,
    this.detail = const {},
    this.source,
  });

  /// Stable key (plan §3): `java`, `android-sdk`, `frida`, ...
  final String id;
  final ToolState state;

  /// Executable, file or folder, when known.
  final String? path;
  final String? version;
  final Issue? issue;

  /// Values for the [issue] message, e.g. `{'found': '8'}`.
  final Map<String, String> detail;

  /// Where it was found: `flutter config`, `ANDROID_HOME`, a default, ...
  final String? source;

  bool get ok => state == ToolState.present;
  bool get installable => state == ToolState.installable;
}

/// Ids in display order.
const toolIds = [
  'flutter',
  'java',
  'android-sdk',
  'cmdline-tools',
  'platform-tools',
  'build-tools',
  'emulator',
  'system-image',
  'control-image',
  'avd',
  'control-avd',
  'python',
  'frida',
  'frida-server',
  'bundletool',
];

/// What must be present before aegis can install a tool (plan §3). frida-server
/// and bundletool have pinned versions, so they depend on nothing.
const toolNeeds = <String, List<String>>{
  'platform-tools': ['android-sdk', 'cmdline-tools', 'java'],
  'build-tools': ['android-sdk', 'cmdline-tools', 'java'],
  'emulator': ['android-sdk', 'cmdline-tools', 'java'],
  'system-image': ['android-sdk', 'cmdline-tools', 'java'],
  'control-image': ['android-sdk', 'cmdline-tools', 'java'],
  'avd': ['system-image', 'emulator', 'cmdline-tools', 'java'],
  'control-avd': ['control-image', 'emulator', 'cmdline-tools', 'java'],
  'frida': ['python'],
};

class Toolchain {
  Toolchain(this.host);

  final Host host;

  p.Context get _p => host.os == 'windows' ? p.windows : p.posix;
  bool get _win => host.os == 'windows';

  String get aegisDir => _p.join(host.home ?? '.', '.aegis');
  String get toolsDir => _p.join(aegisDir, 'tools');
  String get venvDir => _p.join(aegisDir, 'venv');
  String get toolsJsonPath => _p.join(aegisDir, 'tools.json');

  /// `arm64-v8a` or `x86_64`: the emulator image ABI.
  String get abi => host.arch == 'arm64' ? 'arm64-v8a' : 'x86_64';

  /// Frida's name for the same architecture.
  String get fridaArch => host.arch == 'arm64' ? 'arm64' : 'x86_64';

  String get systemImagePackage => _systemImagePackage(false);
  String get controlImagePackage => _systemImagePackage(true);

  String _systemImagePackage(bool control) =>
      'system-images;android-${pins.systemImageApi};'
      '${control ? 'google_apis_playstore' : 'google_apis'};$abi';

  String get fridaServerPath =>
      _p.join(toolsDir, pins.fridaServerName(fridaArch));
  String get iosFridaCache => _p.join(toolsDir, 'ios-${pins.fridaVersion}');
  String get iosGadgetPath => _p.join(iosFridaCache, 'frida', 'gadget-ios.dylib');
  String get iosSimulatorGadgetPath => _p.join(
      toolsDir, 'ios-simulator-gadget-${pins.iosSimulatorGadgetVersion}.dylib');
  String get bundletoolPath => _p.join(toolsDir, pins.bundletoolName);

  String venvExe(String name) => _win
      ? _p.join(venvDir, 'Scripts', '$name.exe')
      : _p.join(venvDir, 'bin', name);

  String _exe(String name) => _win ? '$name.exe' : name;
  String _bat(String name) => _win ? '$name.bat' : name;

  /// `~/x` for paths under the home folder.
  String tilde(String path) {
    final h = host.home;
    if (h != null && _p.isWithin(h, path)) {
      return '~${_p.separator}${_p.relative(path, from: h)}';
    }
    if (h != null && path == h) return '~';
    return path;
  }

  // --- Flutter (source of truth for the SDK and the JDK) ------------------

  Map<String, dynamic>? _config;
  bool _configRun = false;
  String? _doctor;
  bool _doctorRun = false;

  /// `flutter config --machine` as a map, or `{}` when Flutter is missing.
  Future<Map<String, dynamic>> flutterConfig() async {
    if (_configRun) return _config ?? const {};
    _configRun = true;
    final r = await host.run(_bat('flutter'), ['config', '--machine']);
    if (r != null && r.ok) {
      final start = r.stdout.indexOf('{');
      if (start >= 0) {
        try {
          final m = jsonDecode(r.stdout.substring(start));
          if (m is Map<String, dynamic>) _config = m;
        } on FormatException {
          // Leave null.
        }
      }
    }
    return _config ?? const {};
  }

  /// `flutter --no-wrap doctor -v`, joined so a wrapped line is reattached.
  Future<String?> flutterDoctor() async {
    if (_doctorRun) return _doctor;
    _doctorRun = true;
    final r = await host.run(_bat('flutter'), ['--no-wrap', 'doctor', '-v']);
    if (r != null) _doctor = unwrapDoctor(r.text);
    return _doctor;
  }

  /// Joins a continuation line (indented, not starting with `•`/`[`) onto the
  /// previous line with one space, so a wrapped path becomes whole again.
  static String unwrapDoctor(String text) {
    final out = <String>[];
    for (final raw in text.split('\n')) {
      final line = raw.trimRight();
      final t = line.trimLeft();
      final continuation = out.isNotEmpty &&
          line.startsWith(' ') &&
          !t.startsWith('•') &&
          !t.startsWith('[') &&
          !t.startsWith('!') &&
          !t.startsWith('✗') &&
          !t.startsWith('✓');
      if (continuation) {
        out[out.length - 1] = '${out.last} $t';
      } else {
        out.add(line);
      }
    }
    return out.join('\n');
  }

  /// The longest space-separated prefix of [text] that [exists]. Unwrapping
  /// `flutter doctor` can glue the sentence after a path onto it
  /// ("…/bin/java This JDK is specified…"); paths with spaces
  /// ("Android Studio.app") still match because longer prefixes go first.
  static String? longestExisting(String text, bool Function(String) exists) {
    final words = text.trim().split(' ');
    for (var n = words.length; n > 0; n--) {
      final candidate = words.take(n).join(' ');
      if (exists(candidate)) return candidate;
    }
    return null;
  }

  // --- Flutter / SDK / Java -----------------------------------------------

  Future<ToolCheck> checkFlutter() async {
    final r = await host.run(_bat('flutter'), ['--version', '--machine']);
    if (r != null && r.ok) {
      final start = r.stdout.indexOf('{');
      if (start >= 0) {
        try {
          final m = jsonDecode(r.stdout.substring(start));
          if (m is Map && m['frameworkVersion'] is String) {
            return ToolCheck('flutter', ToolState.present,
                version: m['frameworkVersion'] as String, source: 'PATH');
          }
        } on FormatException {
          // fall through
        }
      }
      return ToolCheck('flutter', ToolState.present, source: 'PATH');
    }
    return ToolCheck('flutter', ToolState.manual, issue: Issue.flutterMissing);
  }

  /// SDK root: flutter config → ANDROID_HOME → ANDROID_SDK_ROOT → default →
  /// flutter doctor. Returns (path, source) or null.
  Future<({String path, String source})?> findSdkRoot() async {
    final cfg = await flutterConfig();
    final fromCfg = cfg['android-sdk'];
    if (fromCfg is String && fromCfg.isNotEmpty && host.dirExists(fromCfg)) {
      return (path: fromCfg, source: 'flutter config');
    }
    for (final name in ['ANDROID_HOME', 'ANDROID_SDK_ROOT']) {
      final v = host.env(name);
      if (v != null && v.isNotEmpty && host.dirExists(v)) {
        return (path: v, source: name);
      }
    }
    final def = _defaultSdkDir();
    if (def != null && host.dirExists(def)) {
      return (path: def, source: 'default location');
    }
    final doctor = await flutterDoctor();
    if (doctor != null) {
      final m = RegExp(r'Android SDK at (.+)$', multiLine: true).firstMatch(doctor);
      final path = m == null ? null : longestExisting(m.group(1)!, host.dirExists);
      if (path != null) return (path: path, source: 'flutter doctor');
    }
    return null;
  }

  String? _defaultSdkDir() {
    final h = host.home;
    if (h == null) return null;
    return switch (host.os) {
      'macos' => _p.join(h, 'Library', 'Android', 'sdk'),
      'windows' => _p.join(
          host.env('LOCALAPPDATA') ?? _p.join(h, 'AppData', 'Local'),
          'Android',
          'Sdk'),
      _ => _p.join(h, 'Android', 'Sdk'),
    };
  }

  Future<ToolCheck> checkAndroidSdk() async {
    final sdk = await findSdkRoot();
    if (sdk == null) {
      return ToolCheck('android-sdk', ToolState.manual, issue: Issue.sdkMissing);
    }
    return ToolCheck('android-sdk', ToolState.present,
        path: sdk.path, source: sdk.source);
  }

  /// JDK home: flutter config jdk-dir → Android Studio JBR → JAVA_HOME →
  /// `java` on PATH → flutter doctor. Returns (home, source) or null.
  Future<({String home, String source})?> findJavaHome() async {
    final cfg = await flutterConfig();
    final fromCfg = cfg['jdk-dir'];
    if (fromCfg is String && fromCfg.isNotEmpty && _hasJavaBin(fromCfg)) {
      return (home: fromCfg, source: 'flutter config');
    }
    for (final jbr in _studioJbrHomes()) {
      if (_hasJavaBin(jbr)) return (home: jbr, source: 'Android Studio');
    }
    final javaHome = host.env('JAVA_HOME');
    if (javaHome != null && javaHome.isNotEmpty && _hasJavaBin(javaHome)) {
      return (home: javaHome, source: 'JAVA_HOME');
    }
    final doctor = await flutterDoctor();
    if (doctor != null) {
      final m =
          RegExp(r'Java binary at: (.+)$', multiLine: true).firstMatch(doctor);
      final bin = m == null ? null : longestExisting(m.group(1)!, host.fileExists);
      if (bin != null) {
        // …/bin/java → the home is two levels up.
        final home = _p.dirname(_p.dirname(bin));
        return (home: home, source: 'flutter doctor');
      }
    }
    return null;
  }

  bool _hasJavaBin(String home) => host.fileExists(_javaBin(home));
  String _javaBin(String home) => _p.join(home, 'bin', _exe('java'));

  Iterable<String> _studioJbrHomes() sync* {
    final h = host.home;
    switch (host.os) {
      case 'macos':
        yield '/Applications/Android Studio.app/Contents/jbr/Contents/Home';
        if (h != null) {
          yield _p.join(h, 'Applications', 'Android Studio.app', 'Contents',
              'jbr', 'Contents', 'Home');
        }
      case 'windows':
        final pf = host.env('ProgramFiles') ?? r'C:\Program Files';
        yield _p.join(pf, 'Android', 'Android Studio', 'jbr');
      default:
        yield '/opt/android-studio/jbr';
        if (h != null) yield _p.join(h, 'android-studio', 'jbr');
    }
  }

  Future<ToolCheck> checkJava() async {
    final jdk = await findJavaHome();
    if (jdk == null) {
      // Fall back to a bare `java` on PATH even without a home we can name.
      final onPath = await _javaMajorOf(_exe('java'));
      if (onPath != null) {
        return _javaResult(_exe('java'), onPath, 'PATH');
      }
      return ToolCheck('java', ToolState.manual, issue: Issue.javaMissing);
    }
    final bin = _javaBin(jdk.home);
    final major = await _javaMajorOf(bin);
    if (major == null) {
      return ToolCheck('java', ToolState.manual,
          issue: Issue.javaMissing, path: jdk.home, source: jdk.source);
    }
    return _javaResult(jdk.home, major, jdk.source, javaPath: bin);
  }

  ToolCheck _javaResult(String home, int major, String source,
      {String? javaPath}) {
    if (major < pins.minJavaMajor) {
      return ToolCheck('java', ToolState.manual,
          issue: Issue.javaOld,
          version: '$major',
          path: home,
          source: source,
          detail: {'found': '$major', 'need': '${pins.minJavaMajor}'});
    }
    return ToolCheck('java', ToolState.present,
        path: home, version: '$major', source: source);
  }

  Future<int?> _javaMajorOf(String javaBin) async {
    final r = await host.run(javaBin, ['-version']);
    if (r == null) return null;
    return parseJavaMajor(r.text);
  }

  /// `version "21.0.3"` → 21, `version "1.8.0_382"` → 8, `openjdk 17 …` → 17.
  static int? parseJavaMajor(String text) {
    final m = RegExp(r'version "(\d+)(?:\.(\d+))?').firstMatch(text) ??
        RegExp(r'(?:openjdk|java)\s+(\d+)').firstMatch(text);
    if (m == null) return null;
    final first = int.tryParse(m.group(1) ?? '');
    if (first == null) return null;
    if (first == 1 && m.groupCount >= 2 && m.group(2) != null) {
      return int.tryParse(m.group(2)!); // legacy 1.8 → 8
    }
    return first;
  }

  // --- SDK pieces ---------------------------------------------------------

  /// `cmdline-tools/<latest|version>/bin/<tool>` under the SDK, or null.
  String? sdkTool(String sdkRoot, String name) {
    final base = _p.join(sdkRoot, 'cmdline-tools');
    for (final sub in _orderedSubdirs(base, prefer: 'latest')) {
      final exe = _p.join(sub, 'bin', _bat(name));
      if (host.fileExists(exe)) return exe;
    }
    return null;
  }

  Future<ToolCheck> checkCmdlineTools(String? sdkRoot) async {
    if (sdkRoot == null) {
      return ToolCheck('cmdline-tools', ToolState.manual, issue: Issue.sdkMissing);
    }
    final sm = sdkTool(sdkRoot, 'sdkmanager');
    if (sm != null) {
      return ToolCheck('cmdline-tools', ToolState.present, path: sm);
    }
    return ToolCheck('cmdline-tools', ToolState.manual,
        issue: Issue.cmdlineMissing);
  }

  Future<ToolCheck> checkPlatformTools(String? sdkRoot) async {
    if (sdkRoot == null) {
      return ToolCheck('platform-tools', ToolState.installable,
          issue: Issue.missing);
    }
    final adb = _p.join(sdkRoot, 'platform-tools', _exe('adb'));
    if (host.fileExists(adb)) {
      return ToolCheck('platform-tools', ToolState.present, path: adb);
    }
    return ToolCheck('platform-tools', ToolState.installable, issue: Issue.missing);
  }

  Future<ToolCheck> checkBuildTools(String? sdkRoot) async {
    if (sdkRoot == null) {
      return ToolCheck('build-tools', ToolState.installable, issue: Issue.missing);
    }
    final base = _p.join(sdkRoot, 'build-tools');
    // Newest version first; accept one that has both apksigner and zipalign.
    String? best;
    int bestMajor = -1;
    for (final dir in _orderedSubdirs(base)) {
      final name = _p.basename(dir);
      final major = int.tryParse(name.split('.').first) ?? -1;
      final hasSigner = host.fileExists(_p.join(dir, _bat('apksigner')));
      final hasAlign = host.fileExists(_p.join(dir, _exe('zipalign')));
      if (hasSigner && hasAlign && major >= pins.minBuildToolsMajor && major > bestMajor) {
        best = dir;
        bestMajor = major;
      }
    }
    if (best != null) {
      return ToolCheck('build-tools', ToolState.present,
          path: best, version: _p.basename(best));
    }
    return ToolCheck('build-tools', ToolState.installable, issue: Issue.missing);
  }

  Future<ToolCheck> checkEmulator(String? sdkRoot) async {
    if (sdkRoot == null) {
      return ToolCheck('emulator', ToolState.installable, issue: Issue.missing);
    }
    final emu = _p.join(sdkRoot, 'emulator', _exe('emulator'));
    if (host.fileExists(emu)) {
      return ToolCheck('emulator', ToolState.present, path: emu);
    }
    return ToolCheck('emulator', ToolState.installable, issue: Issue.missing);
  }

  Future<ToolCheck> checkSystemImage(String? sdkRoot, {bool control = false}) async {
    final id = control ? 'control-image' : 'system-image';
    if (sdkRoot != null) {
      final dir = _p.joinAll([sdkRoot, ..._systemImagePackage(control).split(';')]);
      if (host.fileExists(_p.join(dir, 'system.img')) &&
          host.fileExists(_p.join(dir, 'source.properties'))) {
        return ToolCheck(id, ToolState.present, path: dir);
      }
    }
    return ToolCheck(id, ToolState.installable, issue: Issue.missing);
  }

  /// `$ANDROID_AVD_HOME`, else `~/.android/avd`.
  String? get avdHome {
    final v = host.env('ANDROID_AVD_HOME');
    if (v != null && v.isNotEmpty) return v;
    final h = host.home;
    return h == null ? null : _p.join(h, '.android', 'avd');
  }

  Future<ToolCheck> checkAvd({bool control = false}) async {
    final id = control ? 'control-avd' : 'avd';
    final name = control ? pins.controlAvdName : pins.avdName;
    final home = avdHome;
    final dir = home == null ? null : _p.join(home, '$name.avd');
    final ini = home == null ? null : _p.join(home, '$name.ini');
    if (dir != null && host.dirExists(dir) && host.fileExists(ini!)) {
      return ToolCheck(id, ToolState.present, path: dir);
    }
    return ToolCheck(id, ToolState.installable, issue: Issue.missing);
  }

  // --- Python + Frida -----------------------------------------------------

  /// A system Python ≥ 3.9 with `venv`. Returns the interpreter or null.
  Future<ToolCheck> checkPython() async {
    for (final exe in [_exe('python3'), _exe('python')]) {
      final r = await host.run(exe, ['--version']);
      if (r == null) continue;
      final v = parsePython(r.text);
      if (v == null) continue;
      if (v.$1 < pins.minPython.$1 ||
          (v.$1 == pins.minPython.$1 && v.$2 < pins.minPython.$2)) {
        return ToolCheck('python', ToolState.manual,
            issue: Issue.pythonOld, version: '${v.$1}.${v.$2}', path: exe);
      }
      final venv = await host.run(exe, ['-c', 'import venv']);
      if (venv == null || !venv.ok) {
        return ToolCheck('python', ToolState.manual,
            issue: Issue.pythonNoVenv, version: '${v.$1}.${v.$2}', path: exe);
      }
      return ToolCheck('python', ToolState.present,
          path: exe, version: '${v.$1}.${v.$2}');
    }
    return ToolCheck('python', ToolState.manual, issue: Issue.pythonMissing);
  }

  static (int, int)? parsePython(String text) {
    final m = RegExp(r'Python (\d+)\.(\d+)').firstMatch(text);
    if (m == null) return null;
    return (int.parse(m.group(1)!), int.parse(m.group(2)!));
  }

  /// Frida in the aegis venv, at the pinned version.
  Future<ToolCheck> checkFrida() async {
    final frida = venvExe('frida');
    final r = await host.run(frida, ['--version']);
    if (r != null && r.ok && r.text.isNotEmpty) {
      final have = r.text.trim();
      if (have == pins.fridaVersion) {
        return ToolCheck('frida', ToolState.present, path: frida, version: have);
      }
      return ToolCheck('frida', ToolState.installable,
          issue: Issue.fridaOtherVersion,
          version: have,
          detail: {'have': have, 'want': pins.fridaVersion});
    }
    return ToolCheck('frida', ToolState.installable, issue: Issue.missing);
  }

  Future<ToolCheck> checkFridaServer() async {
    if (host.fileExists(fridaServerPath)) {
      return ToolCheck('frida-server', ToolState.present,
          path: fridaServerPath, version: pins.fridaVersion);
    }
    return ToolCheck('frida-server', ToolState.installable, issue: Issue.missing);
  }

  Future<ToolCheck> checkBundletool({bool aab = false}) async {
    if (host.fileExists(bundletoolPath)) {
      return ToolCheck('bundletool', ToolState.present,
          path: bundletoolPath, version: pins.bundletoolVersion);
    }
    return ToolCheck('bundletool',
        aab ? ToolState.installable : ToolState.optional,
        issue: aab ? Issue.missing : Issue.optionalAab);
  }

  ToolCheck checkIosGadget({bool simulator = false}) {
    final path = simulator ? iosSimulatorGadgetPath : iosGadgetPath;
    return ToolCheck(
        simulator ? 'ios-simulator-gadget' : 'ios-gadget',
        host.fileExists(path) ? ToolState.present : ToolState.installable,
        path: path,
        version: simulator ? pins.iosSimulatorGadgetVersion : pins.fridaVersion);
  }

  Future<List<ToolCheck>> checkIos() async {
    final xcode = await host.run('xcrun', ['--find', 'devicectl']);
    if (xcode?.ok != true) {
      return [ToolCheck('xcode', ToolState.manual, issue: Issue.xcodeMissing)];
    }
    return [
      ToolCheck('xcode', ToolState.present, path: xcode!.out),
      await checkPython(),
      await checkFrida(),
      checkIosGadget(),
      checkIosGadget(simulator: true),
    ];
  }

  /// Every Android component, in [toolIds] order. [aab] requires bundletool.
  Future<List<ToolCheck>> checkAll({bool aab = false}) async {
    final flutter = await checkFlutter();
    final sdk = await checkAndroidSdk();
    final java = await checkJava();
    final root = sdk.ok ? sdk.path : null;
    final byId = <String, ToolCheck>{
      'flutter': flutter,
      'java': java,
      'android-sdk': sdk,
      'cmdline-tools': await checkCmdlineTools(root),
      'platform-tools': await checkPlatformTools(root),
      'build-tools': await checkBuildTools(root),
      'emulator': await checkEmulator(root),
      'system-image': await checkSystemImage(root),
      'control-image': await checkSystemImage(root, control: true),
      'avd': await checkAvd(),
      'control-avd': await checkAvd(control: true),
      'python': await checkPython(),
      'frida': await checkFrida(),
      'frida-server': await checkFridaServer(),
      'bundletool': await checkBundletool(aab: aab),
    };
    return [for (final id in toolIds) byId[id]!];
  }

  /// Subdirectories of [base], newest-looking last-sorted first, with
  /// [prefer] (e.g. `latest`) moved to the front when it exists.
  Iterable<String> _orderedSubdirs(String base, {String? prefer}) {
    final subs = host.listDir(base).where(host.dirExists).toList()..sort();
    final ordered = subs.reversed.toList();
    if (prefer != null) {
      final want = _p.join(base, prefer);
      if (ordered.remove(want)) ordered.insert(0, want);
    }
    return ordered;
  }
}
