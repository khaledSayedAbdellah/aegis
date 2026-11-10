/// Xcode device commands and verified iOS instrumentation sessions.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:path/path.dart' as p;

import '../plist.dart';
import 'host.dart';

class IosCommand {
  IosCommand._(this.process) {
    final streams = [
      process.stdout.transform(const Utf8Decoder(allowMalformed: true)),
      process.stderr.transform(const Utf8Decoder(allowMalformed: true)),
    ];
    _output = streams.first.transform(const LineSplitter()).listen((line) {
      if (_lines.length >= 2000) _lines.removeAt(0);
      _lines.add(line.trim());
      _count++;
    }).asFuture<void>();
    _errors = streams.last.transform(const LineSplitter()).listen((line) {
      if (errors.length >= 30) errors.removeAt(0);
      errors.add(line.trim());
    }).asFuture<void>();
    unawaited(process.exitCode.then((code) {
      exitCode = code;
    }));
  }

  final Process process;
  final _lines = <String>[];
  final errors = <String>[];
  int _count = 0;
  late final Future<void> _output, _errors;
  int? exitCode;

  static Future<IosCommand> start(String program, List<String> args,
          {Map<String, String>? environment}) async =>
      IosCommand._(
          await Process.start(program, args, environment: environment));

  int get position => _count;
  bool saw(String line) => _lines.contains(line);

  Iterable<String> linesAfter(int position) => _lines
      .skip((position - (_count - _lines.length)).clamp(0, _lines.length));

  Future<bool> ready(String line,
      {Duration timeout = const Duration(seconds: 15)}) async {
    final clock = Stopwatch()..start();
    while (clock.elapsed < timeout && exitCode == null) {
      if (saw(line)) return true;
      await Future<void>.delayed(const Duration(milliseconds: 120));
    }
    return saw(line);
  }

  Future<void> close() async {
    if (exitCode == null) process.kill(ProcessSignal.sigkill);
    await Future.wait<void>([_output, _errors, process.exitCode.then((_) {})])
        .timeout(const Duration(seconds: 3), onTimeout: () => []);
  }
}

class IosDevice {
  IosDevice(this.id, this.work, {this.simulator = false});

  final String id;
  final Directory work;
  final bool simulator;
  final host = SystemHost();
  final _installedPaths = <String, String>{};

  static bool validId(String id) =>
      RegExp(r'^[a-fA-F0-9][a-fA-F0-9-]{7,63}$').hasMatch(id);

  Future<Proc?> _xcrun(List<String> args) =>
      host.run('xcrun', args, timeout: const Duration(seconds: 40));

  Future<Map> _core(List<String> command, {bool forDevice = true}) async {
    final file = File(p.join(work.path, 'core-$id.json'));
    if (file.existsSync()) file.deleteSync();
    final result = await _xcrun([
      'devicectl',
      ...command,
      if (forDevice) ...['--device', id],
      '--timeout',
      '30',
      '--json-output',
      file.path,
    ]);
    if (result?.ok != true || !file.existsSync()) {
      throw StateError(
          'Xcode ${command.join(' ')} failed: ${result?.text ?? 'xcrun unavailable'}');
    }
    final decoded = jsonDecode(file.readAsStringSync());
    if (decoded is! Map || decoded['result'] is! Map) {
      throw StateError(
          'Xcode returned an unreadable ${command.join(' ')} result.');
    }
    return decoded['result'] as Map;
  }

  /// Returns the USB hardware UDID that Frida and iproxy select.
  Future<String> verifyTarget() async {
    if (!validId(id)) {
      throw StateError('Use an explicit iOS device identifier.');
    }
    if (simulator) {
      final result =
          await _xcrun(['simctl', 'list', 'devices', 'booted', '-j']);
      if (result?.ok != true) {
        throw StateError('Could not list booted iOS Simulators.');
      }
      final decoded = jsonDecode(result!.stdout);
      final devices = decoded is Map ? decoded['devices'] : null;
      if (devices is! Map) {
        throw StateError('Could not read the booted iOS Simulators.');
      }
      for (final entry in devices.entries) {
        final entries = entry.value;
        if (!entry.key.toString().contains('SimRuntime.iOS-') ||
            entries is! List) {
          continue;
        }
        for (final d in entries.whereType<Map>()) {
          if (d['udid'] == id && d['state'] == 'Booted') return id;
        }
      }
      throw StateError('The selected iOS Simulator is not booted.');
    }
    final devices =
        (await _core(['list', 'devices'], forDevice: false))['devices'];
    if (devices is! List) {
      throw StateError('Xcode did not list connected iOS devices.');
    }
    for (final device in devices.whereType<Map>()) {
      final hardware = device['hardwareProperties'];
      final udid = hardware is Map ? hardware['udid'] : null;
      if (device['identifier']?.toString().toLowerCase() != id.toLowerCase() &&
          udid?.toString().toLowerCase() != id.toLowerCase()) {
        continue;
      }
      if (hardware is! Map ||
          !{'iOS', 'iPadOS'}.contains(hardware['platform']) ||
          udid is! String ||
          !validId(udid)) {
        break;
      }
      return udid;
    }
    throw StateError(
        'The selected physical iOS device is not listed by Xcode.');
  }

  Future<String?> installedApp(String bundle) async {
    if (simulator) {
      final result = await _xcrun(['simctl', 'listapps', id]);
      if (result?.ok != true) {
        throw StateError('Could not list Simulator apps.');
      }
      final xml = await host.run(
          '/usr/bin/plutil', ['-convert', 'xml1', '-o', '-', '--', '-'],
          input: result!.stdout);
      final apps = xml?.ok == true ? parsePlist(xml!.stdout) : null;
      if (apps == null) {
        throw StateError('Could not read the Simulator app list.');
      }
      if (!apps.containsKey(bundle)) return null;
      final installed = apps[bundle];
      return installed is Map
          ? _filePath(installed['Path'] ?? installed['Bundle']) ?? ''
          : '';
    }
    final apps = (await _core(['device', 'info', 'apps']))['apps'];
    if (apps is! List) {
      throw StateError('Xcode did not return the installed apps.');
    }
    for (final app in apps.whereType<Map>()) {
      if (app['bundleIdentifier'] != bundle) continue;
      final path = _filePath(app['url'] ?? app['bundleURL'] ?? app['path']);
      // Older CoreDevice responses omit the bundle path. Refuse to replace
      // an existing app even when we cannot locate its executable.
      return path ?? _installedPaths[bundle] ?? '';
    }
    return null;
  }

  Future<void> install(String app) async {
    if (simulator) {
      final result = await _xcrun(['simctl', 'install', id, app]);
      if (result?.ok != true) {
        throw StateError('Simulator install failed: ${result?.text}');
      }
    } else {
      final result = await _core(['device', 'install', 'app', app]);
      final apps = result['installedApplications'];
      if (apps is List) {
        for (final entry in apps.whereType<Map>()) {
          final bundle = entry['bundleID'];
          final path = _filePath(entry['installationURL']);
          if (bundle is String && path != null) _installedPaths[bundle] = path;
        }
      }
    }
  }

  Future<void> uninstall(String bundle) async {
    if (simulator) {
      final result = await _xcrun(['simctl', 'uninstall', id, bundle]);
      if (result?.ok != true) {
        throw StateError('Simulator uninstall failed: ${result?.text}');
      }
    } else {
      await _core(['device', 'uninstall', 'app', bundle]);
      _installedPaths.remove(bundle);
    }
  }

  Future<String> simulatorDataPath(String bundle) async {
    final result =
        await _xcrun(['simctl', 'get_app_container', id, bundle, 'data']);
    if (result?.ok != true || !p.isAbsolute(result!.out)) {
      throw StateError('Could not locate the Simulator app data container.');
    }
    return result.out;
  }

  Future<IosCommand> launch(String bundle,
          {String? simulatorLibrary,
          Map<String, String> simulatorEnvironment = const {}}) =>
      IosCommand.start(
        'xcrun',
        [
          if (simulator) ...[
            'simctl',
            'launch',
            '--console',
            '--terminate-running-process',
            id,
            bundle
          ] else ...[
            'devicectl',
            'device',
            'process',
            'launch',
            '--device',
            id,
            '--terminate-existing',
            '--console',
            bundle
          ],
        ],
        environment: simulator
            ? {
                'SIMCTL_CHILD_DYLD_INSERT_LIBRARIES': simulatorLibrary ?? '',
                for (final entry in simulatorEnvironment.entries)
                  'SIMCTL_CHILD_${entry.key}': entry.value,
              }
            : null,
      );

  Future<int?> pid(String appPath, String executable, {int? previous}) async {
    final expected = appPath.isEmpty ? null : p.join(appPath, executable);
    if (simulator) {
      final result = await host.run('/bin/ps', ['-axo', 'pid=,comm=']);
      if (result?.ok != true) {
        throw StateError('Could not enumerate Simulator processes.');
      }
      for (final line in result!.stdout.split('\n')) {
        final match = RegExp(r'^\s*(\d+)\s+(.+)$').firstMatch(line);
        if (match != null &&
            expected != null &&
            _sameDevicePath(match.group(2)!, expected)) {
          return int.parse(match.group(1)!);
        }
      }
      return null;
    }
    final result = await _core(['device', 'info', 'processes']);
    final processes = result['runningProcesses'] ?? result['processes'];
    if (processes is! List) {
      throw StateError('Xcode did not return the running processes.');
    }
    final found = <int>[];
    for (final process in processes.whereType<Map>()) {
      final pid = process['processIdentifier'] ?? process['pid'];
      final path = _filePath(process['executable'] ?? process['executableURL']);
      if (pid is! int || path == null) continue;
      if (expected != null && _sameDevicePath(path, expected) ||
          expected == null &&
              previous == pid &&
              p.basename(path) == executable) {
        found.add(pid);
      }
    }
    if (found.length > 1) {
      throw StateError('The iOS process identity is ambiguous.');
    }
    return found.singleOrNull;
  }

  Future<void> terminate(String bundle, int? pid) async {
    if (simulator) {
      await _xcrun(['simctl', 'terminate', id, bundle]);
    } else if (pid != null) {
      await _core(['device', 'process', 'terminate', '--pid', '$pid']);
    }
  }

  Future<IosCommand> debugger(int pid) {
    final proof = "script p=lldb.debugger.GetSelectedTarget().GetProcess(); "
        "print('AEGIS_'+'IOS_DEBUG_'+str(p.GetProcessID())) "
        "if p.GetState() == lldb.eStateStopped else None";
    final exitProof =
        "script print('AEGIS_'+'IOS_DEBUG_EXIT_'+str(p.GetProcessID())) "
        "if p.GetState() == lldb.eStateExited and p.GetExitStatus() >= 0 "
        "and not p.GetExitDescription() else None";
    return IosCommand.start('xcrun', [
      'lldb',
      '--no-lldbinit',
      '--batch',
      if (!simulator) ...['-o', 'device select $id'],
      '-o',
      simulator ? 'process attach --pid $pid' : 'device process attach -p $pid',
      '-o',
      proof,
      '-o',
      'process continue',
      '-o',
      exitProof,
    ]);
  }
}

String? _filePath(Object? value) {
  if (value is! String) return null;
  if (value.startsWith('/')) return value;
  final uri = Uri.tryParse(value);
  return uri?.scheme == 'file' ? uri!.toFilePath() : null;
}

bool _sameDevicePath(String a, String b) =>
    _normalizeDevicePath(a) == _normalizeDevicePath(b);

String _normalizeDevicePath(String path) => p.posix
    .normalize(path.replaceFirst(RegExp(r'^/+'), '/'))
    .replaceFirst(RegExp(r'^/private(?=/var/)'), '');

/// Proves UID 0 over SSH forwarded to the same USB hardware UDID. A
/// pre-trusted SSH host key and key-based authentication are required.
Future<bool> verifyIosJailbreak(String udid, SystemHost host) async {
  final socket = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
  final port = socket.port;
  await socket.close();
  final forward = await IosCommand.start(
      'iproxy', ['-l', '-s', '127.0.0.1', '-u', udid, '$port:22']);
  try {
    await Future<void>.delayed(const Duration(milliseconds: 400));
    if (forward.exitCode != null) return false;
    final result = await host.run(
        'ssh',
        [
          '-o',
          'BatchMode=yes',
          '-o',
          'StrictHostKeyChecking=yes',
          '-o',
          'HostKeyAlias=aegis-$udid',
          '-o',
          'ConnectTimeout=4',
          '-p',
          '$port',
          'root@127.0.0.1',
          'id -u',
        ],
        timeout: const Duration(seconds: 10));
    return forward.exitCode == null && result?.ok == true && result!.out == '0';
  } finally {
    await forward.close();
  }
}

Future<IosCommand> attachIosFrida(String python, String udid, int pid,
        {String? gadgetCache}) =>
    IosCommand.start(
        python,
        [
          '-u',
          '-c',
          '''
import frida, sys, threading
device = frida.get_device(sys.argv[1], timeout=5)
if device.type != "usb" or device.id.lower() != sys.argv[1].lower():
    sys.exit("Frida could not verify the selected USB device.")
pid = int(sys.argv[2])
detached = threading.Event()
session = device.attach(pid)
session.on("detached", lambda *args: detached.set())
ready = threading.Event()
script = session.create_script("send(Process.id)")
def message(message, data):
    if message.get("type") == "send" and message.get("payload") == pid:
        ready.set()
script.on("message", message)
script.load()
if not ready.wait(5) or detached.is_set():
    sys.exit(2)
print("AEGIS_IOS_FRIDA_" + str(pid), flush=True)
detached.wait(45)
''',
          udid,
          '$pid',
        ],
        environment:
            gadgetCache == null ? null : {'XDG_CACHE_HOME': gadgetCache});
