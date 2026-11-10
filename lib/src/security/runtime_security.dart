import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:isolate';
import 'package:crypto/crypto.dart';
import '../binary/apk.dart';
import '../binary/ipa.dart';
import '../config.dart';

class RuntimeSecurityResult {
  const RuntimeSecurityResult(this.data,
      {this.requested = true,
      this.configured = true,
      this.scenario = '',
      this.digest = '',
      this.pinnedHosts = const [],
      this.markers = const []});
  final Map<String, Object?> data;
  final bool requested, configured;
  final String scenario, digest;
  final List<String> pinnedHosts, markers;
}

/// Runs only from the explicit `run` workflow. Never from a library static audit.
/// The scenario executable is opt-in local developer code; no shell expansion.
Future<RuntimeSecurityResult> runRuntimeSecurity(
    String artifact, String root, AegisConfig config,
    {required String platform,
    required bool enabled,
    void Function(String)? log}) async {
  if (!enabled) {
    return const RuntimeSecurityResult({}, requested: false, configured: false);
  }
  final raw = config.runtimeSecurity;
  if (raw.isEmpty || raw['enabled'] != true) {
    return const RuntimeSecurityResult({}, configured: false);
  }
  final digest =
      (await sha256.bind(File(artifact).openRead()).first).toString();
  try {
    final command = raw['command'];
    final device = raw['device'];
    if (command is! List ||
        command.isEmpty ||
        command.any((s) => s is! String || s.isEmpty) ||
        device is! String ||
        !RegExp(r'^[a-zA-Z0-9_.:-]+$').hasMatch(device)) {
      throw const FormatException('Invalid runtime command/device');
    }
    if (raw['platform'] != platform) {
      throw const FormatException(
          'Runtime target does not match selected run target');
    }
    List<String> hosts(String key) {
      final value = raw[key] ?? const [];
      if (value is! List ||
          value.length > 20 ||
          value.any((s) =>
              s is! String ||
              !RegExp(r'^[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?$')
                  .hasMatch(s))) {
        throw const FormatException('Invalid hosts');
      }
      return value.cast<String>();
    }

    final endpoints = hosts('hosts'), pinned = hosts('pinned_hosts');
    if (!endpoints.toSet().containsAll(pinned)) {
      throw const FormatException('Pinned hosts must be captured hosts');
    }
    final timeout = raw['timeout_seconds'] ?? 120;
    if (timeout is! int || timeout < 1 || timeout > 600) {
      throw const FormatException('Invalid scenario timeout');
    }
    final markerEnv = raw['marker_env'] ?? const {};
    if (markerEnv is! Map || markerEnv.length > 30) {
      throw const FormatException('Invalid markers');
    }
    final markers = <String, String>{};
    for (final e in markerEnv.entries) {
      if (e.key is! String ||
          !RegExp(r'^[a-zA-Z][a-zA-Z0-9_]{0,39}$').hasMatch(e.key) ||
          e.value is! String) {
        throw const FormatException('Invalid marker label');
      }
      final value = Platform.environment[e.value];
      if (value == null || value.length < 12 || value.length > 1024) {
        throw const FormatException('Missing/short synthetic marker');
      }
      markers[e.key] = value;
    }
    final ipa = platform.startsWith('ios') ? IpaContext.load(artifact) : null;
    final apk = ipa == null ? ApkContext.load(artifact) : null;
    final build = ipa?.build ?? apk?.versionCode;
    if (build == null) throw const FormatException('Missing build identity');
    final cfg = <String, Object?>{
      'root': root,
      'artifact': File(artifact).absolute.path,
      'platform': platform,
      'app_id': ipa?.bundleId ?? apk!.packageName,
      'build': build,
      'executable': ipa?.executable,
      'device': device,
      'command': command,
      'hosts': endpoints,
      'pinned_hosts': pinned,
      'markers': markers,
      'timeout_seconds': timeout,
      if (raw['trusted_ca_dir'] is String &&
          AegisConfig.resolve(root, raw['trusted_ca_dir'] as String)
                  ?.contains('<') ==
              false)
        'trusted_ca_dir':
            AegisConfig.resolve(root, raw['trusted_ca_dir'] as String),
      if (raw['adb'] is String) 'adb': raw['adb'],
      if (raw['mitmdump'] is String) 'mitmdump': raw['mitmdump'],
    };
    final script = await Isolate.resolvePackageUri(
        Uri.parse('package:aegis/src/security/runtime_driver.py'));
    if (script == null) {
      throw const FormatException('Runtime driver unavailable');
    }
    log?.call(
        'aegis: running configured network/storage scenario on $platform ($device).');
    final process = await Process.start(
        raw['python'] as String? ?? 'python3', [script.toFilePath()],
        workingDirectory: root);
    process.stdin.write(jsonEncode(cfg));
    await process.stdin.close();
    var overflow = false;
    Future<String> bounded(Stream<List<int>> stream) async {
      final bytes = <int>[];
      await for (final chunk in stream) {
        if (bytes.length + chunk.length > 2 * 1024 * 1024) {
          overflow = true;
          process.kill();
          continue;
        }
        bytes.addAll(chunk);
      }
      return utf8.decode(bytes, allowMalformed: true);
    }

    final out = bounded(process.stdout), err = bounded(process.stderr);
    late final int code;
    try {
      code =
          await process.exitCode.timeout(Duration(seconds: timeout * 6 + 240));
    } on TimeoutException {
      process.kill(ProcessSignal.sigkill);
      await process.exitCode;
      throw const FormatException('Runtime driver timeout');
    }
    final text = await out;
    await err;
    if (code != 0 || overflow) {
      throw const FormatException('Runtime driver failed');
    }
    final data = jsonDecode(text);
    if (data is! Map<String, dynamic>) {
      throw const FormatException('Invalid runtime result');
    }
    return RuntimeSecurityResult(data,
        scenario: (command.first as String).split('/').last,
        digest: digest,
        pinnedHosts: pinned,
        markers: markers.keys.toList());
  } catch (_) {
    log?.call(
        'aegis: runtime scenario could not be verified; see incomplete checks in the report.');
    return RuntimeSecurityResult(const {
      'errors': ['configuration_or_driver']
    }, digest: digest);
  }
}
