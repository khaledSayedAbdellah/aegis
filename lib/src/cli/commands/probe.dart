import 'dart:io';

import 'package:aegis/aegis.dart';
import 'package:args/args.dart';
import 'package:path/path.dart' as p;

import '../../probe/probe_report.dart';
import '../../services/android_probe.dart';
import '../arguments.dart';
import '../probe_options.dart';
import '../terminal.dart';

Future<int> probeCommand(ArgResults a) async {
  if (a['help'] as bool) {
    stdout.writeln(
        'Usage: aegis probe [app.apk|app.aab|app.ipa] [--project DIR] [--profile P] [--only root,hooking] [--lang en|ar]\n');
    stdout.writeln(
        'Runs the resilience probe on an Android emulator or selected iOS target.');
    stdout.writeln(
        'Use an app path or configure apk:, aab: or ipa: in aegis.yaml.');
    stdout.writeln('iOS target options select ipa: when no path is given.\n');
    stdout.writeln(probeParser().usage);
    return 0;
  }

  // An explicit path wins over the configured artifact.
  // The project is --project, else the one the given file sits in, else the
  // current folder; its aegis.yaml also gives the profile.
  final projectArg = a['project'] as String?;
  var appPath = a.rest.isNotEmpty ? a.rest.first : null;
  final projectDir =
      projectArg ?? (appPath == null ? null : projectOf(appPath)) ?? '.';
  AegisConfig config;
  try {
    config = AegisConfig.load(p.absolute(projectDir));
  } on FormatException catch (e) {
    stderr.writeln(e.message);
    return 2;
  }
  final only = (a['only'] as List<String>).toSet();
  final wantsIos = only.contains('jailbreak') ||
      [
        'ios-target',
        'ios-control-device',
        'ios-jailbreak-device',
        'ios-resigned-ipa',
        'ios-simulator',
        'ios-simulator-app'
      ].any((option) => a[option] != null);
  if (appPath == null) {
    final value =
        wantsIos ? config.ipa : config.apk ?? config.aab ?? config.ipa;
    if (value == null) {
      stderr.writeln(wantsIos
          ? (terminalText.aegisSetIpaInAegisYamlOrPassTheIpa)
          : terminalText.aegisSetTheAppSPathInAegisYamlRelativeTo(
              flutterApkDir: flutterApkDir));
      return 2;
    }
    appPath = AegisConfig.resolve(p.absolute(projectDir), value)!;
  }
  if (!File(appPath).existsSync()) {
    stderr.writeln('File not found: $appPath');
    return 2;
  }

  final profileArg = a['profile'] as String?;
  if (profileArg != null) {
    final profile = ProfileSet.tryParse(profileArg);
    if (profile == null) {
      stderr.writeln(
          'Unknown profile "$profileArg". Use l1, l2, l1+r, l2+r or a preset.');
      return 2;
    }
    config = config.copyWith(profile: profile);
  }
  final profileFrom = profileArg != null
      ? '--profile'
      : (config.file != null
          ? p.relative(config.file!)
          : (terminalText.aegisDefault));
  stdout.writeln(terminalText.aegisProfileFrom(
      value1: config.profile, profileFrom: profileFrom));

  if (appPath.toLowerCase().endsWith('.ipa')) {
    final outcome = await runConfiguredIosProbe(
        appPath, a, config, p.absolute(projectDir),
        only: only.isEmpty ? null : only);
    final report = outcome.report;
    if (report == null) {
      stderr.writeln(outcome.skippedOf(terminalLang));
      return 2;
    }
    stdout.write(renderProbe(report,
        lang: terminalLang, resilienceProfile: config.profile.resilience));
    return probeExitCode(report, resilienceProfile: config.profile.resilience);
  }
  if (wantsIos) {
    stderr.writeln(terminalText.aegisIosProbeOptionsRequireAnIpa);
    return 2;
  }

  bool? obfuscated;
  try {
    obfuscated = _looksObfuscated(ApkContext.load(appPath));
  } on FormatException catch (e) {
    stderr.writeln(e.message);
    return 2;
  }

  final outcome = await runAndroidProbe(appPath,
      log: logProbe,
      onRunning: announceAndroidProbe,
      config: config,
      projectRoot: p.absolute(projectDir),
      only: only.isEmpty ? null : only,
      signedApk: a['probe-apk'] as String?,
      expectedSigner: a['probe-cert-sha256'] as String?,
      rootAvd: a['root-avd'] as String?,
      controlAvd: a['control-avd'] as String?);
  final report = outcome.report;
  if (report == null) {
    stderr.writeln(outcome.skippedOf(terminalLang));
    return 2;
  }
  stdout.writeln('');
  stdout.write(renderProbe(report,
      lang: terminalLang, resilienceProfile: config.profile.resilience));
  if (obfuscated != null) {
    final mode = appPath.toLowerCase().endsWith('.aab') ? 'aab' : 'apk';
    stdout.writeln('');
    stdout.writeln(obfuscated
        ? (terminalText.aegisStaticReverseEngineeringThisBuildIsObfuscated)
        : (terminalText.aegisStaticReverseEngineeringThisBuildIsNotObfuscated(
            mode: mode)));
  }
  return probeExitCode(report, resilienceProfile: config.profile.resilience);
}

/// A quick obfuscation signal for the probe's static line: a non-obfuscated
/// Flutter build keeps its source paths (package:.../*.dart) in libapp.so,
/// which --obfuscate strips. Null when there is no libapp.so to judge.
/// The full check is AEG-B07 in the APK audit.
bool? _looksObfuscated(ApkContext apk) {
  if (apk.libappEntry == null) return null;
  final sourcePaths = apk.libappStrings
      .where((s) => s.startsWith('package:') && s.endsWith('.dart'))
      .length;
  return sourcePaths < 20;
}
