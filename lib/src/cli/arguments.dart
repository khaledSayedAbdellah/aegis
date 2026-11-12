import 'package:args/args.dart';

const reportFormats = [
  'console',
  'json',
  'md',
  'html',
  'pdf',
  'sarif',
  'azure'
];

const auditModes = ['code', 'apk', 'aab', 'ipa'];

/// Options shared by plain `aegis` and `aegis run`. `run` has friendlier
/// defaults: an HTML report next to the console output, the APK/AAB comes
/// from apk:/aab: in aegis.yaml, and the resilience probe runs on it.
ArgParser auditParser({bool run = false}) => _iosOptions(
    ArgParser()
      ..addOption('profile',
          abbr: 'p',
          help: 'MAS profile: l1, l2, l1+r, l2+r, or a preset '
              '(standard, sensitive, game, banking, fintech, payments, government).')
      ..addOption('apk',
          help:
              'Also audit a release APK or app bundle (.aab), e.g. build/app/outputs/flutter-apk/app-release.apk '
              'or build/app/outputs/bundle/release/app-release.aab. '
              'Without supported source in the project path, only the artifact is audited.')
      ..addOption('ipa', help: 'Audit a release iOS IPA.')
      ..addOption('lang',
          abbr: 'l',
          allowed: ['en', 'ar'],
          help: 'Report file language; terminal output is always English.')
      ..addMultiOption('format',
          abbr: 'f',
          allowed: reportFormats,
          defaultsTo: run ? ['console', 'html', 'pdf'] : ['console'],
          help:
              'Output formats (comma separated). "pdf" writes the score and open findings to <mode>-<profile>-<date>.pdf '
              'next to the other reports, printed with Chrome, Edge or Chromium (or the browser in AEGIS_BROWSER). '
              '"azure" prints Azure Pipelines annotations for new findings.')
      ..addOption('output',
          abbr: 'o',
          defaultsTo: run ? 'build/aegis-report' : 'aegis-report',
          help: 'Report path without extension for file formats.')
      ..addOption('fail-on',
          allowed: ['critical', 'high', 'medium', 'low'],
          help:
              'Exit with code 1 when a finding at or above this severity exists.')
      ..addOption('min-score',
          help: 'Exit with code 1 when the score is below this value.')
      ..addOption('baseline',
          help:
              'Baseline file of accepted findings (default: aegis-baseline.json in the project, '
              'or "baseline:" in aegis.yaml). Known findings are reported separately and do not trigger --fail-on.')
      ..addFlag('update-baseline',
          negatable: false,
          help:
              'Accept all current findings: write them to the baseline file and exit.')
      ..addFlag('ignore-baseline',
          negatable: false,
          help: 'Report every finding as new, ignoring the baseline.')
      ..addFlag('strict',
          negatable: false,
          help: 'Fail if an applicable check could not complete.')
      ..addFlag('offline',
          negatable: false,
          help: 'Skip the OSV vulnerability lookup (no network).')
      ..addFlag('verbose',
          abbr: 'v',
          negatable: false,
          help: 'Show every finding and not-applicable rules.')
      ..addFlag('color', defaultsTo: true, help: 'Colored console output.')
      ..addFlag('list-rules',
          negatable: false, help: 'List all rules and exit.')
      ..addFlag('version',
          negatable: false, help: 'Print the version and exit.')
      ..addFlag('help', abbr: 'h', negatable: false, help: 'Show this help.')
      ..addOption('mode',
          abbr: 'm',
          allowed: auditModes,
          hide: !run,
          allowedHelp: {
            'code':
                'Dart, Kotlin, Java, Swift and Objective-C source plus platform configuration.',
            'apk':
                'Code + the APK at apk: in aegis.yaml + the resilience probe on the two emulators.',
            'aab':
                'Code + the AAB at aab: in aegis.yaml + the resilience probe on the two emulators.',
            'ipa':
                'Code + the IPA at ipa: in aegis.yaml + the iOS resilience probe.',
          },
          help: 'Required audit mode; asked interactively when omitted.')
      ..addOption('probe-cert-sha256',
          hide: !run,
          help:
              'Expected app signing certificate SHA-256 for --probe-apk (hex).')
      ..addOption('probe-apk',
          hide: !run,
          help:
              'For an AAB, the corresponding signed APK, .apks archive or device-specific APK directory.')
      ..addOption('control-avd',
          hide: !run, help: 'Dedicated Aegis AVD for the control launch.')
      ..addOption('root-avd',
          hide: !run,
          help: 'Dedicated rooted Aegis AVD for the root comparison.')
      ..addFlag('probe',
          defaultsTo: true,
          hide: !run,
          help:
              'Run the resilience probe for the audited Android or iOS artifact. '
              '--no-probe runs the static checks only.')
      ..addFlag('runtime-scenario',
          negatable: false,
          hide: !run,
          help:
              'Execute the runtime_security scenario from aegis.yaml. Its command '
              'and tool paths come from the project, so they never run without '
              'this flag.')
      ..addFlag('open',
          defaultsTo: run,
          hide: !run,
          help:
              'Open the HTML report in the browser (only in a terminal, never in CI).'),
    hide: !run);

ArgParser initParser() => ArgParser()
  ..addOption('profile',
      abbr: 'p',
      help: 'l1, l2, l1+r, l2+r or a preset. Asked interactively when omitted.')
  ..addOption('lang',
      abbr: 'l',
      allowed: ['en', 'ar'],
      help:
          'Report file language (default: system language); terminal output is always English.')
  ..addFlag('force',
      negatable: false, help: 'Overwrite an existing aegis.yaml.')
  ..addFlag('help', abbr: 'h', negatable: false, help: 'Show this help.');

ArgParser toolsParser({bool setup = false}) {
  final a = ArgParser()
    ..addOption('lang',
        abbr: 'l',
        allowed: ['en', 'ar'],
        help: 'Compatibility option; terminal output is always English.')
    ..addFlag('ios',
        negatable: false,
        help: 'Check or prepare the iOS probe tools on macOS.')
    ..addFlag('help', abbr: 'h', negatable: false, help: 'Show this help.');
  if (setup) {
    a
      ..addFlag('yes',
          abbr: 'y',
          negatable: false,
          help:
              'Skip installation confirmation; platform selection is still required.')
      ..addFlag('android',
          negatable: false,
          help: 'Prepare Android only, including bundletool for APK/AAB tests.')
      ..addFlag('both',
          negatable: false,
          help: 'Prepare Android first, then iOS (requires macOS for iOS).')
      ..addFlag('aab',
          negatable: false,
          help: 'Compatibility alias for --android (includes bundletool).')
      ..addFlag('remove',
          negatable: false,
          help: "Delete what aegis installed under ~/.aegis and exit.");
  }
  return a;
}

ArgParser rootParser() => auditParser()
  ..addCommand('run', auditParser(run: true))
  ..addCommand('init', initParser())
  ..addCommand('doctor', toolsParser())
  ..addCommand('setup', toolsParser(setup: true))
  ..addCommand('probe', probeParser());

ArgParser _iosOptions(ArgParser parser, {bool hide = false}) => parser
  ..addOption('ios-target',
      hide: hide,
      allowed: ['simulator', 'device'],
      help:
          'IPA runtime target. run asks when omitted; required for non-interactive IPA probes.')
  ..addOption('ios-control-device',
      hide: hide, help: 'UDID of the dedicated stock iPhone/iPad.')
  ..addOption('ios-jailbreak-device',
      hide: hide, help: 'UDID of the dedicated jailbroken iPhone/iPad.')
  ..addOption('ios-resigned-ipa',
      hide: hide,
      help: 'The same iOS app re-signed with a different Apple certificate.')
  ..addOption('ios-simulator',
      hide: hide,
      help: 'UDID of a booted iOS Simulator for the debugger and Frida checks.')
  ..addOption('ios-simulator-app',
      hide: hide,
      help:
          'Matching Simulator .app (automatically built from the Flutter project when missing or mismatched).');

ArgParser probeParser() => _iosOptions(ArgParser()
  ..addOption('lang',
      abbr: 'l',
      allowed: ['en', 'ar'],
      help: 'Compatibility option; terminal output is always English.')
  ..addOption('project',
      help:
          "The app's Flutter project, for its aegis.yaml (default: found from the APK's location).")
  ..addOption('profile',
      help: "MAS profile (default: the project's aegis.yaml, else L1).")
  ..addOption('probe-cert-sha256',
      help: 'Expected app signing certificate SHA-256 for --probe-apk (hex).')
  ..addOption('probe-apk',
      help:
          'For an AAB, the corresponding signed APK, .apks archive or device-specific APK directory.')
  ..addOption('control-avd',
      help: 'Dedicated Aegis AVD for the control launch.')
  ..addOption('root-avd',
      help: 'Dedicated rooted Aegis AVD for the root comparison.')
  ..addMultiOption('only',
      allowed: ['root', 'jailbreak', 'debugger', 'hooking', 'repackage'],
      help: 'Run only these checks.')
  ..addFlag('help', abbr: 'h', negatable: false, help: 'Show this help.'));
