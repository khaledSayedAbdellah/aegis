import 'dart:convert';
import 'dart:io';
import 'package:aegis/aegis.dart';
import 'package:aegis/src/probe/ios_simulator_build.dart';
import 'package:aegis/src/probe/ios_target.dart';
import 'package:test/test.dart';
import 'ipa_test.dart' show fixture, executable;

void main() {
  late Directory root;
  late IpaContext ipa;
  late String product;
  late int builds;
  late List<String> lastBuild;
  var failBuild = false, wrongProduct = false, ambiguous = false;
  void writeApp() {
    Directory(product).createSync(recursive: true);
    File('$product/Info.plist').writeAsStringSync('''<plist><dict>
<key>CFBundleIdentifier</key><string>org.aegis.fixture</string>
<key>CFBundleExecutable</key><string>Probe</string>
<key>CFBundleVersion</key><string>${wrongProduct ? '9' : '1'}</string>
<key>CFBundleShortVersionString</key><string>1.0</string></dict></plist>''');
    File('$product/Probe').writeAsBytesSync(executable(7));
  }

  Future<int> command(String exe, List<String> args, String cwd, File output,
      void Function(String)? log) async {
    expect(exe, 'xcodebuild');
    expect(cwd, root.path);
    if (args.contains('-list')) {
      output.writeAsStringSync(jsonEncode({
        'project': {
          'schemes': ['Probe', if (ambiguous) 'Other']
        }
      }));
    } else if (args.contains('-showBuildSettings')) {
      output.writeAsStringSync(jsonEncode([
        {
          'buildSettings': {
            'PRODUCT_BUNDLE_IDENTIFIER': 'org.aegis.fixture',
            'WRAPPER_EXTENSION': 'app',
            'EXECUTABLE_NAME': 'Probe',
            'PLATFORM_NAME': 'iphonesimulator',
            'TARGET_BUILD_DIR': Directory(product).parent.path,
            'FULL_PRODUCT_NAME': 'Probe.app',
          }
        }
      ]));
    } else {
      builds++;
      lastBuild = args;
      writeApp();
      if (failBuild) return 65;
    }
    return 0;
  }

  setUp(() {
    root = Directory.systemTemp.createTempSync('aegis-native-build-');
    addTearDown(() => root.deleteSync(recursive: true));
    Directory('${root.path}/Probe.xcodeproj').createSync();
    ipa = IpaContext.load(fixture(root).path);
    product =
        '${root.path}/.dart_tool/aegis/native-ios/DerivedData/Build/Products/Release-iphonesimulator/Probe.app';
    builds = 0;
    lastBuild = [];
    failBuild = false;
    wrongProduct = false;
    ambiguous = false;
  });
  test('native app builds with matching identity and verified receipt reuse',
      () async {
    final builder = IosSimulatorBuilder(command: command);
    expect(await builder.ensure(ipa, project: root.path), product);
    expect(
        lastBuild,
        containsAll([
          '-project',
          '${root.path}/Probe.xcodeproj',
          '-scheme',
          'Probe',
          '-configuration',
          'Release',
          'MARKETING_VERSION=1.0',
          'CURRENT_PROJECT_VERSION=1',
          'build'
        ]));
    expect(await builder.ensure(ipa, project: root.path), product);
    expect(builds, 1);
    File('$product/Probe').writeAsBytesSync(executable(2));
    await builder.ensure(ipa, project: root.path);
    expect(builds, 2);
  });
  test('workspace preference and ambiguous schemes require explicit selection',
      () async {
    Directory('${root.path}/Probe.xcworkspace').createSync();
    ambiguous = true;
    final builder = IosSimulatorBuilder(command: command);
    await expectLater(
        builder.ensure(ipa, project: root.path), throwsFormatException);
    expect(builds, 0);
    await builder.ensure(ipa, project: root.path, xcodeScheme: 'Probe');
    expect(lastBuild,
        containsAll(['-workspace', '${root.path}/Probe.xcworkspace']));
  });
  test('failed or mismatched builds cannot authorize reuse', () async {
    final builder = IosSimulatorBuilder(command: command);
    failBuild = true;
    await expectLater(
        builder.ensure(ipa, project: root.path), throwsStateError);
    failBuild = false;
    await builder.ensure(ipa, project: root.path, app: product);
    expect(builds, 2);
    wrongProduct = true;
    await expectLater(
        builder.ensure(ipa, project: root.path, xcodeConfiguration: 'Debug'),
        throwsFormatException);
    expect(
        File('${root.path}/.dart_tool/aegis/native-ios/inputs.json')
            .existsSync(),
        isFalse);
  });
  test('native YAML build settings survive overrides and isolate device target',
      () {
    final config = AegisConfig.parse(
            'ios_xcode_project: App.xcworkspace\nios_xcode_scheme: App Release\nios_xcode_configuration: Release-CI')
        .copyWith(lang: 'ar');
    final selected = resolveIosProbeSelection(
        config: config, project: root.path, target: IosTarget.simulator);
    expect(selected.xcodeProject, '${root.path}/App.xcworkspace');
    expect(selected.xcodeScheme, 'App Release');
    expect(selected.xcodeConfiguration, 'Release-CI');
    expect(
        resolveIosProbeSelection(
                config: config, project: root.path, target: IosTarget.device)
            .xcodeProject,
        isNull);
    expect(
        AegisConfig.parse(
                'ios_xcode_project: <path-to-file>\nios_xcode_scheme: <scheme>')
            .iosXcodeScheme,
        isNull);
  });
}
