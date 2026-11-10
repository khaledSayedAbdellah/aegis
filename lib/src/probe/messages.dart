/// en/ar strings for `aegis doctor` and `aegis setup`.
library;

import '../l10n/messages.g.dart';

import 'pins.dart' as pins;
import 'toolchain.dart';

/// Human titles for each tool id, in both languages.


class Msg {
  const Msg(this.lang, {this.ios = false});
  final String lang;
  final bool ios;
  bool get ar => lang == 'ar';
  String get _setupCommand => ios ? 'aegis setup --ios' : 'aegis setup --android';


  String title(String id) => switch (id) {
      'flutter' => L10n(lang).toolFlutter,
      'java' => L10n(lang).toolJava,
      'android-sdk' => L10n(lang).toolAndroidSdk,
      'cmdline-tools' => L10n(lang).toolCmdlineTools,
      'platform-tools' => L10n(lang).toolPlatformTools,
      'build-tools' => L10n(lang).toolBuildTools,
      'emulator' => L10n(lang).toolEmulator,
      'system-image' => L10n(lang).toolSystemImage,
      'control-image' => L10n(lang).toolControlImage,
      'control-avd' => L10n(lang).toolControlAvd(control: pins.controlAvdName),
      'avd' => L10n(lang).toolAvd(avd: pins.avdName),
      'python' => L10n(lang).toolPython,
      'frida' => L10n(lang).toolFrida,
      'frida-server' => L10n(lang).toolFridaServer,
      'ios-gadget' => L10n(lang).toolIosGadget,
      'ios-simulator-gadget' => L10n(lang).toolIosSimulatorGadget,
      'xcode' => L10n(lang).toolXcode,
      'bundletool' => L10n(lang).toolBundletool,
      _ => id,
    };

  String get header => L10n(lang).messagesResilienceProbeTools;

  /// The reason line shown after a tool that is not simply present.
  String issue(ToolCheck c) {
    final d = c.detail;
    return switch (c.issue) {
      Issue.flutterMissing => L10n(lang).messagesNotFoundOnPathInstallFlutter,
      Issue.javaMissing => L10n(lang).messagesNoJdkFoundInstallAndroidStudioOr,
      Issue.javaOld => L10n(lang).messagesFoundJavaButIsNeeded(value1: d['found'], value2: d['need']),
      Issue.sdkMissing => L10n(lang).messagesNotFoundInstallAndroidStudioBringsThe,
      Issue.cmdlineMissing => L10n(lang).messagesMissingAndroidStudioSettingsLanguages,
      Issue.buildToolsOld => L10n(lang).messagesTooOldAegisInstalls(value1: pins.buildToolsVersion),
      Issue.pythonMissing => L10n(lang).messagesNoPython39FoundInstallItThen,
      Issue.pythonOld => L10n(lang).messagesPythonIsTooOldNeed(value1: c.version, value2: pins.minPython.$1, value3: pins.minPython.$2),
      Issue.pythonNoVenv => L10n(lang).messagesThisPythonHasNoVenvModuleInstall,
      Issue.fridaOtherVersion => L10n(lang).messagesHaveNeed(value1: d['have'], value2: d['want']),
      Issue.xcodeMissing => L10n(lang).messagesRequiresMacosWithXcodeSelectedViaXcodeSelect,
      Issue.optionalAab => L10n(lang).messagesOptionalOnlyForAabAegisSetupAab,
      Issue.missing || null => L10n(lang).messagesNotInstalled,
    };
  }

  /// The short note after an installable row in `doctor`.
  String get installHint =>
      L10n(lang).messagesInstallsIt(value1: _setupCommand);

  /// [installHint] with the flag the tool needs (bundletool only with --aab).
  String installHintFor(String id) => id == 'bundletool'
      ? L10n(lang).messagesAegisSetupAabInstallsIt
      : installHint;

  String toInstall(int n) => L10n(lang).toolsMissing(count: n, command: _setupCommand);

  String get allPresent =>
      L10n(lang).messagesEverythingTheProbeNeedsIsInstalled;

  String get someManual => L10n(lang).messagesSomeToolsYouInstallYourselfSeeAboveThen(value1: _setupCommand);

  // setup
  String get willInstall => L10n(lang).messagesWillInstall;
  String get alreadyThere => L10n(lang).messagesPresentSkipped;
  String installYourself(ToolCheck c) =>
      L10n(lang).messagesInstallItYourself + issue(c);
  String waitingFor(List<String> needs) => L10n(lang).messagesWaitingFor(value1: (lang == 'ar' ? needs.join('، ') : needs.join(', ')));
  String get licensesNote => L10n(lang).messagesTheAndroidSdkToolsWillAskYouTo;
  String get confirm => L10n(lang).messagesContinueYN;
  String get cancelled => L10n(lang).messagesCancelled;
  String get noTerminal =>
      L10n(lang).messagesNoTerminalUseYes(value1: _setupCommand);
  String get nothingToInstall =>
      L10n(lang).messagesNothingToInstall;
  String get removed =>
      L10n(lang).messagesRemovedWhatAegisInstalled;
  String get nothingToRemove => L10n(lang).messagesNothingToRemoveAegisHadInstalledNothing;
  String get done => L10n(lang).messagesDone;
  String get result => L10n(lang).messagesResult;
  String savedTo(String path) =>
      L10n(lang).messagesPathsSavedTo(path: path);
  String get stillMissing => L10n(lang).messagesSomeToolsAreStillMissingSeeAbove;
  String freeSpaceWarning(String need, String have) => L10n(lang).messagesTheSystemImageNeedsFreeYouHave(need: need, have: have);
  String step(String title) => L10n(lang).messagesInstalling(title: title);
}

/// Yes answers accepted at the setup prompt.
const yesAnswers = ['y', 'yes', 'اه', 'أه', 'أيوه', 'ايوه', 'نعم', 'ن'];
