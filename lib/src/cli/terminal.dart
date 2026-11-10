import 'dart:io';

import '../l10n/messages.g.dart';

// Terminal output is always English. Report files use config.lang.
const terminalLang = 'en';
const terminalText = L10n(terminalLang);

/// `ar` when the system language is Arabic, else `en`.
String systemLang() {
  try {
    return Platform.localeName.toLowerCase().startsWith('ar') ? 'ar' : 'en';
  } catch (_) {
    return 'en';
  }
}

void logProbe(String message) => stdout.writeln('  · $message');

void announceAndroidProbe(String package, String controlName) =>
    stdout.writeln(terminalText.aegisRunningOnTheEmulatorThisCanTakeA(
        package: package, controlName: controlName));
