/// All built-in rules.
library;

import 'android_rules.dart';
import 'binary_rules.dart';
import 'dart_rules.dart';
import 'dependency_rules.dart';
import 'ios_rules.dart';
import 'protection_rules.dart';
import 'rule.dart';

/// Rules that read the source project.
const List<Rule> allRules = [
  ...protectionRules,
  ...androidRules,
  ...iosRules,
  ...dartRules,
  ...dependencyRules,
];

/// Rules that read a compiled APK (used with --apk).
const List<Rule> apkRules = binaryRules;
