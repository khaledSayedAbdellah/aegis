/// All built-in rules.
library;

import 'android_rules.dart';
import 'assert_rules.dart';
import 'backend_rules.dart';
import 'platform_security_rules.dart';
import 'platform_protection_rules.dart';
import 'native_security_rules.dart';
import 'native_library_rules.dart';
import 'package_hygiene_rules.dart';
import 'platform_ipc_rules.dart';
import 'native_source_rules.dart';
import 'source_coverage_rule.dart';
import 'elf_rules.dart';
import 'tracker_rules.dart';
import 'ui_leak_rules.dart';
import 'binary_rules.dart';
import 'dart_rules.dart';
import 'debug_tool_rules.dart';
import 'deep_link_rules.dart';
import 'deserialization_rules.dart';
import 'dependency_rules.dart';
import 'injection_rules.dart';
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
  ...backendRules,
  ...injectionRules,
  DeepLinkActionRule(),
  UnsafeDeserializationRule(),
  ...debugToolRules,
  ...assertRules,
  ...uiLeakRules,
  PackageHygieneRule(),
  ...platformIpcRules,
];

/// Rules that read a compiled APK (used with --apk).
const List<Rule> apkRules = [
  ...binaryRules,
  DebugToolApkRule(),
  OldNativeLibraryApkRule(),
  V1OnlySignatureRule(),
  FileProviderApkRule(),
  DynamicCodeApkRule(),
];

// Run once for either source or artifact. Each rule selects the authoritative
// final manifest when available and retains source-only scope explicitly.
const extendedRules = <Rule>[
  SourceCoverageRule(),
  NativeSourceRule(),
  NativeSourceRule(logging: true),
  ...platformProtectionRules,
  AndroidLinksRule(),
  AndroidPermissionStrengthRule(),
  AndroidAssociationRule(),
  NativeSecurityRule('AEG-N01'),
  NativeSecurityRule('AEG-N02'),
  NativeSecurityRule('AEG-N03'),
  NativeSecurityRule('AEG-N04'),
  IosEntitlementScopeRule(),
  AtsForwardSecrecyRule(),
  ElfHardeningRule(),
  TrackerInventoryRule(),
];
