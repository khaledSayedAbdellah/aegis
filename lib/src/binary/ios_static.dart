/// Offline IPA hardening facts and resilience references, separate from probes.
library;

import '../plist.dart';
import 'macho_security.dart';
import 'zip.dart';

class IosStaticBinary {
  IosStaticBinary(this.path, this.slices, {this.issue});
  final String path;
  final List<MachSecurity> slices;
  final String? issue;
}

class IosStaticEvidence {
  IosStaticEvidence(this.file, this.architecture, this.source, this.token);
  final String file, architecture, source, token;
  String? owner, kind, value;
  int? offset;
  Map<String, Object?> toJson() => {
        'file': file,
        'architecture': architecture,
        'source': source,
        'token': token,
        if (value != null) 'value': value,
        if (owner != null) 'owner': owner,
        if (kind != null) 'kind': kind,
        if (offset != null && offset! >= 0) 'sliceOffset': offset,
      };
}

class IosStaticSignal {
  IosStaticSignal(this.id, this.evidence, {required this.limited});
  final String id;
  final List<IosStaticEvidence> evidence;
  final bool limited;
  String get status => evidence.isNotEmpty
      ? 'observed'
      : limited
          ? 'unavailable'
          : 'not_observed';
}

class IosStaticAnalysis {
  IosStaticAnalysis(this.binaries);
  final List<IosStaticBinary> binaries;
  bool get complete => binaries.every((b) => b.issue == null);
  bool get limited =>
      !complete ||
      binaries.any((b) => b.slices.any((s) =>
          s.encrypted ||
          !s.symbolTable ||
          s.stringsLimited ||
          s.metadata.limited));

  late final List<IosStaticSignal> signals = [
    for (final entry in _patterns.entries)
      IosStaticSignal(
          entry.key,
          [
            for (final binary in binaries)
              for (final slice in binary.slices)
                ..._matches(binary.path, slice, entry.value,
                    symbolsOnly:
                        entry.key == 'arc' || entry.key == 'stack_canary'),
          ],
          limited: limited),
  ];

  Map<String, Object?> toJson() => {
        'kind': 'static',
        'runtimeVerified': false,
        'complete': complete,
        'limited': limited,
        'signals': [
          for (final signal in signals)
            {
              'id': signal.id,
              'status': signal.status,
              'limited': signal.limited,
              'evidence': signal.evidence.map((e) => e.toJson()).toList(),
            }
        ],
        'binaries': [
          for (final b in binaries)
            {
              'file': b.path,
              if (b.issue != null) 'issue': b.issue,
              'slices': [
                for (final s in b.slices)
                  {
                    'architecture': s.architecture,
                    'fileType': s.fileType,
                    'pie': s.fileType == 2 ? s.pie : null,
                    'executableStackRequested': s.executableStackRequested,
                    'writableExecutableSegments': s.writableExecutableSegments,
                    'codeSignatureBlobPresent': s.signatureBlob,
                    'encrypted': s.encrypted,
                    'symbolTablePresent': s.symbolTable,
                    'stringsLimited': s.stringsLimited,
                    'metadata': s.metadata.toJson(),
                    'debugSymbolCount': s.symbolTable ? s.debugSymbols : null,
                    'rpaths': s.rpaths,
                  }
              ],
            }
        ],
      };
}

// References are evidence for review, never a pass/fail protection verdict.
final _patterns = <String, RegExp>{
  'jailbreak': RegExp(
      r'isJailbroken|isJailBreak|jailbreakDetected|amIJailbroken|JailbreakDetector|JailbreakDetection|/Applications/(?:Cydia|Sileo|Zebra)\.app|/Library/MobileSubstrate|/var/jb(?:/|$)|/usr/sbin/sshd|/etc/apt(?:/|$)|cydia://|/private/var/lib/apt',
      caseSensitive: false),
  'debugger': RegExp(
      r'ptrace|sysctl|isDebuggerAttached|amIBeingDebugged|task_get_exception_ports',
      caseSensitive: false),
  'hooking': RegExp(
      r'frida|MSHookFunction|MSHookMessageEx|amIReverseEngineered|amIRuntimeHooked|FridaGadget|libcycript|cynject',
      caseSensitive: false),
  'signing': RegExp(
      r'SecCodeCheckValidity|SecStaticCodeCheckValidity|SecCodeCopySigningInformation|amITampered|hasValidSignature|verifyAppSignature|checkCodeSignature|validateCodeSignature|embedded\.mobileprovision|_CodeSignature/CodeResources|application-identifier',
      caseSensitive: false),
  'stack_canary': RegExp(r'^_+stack_chk_(?:fail|guard)$'),
  'arc': RegExp(r'^_(?:objc|swift)_(?:release|retain|storeStrong)$'),
};

Iterable<IosStaticEvidence> _matches(
    String path, MachSecurity slice, RegExp pattern,
    {bool symbolsOnly = false}) sync* {
  final seen = <String>{};
  if (!symbolsOnly) {
    for (final entry in slice.metadata.entries) {
      for (final match in pattern.allMatches(entry.qualifiedName)) {
        final token = match.group(0)!;
        if (!seen.add('${entry.source}:${entry.kind}:${entry.owner}:$token')) {
          continue;
        }
        yield IosStaticEvidence(path, slice.architecture, entry.source, token)
          ..owner = entry.owner
          ..kind = entry.kind
          ..value = entry.name
          ..offset = entry.offset;
        if (seen.length >= 8) return;
      }
    }
  }
  for (final (source, values) in [
    ('symbol', slice.symbols),
    if (!symbolsOnly) ('string', slice.strings)
  ]) {
    for (final value in values) {
      for (final match in pattern.allMatches(value)) {
        final token = match.group(0)!;
        if (!seen.add('$source:$token')) continue;
        yield IosStaticEvidence(path, slice.architecture, source, token);
        if (seen.length >= 8) return;
      }
    }
  }
}

IosStaticAnalysis analyzeIpaStatic(
    ZipReader archive, String appPath, String executable) {
  final candidates = <String>{'$appPath/$executable'};
  final issues = <IosStaticBinary>[];
  for (final path in archive.entries.keys) {
    if (!path.startsWith('$appPath/')) continue;
    if (path.endsWith('.dylib')) candidates.add(path);
    final framework = RegExp(r'/([^/]+)\.framework/([^/]+)$').firstMatch(path);
    if (framework != null && framework[1] == framework[2]) candidates.add(path);
    if (!RegExp(r'\.(?:framework|appex)/Info\.plist$').hasMatch(path)) continue;
    try {
      final entry = archive.entries[path]!;
      if (entry.size > 1024 * 1024) {
        throw const FormatException('Bundle plist too large.');
      }
      final info = decodeApplePlist(archive.readEntry(entry));
      final name = info?['CFBundleExecutable'];
      if (name is String &&
          RegExp(r'^[a-zA-Z0-9_.+-]+$').hasMatch(name) &&
          name != '.' &&
          name != '..') {
        candidates.add('${path.substring(0, path.lastIndexOf('/'))}/$name');
      } else {
        throw const FormatException('Invalid bundle executable.');
      }
    } on FormatException {
      issues.add(IosStaticBinary(path, const [],
          issue: 'Unreadable bundle Info.plist.'));
    }
  }
  final binaries = <IosStaticBinary>[...issues];
  var total = 0;
  final ordered = candidates.toList()..sort();
  for (final path in ordered) {
    if (binaries.length >= 128) {
      binaries.add(IosStaticBinary(path, const [],
          issue: 'Binary count exceeds analysis limit.'));
      break;
    }
    try {
      final entry = archive.entries[path];
      if (entry == null || entry.isSymlink || entry.isDirectory) {
        throw const FormatException('Missing or unsupported binary entry.');
      }
      total += entry.size;
      if (entry.size > 128 * 1024 * 1024 || total > 512 * 1024 * 1024) {
        throw const FormatException('Binary bytes exceed analysis limit.');
      }
      final bytes = archive.readEntry(entry);
      binaries.add(IosStaticBinary(path, inspectMachSecurity(bytes)));
    } on FormatException catch (e) {
      binaries.add(IosStaticBinary(path, const [], issue: e.message));
    } on RangeError {
      binaries.add(
          IosStaticBinary(path, const [], issue: 'Truncated binary entry.'));
    }
  }
  return IosStaticAnalysis(binaries);
}
