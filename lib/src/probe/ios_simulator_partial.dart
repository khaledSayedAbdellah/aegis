/// Scoped Simulator experiments. Never changes host security or system files.
library;

import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:path/path.dart' as p;

import '../binary/ios_signature.dart';
import '../l10n/messages.g.dart';
import 'ios_device.dart';

const jailbreakLimit = En.jailbreakLimit;
const jailbreakLimitAr = Ar.jailbreakLimit;
const signingLimit = En.signingLimit;
const signingLimitAr = Ar.signingLimit;

String _nonce() => base64UrlEncode(
    List<int>.generate(24, (_) => Random.secure().nextInt(256)));

class SimulatorIndicators {
  SimulatorIndicators(this.library, this.directory, this.file, this.data);
  final String library, directory, file, data;

  static Future<SimulatorIndicators> prepare(
      IosDevice device, String bundle) async {
    final work = Directory(p.join(device.work.path, 'simulator-indicators'))
      ..createSync();
    final data = await device.simulatorDataPath(bundle);
    final fixtures =
        Directory(p.join(data, 'tmp', 'aegis-indicators-${_nonce()}'))
          ..createSync();
    final directory = Directory(p.join(fixtures.path, 'directory'))
      ..createSync();
    final file = File(p.join(fixtures.path, 'library'))
      ..writeAsStringSync('aegis test fixture');
    final source = File(p.join(work.path, 'indicators.m'))
      ..writeAsStringSync(simulatorIndicatorSource);
    final library = p.join(work.path, 'Indicators.dylib');
    final build = await device.host.run(
        'xcrun',
        [
          '--sdk',
          'iphonesimulator',
          'clang',
          '-dynamiclib',
          '-fobjc-arc',
          '-arch',
          'arm64',
          '-arch',
          'x86_64',
          '-mios-simulator-version-min=15.0',
          '-framework',
          'Foundation',
          source.path,
          '-o',
          library,
        ],
        timeout: const Duration(minutes: 2));
    if (build?.ok != true) {
      throw StateError(
          'Could not compile the Simulator indicator helper: ${build?.text}');
    }
    final sign =
        await device.host.run('/usr/bin/codesign', ['-f', '-s', '-', library]);
    if (sign?.ok != true) {
      throw StateError('Could not sign the Simulator indicator helper.');
    }
    return SimulatorIndicators(library, directory.path, file.path, data);
  }

  IndicatorSession session({required bool enabled}) {
    final nonce = _nonce();
    final proof = File(p.join(data, 'tmp', 'aegis-indicator-proof-$nonce'));
    return IndicatorSession(proof, nonce, {
      'AEGIS_INDICATORS_ENABLED': enabled ? '1' : '0',
      'AEGIS_INDICATORS_NONCE': nonce,
      'AEGIS_INDICATORS_PROOF': proof.path,
      'AEGIS_INDICATORS_DIRECTORY': directory,
      'AEGIS_INDICATORS_FILE': file,
    });
  }
}

class IndicatorSession {
  IndicatorSession(this.proof, this.nonce, this.environment);
  final File proof;
  final String nonce;
  final Map<String, String> environment;

  List<String> events(int pid) {
    if (FileSystemEntity.typeSync(proof.path, followLinks: false) !=
            FileSystemEntityType.file ||
        proof.lengthSync() > 65536) {
      return [];
    }
    return proof
        .readAsLinesSync()
        .where((line) => line.startsWith('$nonce:$pid:'))
        .map((line) => line.substring('$nonce:$pid:'.length))
        .toList();
  }
}

// Not `hash`: Dart 3.0 rejects record fields named like any `Object` member,
// including the static `Object.hash`.
typedef SimulatorSignature = ({String identifier, String cdHash});

Future<SimulatorSignature> simulatorSignature(
    IosDevice device, String app) async {
  final verify = await device.host
      .run('/usr/bin/codesign', ['--verify', '--deep', '--strict', app]);
  final display = await device.host
      .run('/usr/bin/codesign', ['--display', '--verbose=4', app]);
  final text = display?.text ?? '';
  final id =
      RegExp(r'^Identifier=(.+)$', multiLine: true).firstMatch(text)?.group(1);
  final hash = RegExp(r'^CDHash=([a-fA-F0-9]+)$', multiLine: true)
      .firstMatch(text)
      ?.group(1);
  if (verify?.ok != true || display?.ok != true || id == null || hash == null) {
    throw StateError(
        'Could not verify the Simulator CodeDirectory signature: ${verify?.text}');
  }
  return (identifier: id.trim(), cdHash: hash.toLowerCase());
}

Future<({String app, SimulatorSignature before, SimulatorSignature after})>
    prepareSimulatorResign(IosDevice device, String original) async {
  final before = await simulatorSignature(device, original);
  final folder = Directory(p.join(device.work.path, 'simulator-resigned'))
    ..createSync();
  final alternate = p.join(folder.path, p.basename(original));
  final copy = await device.host.run('/usr/bin/ditto', [original, alternate]);
  if (copy?.ok != true) {
    throw StateError('Could not copy the Simulator app.');
  }
  final identifier = '${before.identifier}.aegis.partial.${_nonce()}';
  final sign = await device.host.run(
      '/usr/bin/codesign',
      [
        '--force',
        '--sign',
        '-',
        '--identifier',
        identifier,
        '--preserve-metadata=entitlements,flags,runtime',
        alternate,
      ],
      timeout: const Duration(minutes: 2));
  if (sign?.ok != true) {
    throw StateError(
        'Could not re-sign the temporary Simulator app: ${sign?.text}');
  }
  final after = await simulatorSignature(device, alternate);
  if (after.identifier != identifier || after.cdHash == before.cdHash) {
    throw StateError('The Simulator signature change was not verified.');
  }
  final scratch = Directory(p.join(folder.path, 'unsigned'))..createSync();
  final a = await iosUnsignedPayload(original, scratch);
  final b = await iosUnsignedPayload(alternate, scratch);
  if (a.length != b.length || a.entries.any((e) => b[e.key] != e.value)) {
    throw StateError('The Simulator copy differs beyond its signing data.');
  }
  return (app: alternate, before: before, after: after);
}

// Injected only into the selected Simulator app. All fixtures and evidence are
// inside its temporary data container. No host paths are created or modified.
const simulatorIndicatorSource = r'''
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
static bool enabled = false, testing = true;
static int evidence = -1;
static const char *nonce, *directoryPath, *filePath;
static _Atomic unsigned queries;
static void event(const char *kind) {
  if (evidence >= 0) dprintf(evidence, "%s:%d:%s\n", nonce, getpid(), kind);
}
static const char *mapped(const char *path) {
  if (!enabled || !path) return path;
  bool directory = !strcmp(path, "/Applications/Cydia.app") || !strcmp(path, "/var/jb");
  bool file = !strcmp(path, "/Library/MobileSubstrate/MobileSubstrate.dylib") ||
              !strcmp(path, "/var/jb/usr/lib/libjailbreak.dylib");
  if (!directory && !file) return path;
  if (!testing && atomic_fetch_add(&queries, 1) < 64) {
    if (evidence >= 0) dprintf(evidence, "%s:%d:query:%s\n", nonce, getpid(), path);
  }
  return directory ? directoryPath : filePath;
}
static int probe_access(const char *path, int mode) { return access(mapped(path), mode); }
static int probe_stat(const char *path, struct stat *value) { return stat(mapped(path), value); }
static int probe_lstat(const char *path, struct stat *value) { return lstat(mapped(path), value); }
#define INTERPOSE(replacement, original) \
  __attribute__((used)) static struct { const void *a; const void *b; } interpose_##original \
  __attribute__((section("__DATA,__interpose"))) = { (const void *)&replacement, (const void *)&original };
INTERPOSE(probe_access, access)
INTERPOSE(probe_stat, stat)
INTERPOSE(probe_lstat, lstat)
static BOOL (*originalExists)(id, SEL, NSString *);
static BOOL (*originalExistsDirectory)(id, SEL, NSString *, BOOL *);
static NSString *mappedString(NSString *path) {
  const char *value = path.fileSystemRepresentation;
  const char *redirect = mapped(value);
  return redirect == value ? path : [NSString stringWithUTF8String:redirect];
}
static BOOL exists(id obj, SEL cmd, NSString *path) { return originalExists(obj, cmd, mappedString(path)); }
static BOOL existsDirectory(id obj, SEL cmd, NSString *path, BOOL *dir) {
  return originalExistsDirectory(obj, cmd, mappedString(path), dir);
}
static void exited(void) { event("normal-exit"); }
__attribute__((constructor)) static void setup(void) {
  @autoreleasepool {
    nonce = getenv("AEGIS_INDICATORS_NONCE");
    const char *proof = getenv("AEGIS_INDICATORS_PROOF");
    directoryPath = getenv("AEGIS_INDICATORS_DIRECTORY");
    filePath = getenv("AEGIS_INDICATORS_FILE");
    const char *flag = getenv("AEGIS_INDICATORS_ENABLED");
    if (!nonce || !proof || !directoryPath || !filePath || !flag) return;
    evidence = open(proof, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (evidence < 0) return;
    enabled = !strcmp(flag, "1");
    Method m = class_getInstanceMethod([NSFileManager class], @selector(fileExistsAtPath:));
    Method d = class_getInstanceMethod([NSFileManager class], @selector(fileExistsAtPath:isDirectory:));
    if (!m || !d) { event("failed"); return; }
    originalExists = (void *)method_setImplementation(m, (IMP)exists);
    originalExistsDirectory = (void *)method_setImplementation(d, (IMP)existsDirectory);
    struct stat s;
    BOOL isDir = NO;
    BOOL ok = access(directoryPath, F_OK) == 0 && access(filePath, F_OK) == 0;
    if (enabled) {
      ok = ok && probe_access("/Applications/Cydia.app", F_OK) == 0 &&
        probe_stat("/var/jb", &s) == 0 && S_ISDIR(s.st_mode) &&
        probe_lstat("/Library/MobileSubstrate/MobileSubstrate.dylib", &s) == 0 &&
        [[NSFileManager defaultManager] fileExistsAtPath:@"/var/jb/usr/lib/libjailbreak.dylib"] &&
        [[NSFileManager defaultManager] fileExistsAtPath:@"/Applications/Cydia.app" isDirectory:&isDir] && isDir;
    }
    if (!ok) { event("failed"); return; }
    atexit(exited);
    event("ready");
    testing = false;
  }
}
''';
