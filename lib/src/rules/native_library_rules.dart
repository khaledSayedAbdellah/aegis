/// Old C libraries compiled into an APK or IPA, found by their version
/// strings.
library;

import 'dart:convert';

import '../l10n/messages.g.dart';
import '../model.dart';
import '../project.dart';
import '../security/evidence.dart';
import 'rule.dart';

const _all = {MasProfile.l1, MasProfile.l2, MasProfile.r};

/// A library version found in a binary.
class NativeLibraryVersion {
  NativeLibraryVersion(this.library, this.version, this.file);
  final String library, version, file;
}

/// Library -> pattern whose first group is the version.
final _versionPatterns = <String, RegExp>{
  'OpenSSL': RegExp(r'\bOpenSSL (\d+\.\d+\.\d+[a-z]{0,2})\b'),
  'zlib': RegExp(r'\b(?:de|in)flate (\d+\.\d+\.\d+(?:\.\d+)?) Copyright'),
  'libpng': RegExp(r'\blibpng version (\d+\.\d+\.\d+)'),
  'libcurl': RegExp(r'\blibcurl/(\d+\.\d+\.\d+)'),
};

/// Versions with critical published vulnerabilities: library -> (the first
/// safe version, or null when the whole branch is end of life, the
/// advisory, and the versions it applies to).
final _vulnerable =
    <String, List<(String? fixed, String advisory, bool Function(List<int>))>>{
  // Branches past their end of life: 1.0.2 and 1.1.1 (2019, 2023),
  // 3.0 (2026-09-07), 3.1 (2025-03-14), 3.2 (2025-11-23).
  'OpenSSL': [
    (
      null,
      'that branch is past its end of life and gets no security fixes',
      (v) => v[0] < 3 || (v[0] == 3 && v[1] <= 2)
    ),
  ],
  'zlib': [
    ('1.2.13', 'CVE-2022-37434, CVE-2018-25032', (v) => _less(v, [1, 2, 13])),
  ],
  'libpng': [
    ('1.6.37', 'CVE-2019-7317', (v) => _less(v, [1, 6, 37])),
  ],
  'libcurl': [
    ('8.4.0', 'CVE-2023-38545', (v) => _less(v, [8, 4, 0])),
  ],
};

bool _less(List<int> a, List<int> b) {
  for (var i = 0; i < b.length; i++) {
    final x = i < a.length ? a[i] : 0;
    if (x != b[i]) return x < b[i];
  }
  return false;
}

List<int> _numbers(String version) =>
    RegExp(r'\d+').allMatches(version).map((m) => int.parse(m[0]!)).toList();

/// Version strings of the known libraries in [text].
Iterable<NativeLibraryVersion> findLibraryVersions(
    String text, String file) sync* {
  final seen = <String>{};
  for (final e in _versionPatterns.entries) {
    for (final m in e.value.allMatches(text)) {
      if (seen.add('${e.key} ${m[1]}')) {
        yield NativeLibraryVersion(e.key, m[1]!, file);
      }
    }
  }
}

/// The advisory for [v], or null when its version has none in the table.
(String? fixed, String advisory)? vulnerability(NativeLibraryVersion v) {
  final numbers = _numbers(v.version);
  for (final entry in _vulnerable[v.library] ??
      const <(String?, String, bool Function(List<int>))>[]) {
    if (numbers.length >= 3 && entry.$3(numbers)) return (entry.$1, entry.$2);
  }
  return null;
}

RuleCheck _report(Rule rule, Project project, List<NativeLibraryVersion> found,
    String artifact) {
  final out = <Finding>[];
  for (final v in found) {
    final hit = vulnerability(v);
    if (hit == null) continue;
    final (fixed, advisory) = hit;
    final (en, ar) = fixed == null
        ? (
            En.oldLibraryEol(
                library: v.library,
                version: v.version,
                artifact: artifact,
                note: advisory),
            Ar.oldLibraryEol(
                library: v.library,
                version: v.version,
                artifact: artifact,
                note: advisory)
          )
        : (
            En.oldLibrary(
                library: v.library,
                version: v.version,
                artifact: artifact,
                fixed: fixed,
                advisory: advisory),
            Ar.oldLibrary(
                library: v.library,
                version: v.version,
                artifact: artifact,
                fixed: fixed,
                advisory: advisory)
          );
    out.add(rule.inFile(v.file, null, en, messageAr: ar));
  }
  if (found.isNotEmpty) {
    final list =
        {for (final v in found) '${v.library} ${v.version}'}.join(', ');
    project.securityEvidence.add(SecurityEvidence(
        rule.meta.id,
        found.first.file,
        Bilingual(En.libraryVersions(artifact: artifact, versions: list),
            Ar.libraryVersions(artifact: artifact, versions: list)),
        status: 'facts',
        data: {'versions': list}));
  }
  return RuleCheck(out);
}

const _description =
    Bilingual(En.oldLibraryDescription, Ar.oldLibraryDescription);
const _fix = Bilingual(En.oldLibraryFix, Ar.oldLibraryFix);

class OldNativeLibraryApkRule extends Rule {
  const OldNativeLibraryApkRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-B14',
        title: Bilingual(En.oldLibraryApkTitle, Ar.oldLibraryApkTitle),
        passTitleText: Bilingual(En.oldLibraryApkPass, Ar.oldLibraryApkPass),
        description: _description,
        fix: _fix,
        severity: Severity.medium,
        l2Severity: Severity.high,
        masvs: ['MASVS-CODE-3'],
        maswe: ['MASWE-0044'],
        cwe: 'CWE-1395',
        profiles: _all,
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final apk = project.apk;
    if (apk == null) return RuleCheck.notApplicable();
    final abi = const ['arm64-v8a', 'armeabi-v7a', 'x86_64', 'x86']
            .where(apk.abis.contains)
            .firstOrNull ??
        apk.abis.firstOrNull;
    if (abi == null) return RuleCheck([]);
    final found = <NativeLibraryVersion>[];
    for (final e in apk.zip.entries.values) {
      final name = e.name;
      if (!name.startsWith('lib/$abi/') || !name.endsWith('.so')) continue;
      // The Flutter engine's own copies follow the Flutter version.
      if (name.endsWith('/libflutter.so') || e.size > 96 * 1024 * 1024) {
        continue;
      }
      final text = latin1.decode(apk.zip.readEntry(e), allowInvalid: true);
      found.addAll(findLibraryVersions(text, '${apk.fileName}!/$name'));
    }
    return _report(this, project, found, apk.kind);
  }
}

class OldNativeLibraryIpaRule extends Rule {
  const OldNativeLibraryIpaRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-I13',
        title: Bilingual(En.oldLibraryIpaTitle, Ar.oldLibraryIpaTitle),
        passTitleText: Bilingual(En.oldLibraryIpaPass, Ar.oldLibraryIpaPass),
        description: _description,
        fix: _fix,
        severity: Severity.medium,
        l2Severity: Severity.high,
        masvs: ['MASVS-CODE-3'],
        maswe: ['MASWE-0044'],
        cwe: 'CWE-1395',
        profiles: _all,
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final ipa = project.ipa;
    if (ipa == null) return RuleCheck.notApplicable();
    final found = <NativeLibraryVersion>[];
    var encrypted = false;
    for (final binary in ipa.staticAnalysis.binaries) {
      if (binary.path.contains('/Flutter.framework/')) continue;
      for (final slice in binary.slices) {
        if (slice.encrypted) {
          encrypted = true;
        }
        found.addAll(findLibraryVersions(
            slice.strings.join('\n'), '${ipa.label}!/${binary.path}'));
      }
    }
    final check = _report(this, project, found, 'IPA');
    if (encrypted && check.findings.isEmpty) {
      return RuleCheck.incompleteLocalized(
          En.oldLibraryEncrypted, Ar.oldLibraryEncrypted);
    }
    return check;
  }
}
