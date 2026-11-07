/// Rules for iOS configuration: Info.plist and entitlements.
library;

import '../model.dart';
import '../project.dart';
import '../util.dart';
import 'rule.dart';

const _all = {MasProfile.l1, MasProfile.l2, MasProfile.r};

Map<String, Object?>? _ats(Project p) {
  final ats = p.infoPlistData?['NSAppTransportSecurity'];
  return ats is Map<String, Object?> ? ats : null;
}

class AtsArbitraryLoadsRule extends Rule {
  const AtsArbitraryLoadsRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-I01',
        title: Bilingual('App Transport Security disabled (iOS)', 'الـ App Transport Security مقفول (iOS)'),
        description: Bilingual(
            'NSAllowsArbitraryLoads turns off ATS, so the app accepts plain HTTP and weak TLS for every domain.',
            'NSAllowsArbitraryLoads بيقفل الـ ATS، فالتطبيق بيقبل HTTP عادي و TLS ضعيف لأي domain.'),
        fix: Bilingual(
            'Remove NSAllowsArbitraryLoads (and NSAllowsArbitraryLoadsInWebContent). Add a narrow NSExceptionDomains entry only for hosts that really need it.',
            'شيل NSAllowsArbitraryLoads (و NSAllowsArbitraryLoadsInWebContent). ولو فيه سيرفر محتاج استثناء، اعمله في NSExceptionDomains ليه هو بس.'),
        severity: Severity.high,
        masvs: ['MASVS-NETWORK-1'],
        maswe: ['MASWE-0026'],
        cwe: 'CWE-319',
        profiles: _all,
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final f = project.infoPlist;
    if (f == null || project.infoPlistData == null) {
      return RuleCheck.notApplicable('No ios/Runner/Info.plist');
    }
    final ats = _ats(project);
    if (ats == null) return RuleCheck([]);
    final out = <Finding>[];
    for (final key in const ['NSAllowsArbitraryLoads', 'NSAllowsArbitraryLoadsInWebContent', 'NSAllowsArbitraryLoadsForMedia']) {
      if (ats[key] == true) {
        out.add(inFile(f.path, lineOfFirst(f.text, key), '$key is true.',
            messageAr: '$key قيمته true.'));
      }
    }
    return RuleCheck(out);
  }
}

class AtsExceptionsRule extends Rule {
  const AtsExceptionsRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-I02',
        title: Bilingual('Insecure ATS exception domain', 'استثناء ATS غير آمن'),
        description: Bilingual(
            'An ATS exception allows HTTP or TLS below 1.2 for a domain.',
            'فيه استثناء ATS بيسمح بـ HTTP أو TLS أقل من 1.2 لـ domain معين.'),
        fix: Bilingual('Serve the domain over HTTPS with TLS 1.2+ and remove the exception.',
            'خلي السيرفر يشتغل HTTPS بـ TLS 1.2 أو أعلى، وشيل الاستثناء.'),
        severity: Severity.medium,
        masvs: ['MASVS-NETWORK-1'],
        maswe: ['MASWE-0026'],
        cwe: 'CWE-326',
        profiles: _all,
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final f = project.infoPlist;
    if (f == null || project.infoPlistData == null) return RuleCheck.notApplicable();
    final domains = _ats(project)?['NSExceptionDomains'];
    if (domains is! Map<String, Object?>) return RuleCheck([]);
    final out = <Finding>[];
    domains.forEach((domain, cfg) {
      if (cfg is! Map<String, Object?>) return;
      if (const {'localhost', '127.0.0.1'}.contains(domain)) return;
      if (cfg['NSExceptionAllowsInsecureHTTPLoads'] == true ||
          cfg['NSTemporaryExceptionAllowsInsecureHTTPLoads'] == true) {
        out.add(inFile(f.path, lineOfFirst(f.text, domain),
            '$domain allows insecure HTTP loads.',
            messageAr: '$domain مسموح له بـ HTTP غير مشفر.'));
      }
      final tls = (cfg['NSExceptionMinimumTLSVersion'] ??
              cfg['NSTemporaryExceptionMinimumTLSVersion'])
          ?.toString();
      if (tls == 'TLSv1.0' || tls == 'TLSv1.1') {
        out.add(inFile(f.path, lineOfFirst(f.text, domain),
            '$domain allows $tls.', messageAr: '$domain مسموح له بـ $tls.'));
      }
    });
    return RuleCheck(out);
  }
}

class GetTaskAllowRule extends Rule {
  const GetTaskAllowRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-I03',
        title: Bilingual('Debugging entitlement enabled (iOS)', 'صلاحية الـ debugging مفعّلة (iOS)'),
        description: Bilingual(
            'get-task-allow lets debuggers attach to the app process.',
            'get-task-allow بيسمح لأي debugger يتوصل بالتطبيق وهو شغال.'),
        fix: Bilingual('Remove get-task-allow from the release entitlements.',
            'شيل get-task-allow من الـ entitlements بتاعة الـ release.'),
        severity: Severity.high,
        masvs: ['MASVS-RESILIENCE-4'],
        maswe: ['MASWE-0063'],
        cwe: 'CWE-489',
        profiles: _all,
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    if (!project.hasIos) return RuleCheck.notApplicable();
    if (project.entitlements.isEmpty) return RuleCheck.notApplicable('No entitlements file');
    final out = <Finding>[];
    project.entitlements.forEach((path, data) {
      if (path.toLowerCase().contains('debug')) return;
      if (data['get-task-allow'] == true) {
        out.add(inFile(path, null, 'get-task-allow is true in $path.',
            messageAr: 'get-task-allow قيمته true في $path.'));
      }
    });
    return RuleCheck(out);
  }
}

class FileSharingRule extends Rule {
  const FileSharingRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-I04',
        title: Bilingual('Documents folder exposed (iOS)', 'فولدر الـ Documents مكشوف (iOS)'),
        description: Bilingual(
            'UIFileSharingEnabled / LSSupportsOpeningDocumentsInPlace expose the app\'s Documents folder in the Files app and Finder.',
            'UIFileSharingEnabled أو LSSupportsOpeningDocumentsInPlace بيخلوا فولدر Documents بتاع التطبيق ظاهر في تطبيق Files و Finder.'),
        fix: Bilingual(
            'Disable them unless sharing is a feature, and never store tokens or databases in Documents.',
            'اقفلهم إلا لو مشاركة الملفات ميزة مقصودة، ومتخزنش tokens أو قواعد بيانات في Documents.'),
        severity: Severity.low,
        l2Severity: Severity.medium,
        masvs: ['MASVS-STORAGE-2'],
        maswe: ['MASWE-0002'],
        cwe: 'CWE-552',
        profiles: _all,
      );

  @override
  RuleCheck check(Project project, ProfileSet profile) {
    final f = project.infoPlist;
    final data = project.infoPlistData;
    if (f == null || data == null) return RuleCheck.notApplicable();
    final out = <Finding>[];
    for (final key in const ['UIFileSharingEnabled', 'LSSupportsOpeningDocumentsInPlace']) {
      if (data[key] == true) {
        out.add(inFile(f.path, lineOfFirst(f.text, key), '$key is true.',
            messageAr: '$key قيمته true.'));
      }
    }
    return RuleCheck(out);
  }
}

const iosRules = <Rule>[
  AtsArbitraryLoadsRule(),
  AtsExceptionsRule(),
  GetTaskAllowRule(),
  FileSharingRule(),
];
