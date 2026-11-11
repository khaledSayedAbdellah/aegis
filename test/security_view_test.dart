import 'package:aegis/src/l10n/messages.g.dart';
import 'package:aegis/src/model.dart';
import 'package:aegis/src/reporters/security_view.dart';
import 'package:aegis/src/security/evidence.dart';
import 'package:test/test.dart';

void main() {
  const evidence = [
    SecurityEvidence(
        'AEG-P11', 'first.dart', Bilingual('First fact', 'ملاحظة أولى'),
        status: 'facts', data: {'source': 'source-reference'}),
    SecurityEvidence(
        'AEG-N05', 'backup.xml', Bilingual('Backup rule', 'قاعدة النسخ')),
    SecurityEvidence('AEG-P11', 'Runner.app',
        Bilingual('Unavailable detail', 'تفصيل غير متاح'),
        status: 'unavailable'),
  ];

  test('one HTML card per rule preserves mixed statuses and all observations',
      () {
    final before = evidence.map((e) => e.toJson()).toList();
    final html = SecurityView(evidence, 'ar').html();
    expect('<details '.allMatches(html), hasLength(2));
    expect('<summary>'.allMatches(html), hasLength(2));
    expect('AEG-P11'.allMatches(html), hasLength(1));
    expect('class="evidence-item"'.allMatches(html), hasLength(3));
    expect(html, contains(Ar.extEvidenceCount(count: 2)));
    expect(html, contains(Ar.extFacts));
    expect(html, contains(Ar.extUnavailable));
    for (final item in evidence) {
      expect(html, contains(item.file));
      expect(html, contains(item.detail.ar));
    }
    expect(html.indexOf('first.dart'), lessThan(html.indexOf('Runner.app')));
    expect(html.indexOf('AEG-P11'), lessThan(html.indexOf('AEG-N05')));
    expect(evidence.map((e) => e.toJson()).toList(), before);
  });

  test('grouped HTML escapes every source and detail', () {
    final html = SecurityView(const [
      SecurityEvidence('AEG-P11', '<img src=x onerror=alert(1)>',
          Bilingual('<script>alert(1)</script>', '<script>alert(1)</script>')),
    ], 'en')
        .html();
    expect(html, isNot(contains('<script>')));
    expect(html, isNot(contains('<img')));
    expect(html, contains('&lt;script&gt;'));
    expect(html, contains(En.extEvidenceCount(count: 1)));
  });

  test('Markdown groups the same observations without discarding provenance',
      () {
    final md = SecurityView(evidence, 'en').markdown();
    expect('\n### '.allMatches(md), hasLength(2));
    expect(md, contains(En.extEvidenceCount(count: 2)));
    expect(md, contains('First fact'));
    expect(md, contains('Unavailable detail'));
    expect(md, contains('Backup rule'));
    expect(md, contains('first\\.dart'));
    expect(md, contains('Runner\\.app'));
  });

  test('empty evidence produces no section', () {
    expect(SecurityView([], 'ar').html(), isEmpty);
    expect(SecurityView([], 'en').markdown(), isEmpty);
  });
}
