import 'package:aegis/aegis.dart';
import 'package:aegis/src/rules/backend_rules.dart';
import 'package:test/test.dart';

import 'rules_test.dart' show audit, result;

const firestore = '''
rules_version = '2';
// allow read, write: if true;   <- a comment, not a rule
service cloud.firestore {
  match /databases/{database}/documents {
    function isOwner(uid) {
      return request.auth != null && request.auth.uid == uid;
    }
    match /users/{uid} {
      allow read: if true;
      allow write: if isOwner(uid);
    }
    match /feedback/{id} {
      allow create;
    }
    match /{document=**} {
      allow read, write: if request.time < timestamp.date(2099, 1, 31);
    }
  }
}
''';

List<String> messages(AuditReport r, String id) =>
    result(r, id).findings.map((f) => '${f.line}: ${f.message}').toList();

void main() {
  test('the parser keeps match paths and conditions', () {
    final grants =
        parseSecurityRules('Cloud Firestore', 'firestore.rules', firestore);
    expect([
      for (final g in grants) '${g.path} ${g.ops} ${g.condition}'
    ], [
      '/users/{uid} {read} true',
      '/users/{uid} {write} isOwner(uid)',
      '/feedback/{id} {write} ',
      '/{document=**} {read, write} request.time<timestamp.date(2099,1,31)',
    ]);
    expect(grants.last.everything, isTrue);
    expect(grants.last.until, DateTime.utc(2099, 1, 31));
  });

  test('open and test-mode rules on all data are critical', () async {
    final r = await audit({'firestore.rules': firestore});
    expect(messages(r, 'AEG-P12'), [
      '16: Cloud Firestore: test-mode rules let anyone, without signing in, '
          'read and write all data until 2099-01-31 (`allow read, write: if '
          'request.time < timestamp.date(2099, 1, 31);`).'
    ]);
    expect(result(r, 'AEG-P12').severity, Severity.critical);
    // Anonymous writes to one path are broader than needed, not critical.
    expect(messages(r, 'AEG-P15'), [
      '13: Cloud Firestore: anyone, without signing in, can write to '
          '/feedback/{id} (`allow create;`).'
    ]);
  });

  test('expired test mode and owner-only rules pass', () async {
    final r = await audit({
      'firestore.rules': '''
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} {
      allow read, write: if request.time < timestamp.date(2020, 1, 1);
    }
    match /users/{uid} {
      allow read, write: if request.auth != null && request.auth.uid == uid;
    }
  }
}''',
    });
    expect(result(r, 'AEG-P12').status, RuleStatus.passed);
    expect(result(r, 'AEG-P15').status, RuleStatus.passed);
  });

  test('any signed-in user on all data, from firebase.json paths', () async {
    final r = await audit({
      'firebase.json':
          '{"storage": [{"bucket": "b", "rules": "backend/storage.rules"}]}',
      'backend/storage.rules': '''
service firebase.storage {
  match /b/{bucket}/o {
    match /{allPaths=**} {
      allow read, write: if (request.auth != null);
    }
  }
}''',
    });
    expect(result(r, 'AEG-P12').status, RuleStatus.passed);
    expect(messages(r, 'AEG-P15').single,
        startsWith('4: Cloud Storage: any signed-in user can read and write'));
    expect(result(r, 'AEG-P15').findings.single.file, 'backend/storage.rules');
  });

  test('Realtime Database rules', () async {
    final open = await audit({
      'database.rules.json':
          '{\n  "rules": {\n    ".read": true,\n    ".write": "auth != null"\n  }\n}',
    });
    expect(messages(open, 'AEG-P12'), [
      '3: Realtime Database: anyone, without signing in, can read all data '
          '(`".read": true`).'
    ]);
    expect(messages(open, 'AEG-P15').single,
        startsWith('4: Realtime Database: any signed-in user can write'));
  });

  test('rules not in the repository are listed for review', () async {
    final r = await audit({
      'pubspec.yaml': 'name: app\ndependencies:\n  flutter:\n    sdk: flutter\n'
          '  cloud_firestore: any\n',
    });
    expect(result(r, 'AEG-P12').status, RuleStatus.evidenceOnly);
    expect(result(r, 'AEG-P12').note, contains('Cloud Firestore'));
    expect(result(r, 'AEG-P15').status, RuleStatus.notApplicable);

    final none = await audit({});
    expect(result(none, 'AEG-P12').status, RuleStatus.notApplicable);
  });

  test('a rules file that is not valid JSON makes the check incomplete',
      () async {
    final r = await audit({'database.rules.json': '{"rules": '});
    expect(result(r, 'AEG-P12').status, RuleStatus.incomplete);
  });
}
