import 'package:aegis/aegis.dart';
import 'package:test/test.dart';

import 'rules_test.dart' show audit, result;

const _kt = 'android/app/src/main/kotlin/com/example/Main.kt';

Future<AuditReport> run(Map<String, String> files) => audit(files);

List<String> lines(AuditReport r) =>
    result(r, 'AEG-C05').findings.map((f) => '${f.file}:${f.line}').toList();

void main() {
  test('Kotlin: Intent data reaching ObjectInputStream', () async {
    final r = await run({
      _kt: '''
class Main : Activity() {
    fun handle(intent: Intent) {
        val b64 = intent.getStringExtra("payload")
        val bytes = Base64.getDecoder().decode(b64)
        val ois = ObjectInputStream(ByteArrayInputStream(bytes))
        val user = ois.readObject()
    }
    fun legacy(intent: Intent) {
        val user = intent.getSerializableExtra("user") as User
        val typed = intent.getSerializableExtra("user", User::class.java)
    }
    fun mapper() = ObjectMapper().activateDefaultTyping(validator)
    fun local(file: File) {
        val cached = ObjectInputStream(file.inputStream()).readObject()
    }
}
''',
    });
    expect(lines(r), unorderedEquals(['$_kt:5', '$_kt:9', '$_kt:12']));
  });

  test('Java: network data, and a class filter makes it safe', () async {
    final r = await run({
      'android/app/src/main/java/com/example/Net.java': '''
class Net {
    Object read(HttpURLConnection connection) throws Exception {
        InputStream in = connection.getInputStream();
        return new ObjectInputStream(in).readObject();
    }
}
''',
      'android/app/src/main/java/com/example/Safe.java': '''
class Safe {
    Object read(HttpURLConnection connection) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(connection.getInputStream());
        ois.setObjectInputFilter(ObjectInputFilter.Config.createFilter("com.example.*;!*"));
        return ois.readObject();
    }
}
''',
    });
    expect(lines(r), ['android/app/src/main/java/com/example/Net.java:4']);
  });

  test('Swift: a link or downloaded data reaching NSKeyedUnarchiver', () async {
    final r = await run({
      'ios/Runner/Restore.swift': '''
class Restore {
    func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey: Any] = [:]) -> Bool {
        let data = try? Data(contentsOf: url)
        let state = NSKeyedUnarchiver.unarchiveObject(with: data!)
        return true
    }
    func safe(data: Data) throws {
        let state = try NSKeyedUnarchiver.unarchivedObject(ofClass: State.self, from: data)
    }
    func cached() {
        let old = NSKeyedUnarchiver.unarchiveObject(withFile: path)
    }
}
''',
    });
    expect(lines(r), ['ios/Runner/Restore.swift:4']);
    expect(
        r.securityEvidence.where((e) => e.ruleId == 'AEG-C05').single.detail.en,
        contains('ios/Runner/Restore.swift:11'));
  });

  test('React Native: node-serialize', () async {
    final r = await run({
      'package.json': '{"dependencies": {"react-native": "0.76.0"}}',
      'src/session.js': '''
const serialize = require('node-serialize');
export const load = (text) => serialize.unserialize(text);
''',
    });
    expect(lines(r), ['src/session.js:2']);
  });

  test('not applicable without native or script code', () async {
    final r = await run({'lib/main.dart': 'void main() {}'});
    expect(result(r, 'AEG-C05').status, RuleStatus.notApplicable);
  });
}
