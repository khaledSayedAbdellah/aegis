# aegis examples

## Command line

`vulnerable_app` is a small Flutter project that is insecure on purpose. Audit
it to see what a report looks like:

```bash
dart pub global activate aegis
aegis example/vulnerable_app --offline
```

It exits with code 1 because the project has high-severity findings. Write the
other report formats with `-f`:

```bash
aegis example/vulnerable_app --offline -f json,sarif,html,md -o build/aegis-example
```

Audit your own app from its project folder:

```bash
aegis                      # source audit of the current folder
aegis --apk build/app/outputs/flutter-apk/app-release.apk
aegis init                 # write an aegis.yaml with every setting
```

## From Dart code

[`example.dart`](example.dart) runs the same audit through the library API:

```dart
import 'package:aegis/aegis.dart';

Future<void> main() async {
  final report = await runAudit('example/vulnerable_app', offline: true);
  print(ConsoleReporter().render(report));
  print('Score: ${report.score.value}/100');
}
```

```bash
dart run example/example.dart example/vulnerable_app
```
