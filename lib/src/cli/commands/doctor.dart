import 'dart:io';

import 'package:args/args.dart';

import '../../probe/host.dart';
import '../../probe/messages.dart';
import '../../probe/setup.dart';
import '../../probe/toolchain.dart';
import '../arguments.dart';
import '../terminal.dart';
import '../tool_output.dart';

Future<int> doctorCommand(ArgResults a) async {
  final ios = a['ios'] as bool;
  final m = Msg(terminalLang, ios: ios);
  if (a['help'] as bool) {
    stdout.writeln('Usage: aegis doctor [--ios] [--lang en|ar]\n');
    stdout.writeln(
        'Checks the tools the resilience probe needs. Changes nothing.');
    stdout.writeln('Exit code 0 when everything required is present.\n');
    stdout.writeln(toolsParser().usage);
    return 0;
  }
  final t = Toolchain(SystemHost());
  final checks = ios ? await t.checkIos() : await t.checkAll();
  stdout.writeln(m.header);
  printToolChecks(checks, m, t);
  stdout.writeln('');

  final required = checks.where((c) => c.state != ToolState.optional);
  final missing = required.where((c) => !c.ok).toList();
  if (missing.isEmpty) {
    stdout.writeln(m.allPresent);
    return 0;
  }
  final installable = Setup(t).buildPlan(checks).steps.length;
  if (installable > 0) stdout.writeln('⬇️  ${m.toInstall(installable)}');
  if (missing.any((c) => c.state == ToolState.manual)) {
    stdout.writeln('❌ ${m.someManual}');
  }
  return 1;
}
