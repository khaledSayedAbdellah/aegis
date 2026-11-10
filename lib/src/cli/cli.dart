import 'dart:io';

import 'package:args/args.dart';

import 'arguments.dart';
import 'commands/audit.dart';
import 'commands/doctor.dart';
import 'commands/init.dart';
import 'commands/probe.dart';
import 'commands/setup.dart';

Future<void> runCli(List<String> arguments) async {
  final parser = rootParser();
  final ArgResults root;
  try {
    root = parser.parse(arguments);
  } on FormatException catch (e) {
    stderr.writeln(e.message);
    stderr.writeln('Run "aegis --help" for usage.');
    exit(2);
  }

  if (root.command?.name == 'init') {
    await initCommand(root.command!);
    return;
  }
  if (root.command?.name == 'doctor') {
    exit(await doctorCommand(root.command!));
  }
  if (root.command?.name == 'setup') {
    exit(await setupCommand(root.command!));
  }
  if (root.command?.name == 'probe') {
    exit(await probeCommand(root.command!));
  }
  await auditCommand(root, parser);
}
