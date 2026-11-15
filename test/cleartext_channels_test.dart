import 'package:test/test.dart';

import 'rules_test.dart' show audit, result;

Future<List<String>> found(String code) async {
  final r = await audit({'lib/main.dart': code});
  return result(r, 'AEG-D02')
      .findings
      .map((f) => '${f.line}: ${f.message}')
      .toList();
}

void main() {
  test('ws, ftp, mqtt URLs and insecure gRPC and MQTT clients', () async {
    expect(await found('''
const socket = 'ws://chat.my-shop.com/live';
const files = 'ftp://files.my-shop.com/export';
const broker = 'mqtt://iot.my-shop.com';
final channel = ClientChannel('api.my-shop.com',
    options: const ChannelOptions(credentials: ChannelCredentials.insecure()));
final client = MqttServerClient('iot.my-shop.com', 'device-1');
'''), [
      '1: Cleartext URL: ws://chat.my-shop.com/live',
      '2: Cleartext URL: ftp://files.my-shop.com/export',
      '3: Cleartext URL: mqtt://iot.my-shop.com',
      '5: Unencrypted gRPC connection: ChannelCredentials.insecure().',
      '6: Unencrypted MQTT connection: MqttServerClient without secure = true.',
    ]);
  });

  test('secure and local connections pass', () async {
    expect(await found('''
import 'package:flutter/foundation.dart';
const socket = 'wss://chat.my-shop.com/live';
const local = 'ws://localhost:8080';
const emulator = 'ws://10.0.2.2:8080';
final channel = kDebugMode
    ? ChannelCredentials.insecure()
    : const ChannelCredentials.secure();
void connect() {
  final client = MqttServerClient.withPort('iot.my-shop.com', 'id', 8883);
  client.secure = true;
}
'''), isEmpty);
  });

  test('http findings keep their message, so baselines still match', () async {
    expect(await found("const api = 'http://api.my-shop.com/v1';"),
        ['1: Cleartext URL: http://api.my-shop.com/v1']);
  });
}
