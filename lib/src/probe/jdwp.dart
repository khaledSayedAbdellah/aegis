/// Establishes an actual debugger transport to a forwarded Android VM.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

class JdwpSession {
  JdwpSession._(this._socket, this._input);

  final Socket _socket;
  final StreamIterator<List<int>> _input;

  static Future<JdwpSession> connect(int port) async {
    const timeout = Duration(seconds: 5);
    final socket = await Socket.connect(InternetAddress.loopbackIPv4, port,
        timeout: timeout);
    final input = StreamIterator<List<int>>(socket);
    final session = JdwpSession._(socket, input);
    final received = <int>[];
    var at = 0;

    Future<void> readThrough(int end) async {
      while (received.length < end) {
        if (!await input.moveNext()) {
          throw const SocketException('JDWP closed before the VM replied');
        }
        received.addAll(input.current);
      }
    }

    int uint32(int index) =>
        (received[index] << 24) |
        (received[index + 1] << 16) |
        (received[index + 2] << 8) |
        received[index + 3];

    try {
      const handshake = 'JDWP-Handshake';
      socket.add(ascii.encode(handshake));
      await socket.flush();
      await readThrough(handshake.length).timeout(timeout,
          onTimeout: () =>
              throw const SocketException('JDWP handshake timed out'));
      if (ascii.decode(received.sublist(0, handshake.length)) != handshake) {
        throw const FormatException('Invalid JDWP handshake');
      }
      at = handshake.length;

      // VirtualMachine.Version, command set 1 / command 1, packet id 1.
      socket.add([0, 0, 0, 11, 0, 0, 0, 1, 0, 1, 1]);
      await socket.flush();
      await (() async {
        while (true) {
          await readThrough(at + 11);
          final size = uint32(at);
          if (size < 11 || size > 1024 * 1024) {
            throw const FormatException('Invalid JDWP packet length');
          }
          await readThrough(at + size);
          if (received[at + 8] == 0x80 && uint32(at + 4) == 1) {
            if (received[at + 9] != 0 || received[at + 10] != 0) {
              throw const FormatException(
                  'JDWP VM rejected the debugger command');
            }
            return;
          }
          at += size;
        }
      })()
          .timeout(timeout,
              onTimeout: () =>
                  throw const SocketException('JDWP VM reply timed out'));
      return session;
    } catch (_) {
      await session.close();
      rethrow;
    }
  }

  Future<void> close() async {
    _socket.destroy();
    await _input.cancel();
  }
}
