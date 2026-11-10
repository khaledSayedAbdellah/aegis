import 'dart:async';
import 'dart:convert';
import 'dart:io';

/// No redirects, credentials, local addresses or DNS rebinding. Manifest hosts
/// are untrusted. Keep TLS verification against the original hostname.
bool publicAddress(InternetAddress a) {
  final b = a.rawAddress;
  if (b.length != 4) {
    return false; // Deliberately IPv4 only; IPv6 is incomplete.
  }
  return !(b[0] == 0 ||
      b[0] == 10 ||
      b[0] == 127 ||
      b[0] >= 224 ||
      (b[0] == 100 && b[1] >= 64 && b[1] <= 127) ||
      (b[0] == 169 && b[1] == 254) ||
      (b[0] == 172 && b[1] >= 16 && b[1] <= 31) ||
      (b[0] == 192 && (b[1] == 0 || b[1] == 168)) ||
      (b[0] == 198 && (b[1] == 18 || b[1] == 19 || b[1] == 51)) ||
      (b[0] == 203 && b[1] == 0 && b[2] == 113));
}

Future<Object?> fetchPublicJson(Uri uri, {int maxBytes = 1024 * 1024}) async {
  if (uri.scheme != 'https' ||
      uri.port != 443 ||
      uri.userInfo.isNotEmpty ||
      !RegExp(r'^[a-zA-Z0-9.-]+$').hasMatch(uri.host) ||
      !uri.host.contains('.')) {
    throw const FormatException('Unsupported public HTTPS URL');
  }
  final client = HttpClient()
    ..connectionTimeout = const Duration(seconds: 5)
    ..findProxy = (_) => 'DIRECT';
  client.connectionFactory = (url, _, __) async {
    final addresses =
        await InternetAddress.lookup(url.host, type: InternetAddressType.IPv4)
            .timeout(const Duration(seconds: 5));
    if (addresses.isEmpty || addresses.any((a) => !publicAddress(a))) {
      throw const FormatException('Non-public destination');
    }
    return Socket.startConnect(addresses.first, url.port);
  };
  try {
    return await (() async {
      final request = await client.getUrl(uri);
      request.followRedirects = false;
      final response = await request.close();
      if (response.statusCode != 200) {
        throw const FormatException('Association unavailable');
      }
      final bytes = <int>[];
      await for (final chunk in response) {
        if (bytes.length + chunk.length > maxBytes) {
          throw const FormatException('JSON limit');
        }
        bytes.addAll(chunk);
      }
      return jsonDecode(utf8.decode(bytes));
    })()
        .timeout(const Duration(seconds: 10));
  } finally {
    client.close(force: true);
  }
}
