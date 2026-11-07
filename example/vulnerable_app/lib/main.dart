// Intentionally insecure demo code. Do NOT copy any of this into a real app.
import 'dart:io';
import 'dart:math';

import 'package:crypto/crypto.dart';
import 'package:dio/dio.dart';
import 'package:encrypt/encrypt.dart';
import 'package:firebase_app_check/firebase_app_check.dart';
import 'package:flutter/material.dart';
import 'package:freerasp/freerasp.dart';
import 'package:local_auth/local_auth.dart';
import 'package:shared_preferences/shared_preferences.dart';

// AEG-D01: AWS documentation example key (not a real credential).
const awsAccessKey = 'AKIAIOSFODNN7EXAMPLE';
const apiSecret = 'q8Zr2LwX9vT4mN7pK1sB';

// AEG-D02: cleartext endpoint.
const baseUrl = 'http://api.my-shop.com/v1';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();

  // AEG-P06: debug provider shipped in release.
  await FirebaseAppCheck.instance.activate(
    androidProvider: AndroidProvider.debug,
  );

  // AEG-P03: copied from the docs + dev mode in release.
  final config = TalsecConfig(
    androidConfig: AndroidConfig(
      packageName: 'com.aheaditec.freeraspExample',
      signingCertHashes: [],
    ),
    iosConfig: IOSConfig(bundleIds: ['YOUR_BUNDLE_ID'], teamId: 'TEAM'),
    watcherMail: 'security@my-shop.com',
    isProd: false,
  );

  // AEG-P04: detection without reaction.
  final callback = ThreatCallback(
    onPrivilegedAccess: () => print('rooted'),
    onHooks: () {},
    onDebug: () {
      debugPrint('debugger');
    },
  );
  // AEG-P02: listener attached, but Talsec.instance.start(config) is never called.
  Talsec.instance.attachListener(callback);

  runApp(const MaterialApp(home: Scaffold()));
}

Future<void> login(String user, String password) async {
  final dio = Dio(BaseOptions(baseUrl: baseUrl));
  // AEG-D08: logs Authorization headers in release.
  dio.interceptors.add(LogInterceptor(requestHeader: true, responseBody: true));

  // AEG-D03: accepts any certificate.
  final client = HttpClient()
    ..badCertificateCallback = (cert, host, port) => true;
  client.close();

  final res = await dio.post('/login', data: {'user': user, 'password': password});
  final token = res.data['token'] as String;
  print('login ok, token=$token');

  // AEG-D04: token in plain SharedPreferences.
  final prefs = await SharedPreferences.getInstance();
  await prefs.setString('auth_token', token);

  // AEG-D05: weak hash.
  final hash = md5.convert(password.codeUnits).toString();
  await prefs.setString('pwd_hash', hash);

  // AEG-D06: hardcoded key + IV.
  final key = Key.fromUtf8('my32lengthsupersecretnooneknows1');
  final iv = IV.fromUtf8('1234567890123456');
  Encrypter(AES(key, mode: AESMode.ecb)).encrypt(token, iv: iv);

  // AEG-D07: predictable OTP.
  final otp = Random().nextInt(999999).toString();
  debugPrint('otp $otp');
}

Future<bool> unlockWithBiometrics() async {
  // AEG-P08: boolean gate with PIN fallback.
  return LocalAuthentication().authenticate(localizedReason: 'Unlock');
}
