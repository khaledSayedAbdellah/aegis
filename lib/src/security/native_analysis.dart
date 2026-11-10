/// Removes comments while preserving strings and source line offsets.
String withoutComments(String source) {
  final chars = source.split('');
  var i = 0;
  while (i < chars.length) {
    if (chars[i] == '"' || chars[i] == "'") {
      final quote = chars[i++];
      while (i < chars.length) {
        if (chars[i] == '\\') {
          i += 2;
          continue;
        }
        if (chars[i++] == quote) break;
      }
    } else if (i + 1 < chars.length && chars[i] == '/' && chars[i + 1] == '/') {
      while (i < chars.length && chars[i] != '\n') {
        chars[i++] = ' ';
      }
    } else if (i + 1 < chars.length && chars[i] == '/' && chars[i + 1] == '*') {
      chars[i++] = ' ';
      chars[i++] = ' ';
      while (i < chars.length) {
        if (i + 1 < chars.length && chars[i] == '*' && chars[i + 1] == '/') {
          chars[i++] = ' ';
          chars[i++] = ' ';
          break;
        }
        if (chars[i] != '\n') chars[i] = ' ';
        i++;
      }
    } else {
      i++;
    }
  }
  return chars.join();
}

/// Pattern hits are exact configuration evidence, not execution/data-flow proof.
final nativePatterns = <String, List<RegExp>>{
  'AEG-N01': [
    RegExp(
        r'\b(?:setAllowsAnyHTTPSCertificate|setAllowsAnyHTTPSCertificateForHost)\s*[:(]\s*(?:YES|true)\b'),
    RegExp(
        r'\bkCFStreamSSLAllows(?:AnyRoot|ExpiredCertificates|ExpiredRoots)\s*[:=,]\s*(?:true|YES|kCFBooleanTrue)\b'),
    RegExp(
        r'\bcheckServerTrusted\s*\([^)]*\)\s*(?:throws\s+[\w.,\s]+)?\{\s*\}'),
    RegExp(
        r'\bonReceivedSslError\s*\([^)]*\)\s*\{[^{}]{0,600}\b\w+\.proceed\s*\(\s*\)',
        dotAll: true),
  ],
  'AEG-N02': [
    RegExp(
        r'\bsetAllow(?:UniversalAccessFromFileURLs|FileAccessFromFileURLs)\s*\(\s*true\s*\)'),
    RegExp(
        r'\bsetMixedContentMode\s*\(\s*(?:WebSettings\.)?MIXED_CONTENT_ALWAYS_ALLOW\s*\)'),
    RegExp(
        r'\b(?:allowUniversalAccessFromFileURLs|allowFileAccessFromFileURLs)\s*[:=]\s*true\b'),
    RegExp(
        r'\bmixedContentMode\s*[:=]\s*(?:MixedContentMode\.)?MIXED_CONTENT_ALWAYS_ALLOW\b'),
    RegExp(
        r'\bsetValue\s*\(\s*true\s*,\s*forKey\s*:\s*"allow(?:UniversalAccessFromFileURLs|FileAccessFromFileURLs)"'),
  ],
  'AEG-N03': [
    RegExp(
        r'\bCipher\.getInstance\s*\(\s*"(?:DES(?:ede)?(?:/[^"\n]*)?|RC[24](?:/[^"\n]*)?|AES/ECB/[^"\n]+)"'),
    RegExp(
        r'\b(?:CCCrypt|CCCryptorCreate)\s*\([^;\n]{0,200}\bkCCAlgorithm(?:DES|3DES|RC2|RC4)\b'),
  ],
  'AEG-N04': [
    RegExp(
        r'\bkSecAttrAccessible\s*(?:\]|\))?\s*[:=,]\s*kSecAttrAccessibleAlways(?:ThisDeviceOnly)?\b'),
    RegExp(
        r'\b(?:NSFileProtectionKey|FileAttributeKey\.protectionKey)\s*[:=]\s*(?:NSFileProtectionNone|FileProtectionType\.none)\b'),
    RegExp(
        r'\b(?:getSharedPreferences|openFileOutput)\s*\([^;\n]{0,200}\b(?:MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE)\b'),
  ],
};
final nativeIndicators = <String, RegExp>{
  'AEG-N01': RegExp(
      r'\b(?:allowsAnyHTTPSCertificateForHost|continueWithoutCredentialForAuthenticationChallenge|TrustAllCertificates|ALLOW_ALL_HOSTNAME_VERIFIER)\b'),
  'AEG-N02': RegExp(
      r'\b(?:UIWebView|addJavascriptInterface|loadHTMLString|allowUniversalAccessFromFileURLs|allowFileAccessFromFileURLs)\b'),
  'AEG-N03': RegExp(
      r'\b(?:CC_MD[245]|CC_SHA1|MD5|SHA1|SHA-1|kCCAlgorithmDES|kCCAlgorithm3DES|kCCAlgorithmRC[24]|rand|srand|java\.util\.Random|srandom|drand48|kCCOptionECBMode)\b'),
  'AEG-N04': RegExp(
      r'\b(?:kSecAttrAccessibleAlways(?:ThisDeviceOnly)?|kSecAttrAccessControl|biometryAny|userPresence|devicePasscode|NSFileProtectionNone|NSLog|NSLogv|UIPasteboard|generalPasteboard|sqlite3_exec|sqlite3_prepare_v2)\b'),
};

/// Used only to distinguish code matches from documentation/example literals.
String maskNativeLiterals(String source) {
  final chars = source.split('');
  var i = 0;
  while (i < chars.length) {
    if (chars[i] != '"' && chars[i] != "'") {
      i++;
      continue;
    }
    final quote = chars[i];
    chars[i++] = ' ';
    while (i < chars.length) {
      final ch = chars[i];
      if (ch != '\n') chars[i] = ' ';
      i++;
      if (ch == quote) break;
      if (ch == '\\' && i < chars.length) {
        if (chars[i] != '\n') chars[i] = ' ';
        i++;
      }
    }
  }
  return chars.join();
}
