/// Lexes comments and strings without changing source offsets. Supports Kotlin/
/// Java text blocks, Swift raw/multiline strings and nested Swift/Kotlin comments.
class NativeLiteral {
  NativeLiteral(this.start, this.end, this.value);
  final int start, end;
  final String value;
}

({String comments, String code, List<NativeLiteral> literals}) scanNative(
    String source) {
  final comments = source.split(''), code = source.split('');
  final literals = <NativeLiteral>[];
  void blank(List<String> chars, int start, int end) {
    for (var k = start; k < end; k++) {
      if (chars[k] != '\n' && chars[k] != '\r') chars[k] = ' ';
    }
  }

  var i = 0;
  while (i < source.length) {
    final start = i;
    if (source.startsWith('//', i)) {
      while (i < source.length && source[i] != '\n') {
        i++;
      }
      blank(comments, start, i);
      blank(code, start, i);
      continue;
    }
    if (source.startsWith('/*', i)) {
      var depth = 1;
      i += 2;
      while (i < source.length && depth > 0) {
        if (source.startsWith('/*', i)) {
          depth++;
          i += 2;
        } else if (source.startsWith('*/', i)) {
          depth--;
          i += 2;
        } else {
          i++;
        }
      }
      blank(comments, start, i);
      blank(code, start, i);
      continue;
    }
    var hashes = 0;
    while (i + hashes < source.length && source[i + hashes] == '#') {
      hashes++;
    }
    final q = i + hashes;
    if (q < source.length &&
        (source[q] == '"' || hashes == 0 && source[q] == "'")) {
      final quote = source[q];
      final triple = source.startsWith(quote * 3, q);
      final delimiter = quote * (triple ? 3 : 1);
      final closing = delimiter + '#' * hashes;
      i = q + delimiter.length;
      final content = i;
      while (i < source.length && !source.startsWith(closing, i)) {
        if (!triple &&
            hashes == 0 &&
            source[i] == r'\' &&
            i + 1 < source.length) {
          i += 2;
        } else {
          i++;
        }
      }
      final end = i;
      if (i < source.length) i += closing.length;
      literals.add(NativeLiteral(start, i, source.substring(content, end)));
      blank(code, start, i);
    } else {
      i++;
    }
  }
  return (comments: comments.join(), code: code.join(), literals: literals);
}

String withoutComments(String source) => scanNative(source).comments;
String maskNativeLiterals(String source) => scanNative(source).code;

/// Pattern hits are exact configuration evidence, not execution/data-flow proof.
final nativePatterns = <String, List<RegExp>>{
  'AEG-N01': [
    RegExp(r'\bHostnameVerifier\s*\{\s*\w+\s*,\s*\w+\s*->\s*true\s*\}'),
    RegExp(
        r'\bsetHostnameVerifier\s*\(\s*\(\s*\w+\s*,\s*\w+\s*\)\s*->\s*true\s*\)'),
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
        r'\bsetValue\s*:\s*@(?:YES|true)\s+forKey\s*:\s*@"allow(?:UniversalAccessFromFileURLs|FileAccessFromFileURLs)"'),
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
        r'\bkSecAttrAccessible\s+to\s+kSecAttrAccessibleAlways(?:ThisDeviceOnly)?\b'),
    RegExp(
        r'\bkSecAttrAccessible\s+as\s+String\s*:\s*kSecAttrAccessibleAlways(?:ThisDeviceOnly)?\b'),
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
