// App-local, read-only metadata observation. Never enumerates secret values,
// installs trust anchors, opens arbitrary URLs, or invokes app business actions.
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#import <Security/Security.h>
#import <unistd.h>

static NSNumber *N(NSUInteger x) { return @(x); }
static void Observe(NSString *phase) {
  @autoreleasepool {
    NSString *path = NSProcessInfo.processInfo.environment[@"AEGIS_PLATFORM_OUTPUT"];
    NSString *nonce = NSProcessInfo.processInfo.environment[@"AEGIS_PLATFORM_NONCE"];
    if (!path || !nonce) return;
    NSMutableDictionary *screen = [@{@"windows":@0,@"passwordFields":@0,@"unmaskedPasswordFields":@0} mutableCopy];
    NSMutableDictionary *web = [@{@"webviews":@0,@"webviewJs":@0,@"webviewInsecureContent":@0} mutableCopy];
    NSMutableArray<UIView *> *todo = [NSMutableArray new];
    for (UIWindow *window in UIApplication.sharedApplication.windows) {
      if (window.hidden || window.alpha < 0.01) continue;
      screen[@"windows"] = N([screen[@"windows"] unsignedIntegerValue]+1);
      [todo addObject:window];
    }
    NSUInteger visited = 0;
    while (todo.count && visited++ < 5000) {
      UIView *view = todo.lastObject; [todo removeLastObject];
      if (view.hidden || view.alpha < 0.01) continue;
      if ([view isKindOfClass:UITextField.class]) {
        UITextField *field = (UITextField *)view;
        BOOL password = [field.textContentType isEqualToString:UITextContentTypePassword] || [field.textContentType isEqualToString:UITextContentTypeNewPassword];
        if (password || field.secureTextEntry) screen[@"passwordFields"] = N([screen[@"passwordFields"] unsignedIntegerValue]+1);
        // Count only, never collect field contents. A reveal toggle may be valid.
        if (password && !field.secureTextEntry && field.text.length) screen[@"unmaskedPasswordFields"] = N([screen[@"unmaskedPasswordFields"] unsignedIntegerValue]+1);
      }
      if ([view isKindOfClass:WKWebView.class]) {
        WKWebView *wv = (WKWebView *)view;
        web[@"webviews"] = N([web[@"webviews"] unsignedIntegerValue]+1);
        if (wv.configuration.preferences.javaScriptEnabled) web[@"webviewJs"] = N([web[@"webviewJs"] unsignedIntegerValue]+1);
        if (!wv.loading && [wv.URL.scheme.lowercaseString isEqualToString:@"https"] && !wv.hasOnlySecureContent) web[@"webviewInsecureContent"] = N([web[@"webviewInsecureContent"] unsignedIntegerValue]+1);
      }
      [todo addObjectsFromArray:view.subviews];
    }
    NSMutableDictionary *backup = [@{@"files":@0,@"excludedFiles":@0,@"unexcludedFiles":@0,@"unknownFiles":@0} mutableCopy];
    NSURL *home = [NSURL fileURLWithPath:NSHomeDirectory()];
    NSDirectoryEnumerator *enumerator = [NSFileManager.defaultManager enumeratorAtURL:home includingPropertiesForKeys:@[NSURLIsRegularFileKey,NSURLIsSymbolicLinkKey,NSURLIsExcludedFromBackupKey] options:NSDirectoryEnumerationSkipsHiddenFiles errorHandler:^BOOL(NSURL *url, NSError *err) { return NO; }];
    NSUInteger examined=0;
    for (NSURL *url in enumerator) {
      if (++examined > 2000) break;
      NSNumber *regular=nil, *link=nil, *excluded=nil;
      [url getResourceValue:&link forKey:NSURLIsSymbolicLinkKey error:nil];
      if (link.boolValue) { [enumerator skipDescendants]; continue; }
      NSString *relative = [url.path substringFromIndex:home.path.length];
      if ([relative hasPrefix:@"/tmp/"] || [relative hasPrefix:@"/Library/Caches/"]) continue;
      [url getResourceValue:&regular forKey:NSURLIsRegularFileKey error:nil];
      if (!regular.boolValue) continue;
      backup[@"files"] = N([backup[@"files"] unsignedIntegerValue]+1);
      BOOL ok = [url getResourceValue:&excluded forKey:NSURLIsExcludedFromBackupKey error:nil] && excluded != nil;
      // Include inherited advisory exclusions from parent directories.
      NSURL *parent = url.URLByDeletingLastPathComponent;
      NSUInteger depth=0;
      while (ok && !excluded.boolValue && parent.path.length >= home.path.length && depth++ < 32) {
        NSNumber *flag=nil;
        if (![parent getResourceValue:&flag forKey:NSURLIsExcludedFromBackupKey error:nil] || flag == nil) { ok=NO; break; }
        if (flag.boolValue) excluded=flag;
        parent=parent.URLByDeletingLastPathComponent;
      }
      NSString *key = !ok || depth >= 32 ? @"unknownFiles" : excluded.boolValue ? @"excludedFiles" : @"unexcludedFiles";
      backup[key] = N([backup[key] unsignedIntegerValue]+1);
    }
    NSMutableDictionary *keys = [@{@"keychainItems":@0,@"keychainAlways":@0,@"keychainAcl":@0} mutableCopy];
    BOOL keyQueriesComplete = YES;
    for (id itemClass in @[(__bridge id)kSecClassGenericPassword, (__bridge id)kSecClassInternetPassword, (__bridge id)kSecClassKey]) {
      NSDictionary *query = @{(__bridge id)kSecClass:itemClass, (__bridge id)kSecReturnAttributes:@YES, (__bridge id)kSecReturnData:@NO, (__bridge id)kSecMatchLimit:(__bridge id)kSecMatchLimitAll, (__bridge id)kSecUseAuthenticationUI:(__bridge id)kSecUseAuthenticationUIFail};
      CFTypeRef raw = NULL;
      OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &raw);
      id value = CFBridgingRelease(raw);
      if (status != errSecSuccess && status != errSecItemNotFound) keyQueriesComplete=NO;
      if (![value isKindOfClass:NSArray.class]) continue;
      NSUInteger index=0;
      for (NSDictionary *attributes in value) {
        if (++index > 1000) { keyQueriesComplete=NO; break; }
        keys[@"keychainItems"] = N([keys[@"keychainItems"] unsignedIntegerValue]+1);
        id accessible = attributes[(__bridge id)kSecAttrAccessible];
        if ([accessible isEqual:(__bridge id)kSecAttrAccessibleAlways] || [accessible isEqual:(__bridge id)kSecAttrAccessibleAlwaysThisDeviceOnly]) keys[@"keychainAlways"] = N([keys[@"keychainAlways"] unsignedIntegerValue]+1);
        if (attributes[(__bridge id)kSecAttrAccessControl]) keys[@"keychainAcl"] = N([keys[@"keychainAcl"] unsignedIntegerValue]+1);
      }
    }
    NSArray *urlTypes = NSBundle.mainBundle.infoDictionary[@"CFBundleURLTypes"];
    NSUInteger schemes = 0;
    if ([urlTypes isKindOfClass:NSArray.class]) for (NSDictionary *type in urlTypes) {
      id values=type[@"CFBundleURLSchemes"]; if ([values isKindOfClass:NSArray.class]) schemes += [values count];
    }
    NSDictionary *result = @{@"phase":phase, @"nonce":nonce, @"pid":@(getpid()), @"bundle":NSBundle.mainBundle.bundleIdentifier ?: @"", @"screen":screen, @"webview":web, @"backup":backup, @"key_access":keys, @"links":@{@"customSchemes":N(schemes)}, @"viewLimitReached":[NSNumber numberWithBool:visited>=5000], @"fileLimitReached":[NSNumber numberWithBool:examined>2000], @"keyQueriesComplete":@(keyQueriesComplete)};
    NSData *json = [NSJSONSerialization dataWithJSONObject:result options:0 error:nil];
    [json writeToFile:path options:NSDataWritingAtomic error:nil];
  }
}
__attribute__((constructor)) static void Start(void) {
  void (^background)(NSNotification *) = ^(NSNotification *note) {
    @try { Observe(@"background"); } @catch (NSException *exception) {}
  };
  [NSNotificationCenter.defaultCenter addObserverForName:UIApplicationDidEnterBackgroundNotification object:nil queue:NSOperationQueue.mainQueue usingBlock:background];
  // Scene-based apps can deliver transitions through scene notifications.
  if (@available(iOS 13.0, *)) {
    [NSNotificationCenter.defaultCenter addObserverForName:UISceneDidEnterBackgroundNotification object:nil queue:NSOperationQueue.mainQueue usingBlock:background];
  }
  dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 3*NSEC_PER_SEC), dispatch_get_main_queue(), ^{
    @try { Observe(@"foreground"); } @catch (NSException *exception) { /* absence is incomplete */ }
  });
}
