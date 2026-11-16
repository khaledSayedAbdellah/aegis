/// Dependencies that are discontinued, or whose names imitate popular
/// packages.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import '../l10n/messages.g.dart';
import '../model.dart';
import '../project.dart';
import 'rule.dart';

const _all = {MasProfile.l1, MasProfile.l2, MasProfile.r};

/// Widely used pub.dev packages, for look-alike names.
const popularPackages = {
  'http',
  'dio',
  'provider',
  'riverpod',
  'flutter_riverpod',
  'hooks_riverpod',
  'bloc',
  'flutter_bloc',
  'get',
  'get_it',
  'injectable',
  'mobx',
  'flutter_mobx',
  'shared_preferences',
  'flutter_secure_storage',
  'hive',
  'hive_flutter',
  'sqflite',
  'drift',
  'isar',
  'objectbox',
  'path_provider',
  'path',
  'url_launcher',
  'image_picker',
  'file_picker',
  'camera',
  'video_player',
  'cached_network_image',
  'flutter_svg',
  'lottie',
  'google_fonts',
  'intl',
  'flutter_localizations',
  'easy_localization',
  'equatable',
  'freezed',
  'freezed_annotation',
  'json_annotation',
  'json_serializable',
  'build_runner',
  'go_router',
  'auto_route',
  'firebase_core',
  'firebase_auth',
  'cloud_firestore',
  'firebase_messaging',
  'firebase_analytics',
  'firebase_crashlytics',
  'firebase_storage',
  'firebase_database',
  'firebase_app_check',
  'firebase_remote_config',
  'google_sign_in',
  'sign_in_with_apple',
  'flutter_facebook_auth',
  'local_auth',
  'permission_handler',
  'geolocator',
  'google_maps_flutter',
  'location',
  'connectivity_plus',
  'device_info_plus',
  'package_info_plus',
  'share_plus',
  'battery_plus',
  'sensors_plus',
  'network_info_plus',
  'webview_flutter',
  'flutter_inappwebview',
  'flutter_local_notifications',
  'awesome_notifications',
  'onesignal_flutter',
  'uuid',
  'crypto',
  'encrypt',
  'pointycastle',
  'cryptography',
  'jwt_decoder',
  'dart_jsonwebtoken',
  'logger',
  'sentry_flutter',
  'collection',
  'rxdart',
  'async',
  'meta',
  'flutter_dotenv',
  'flutter_launcher_icons',
  'flutter_native_splash',
  'flutter_screenutil',
  'shimmer',
  'carousel_slider',
  'smooth_page_indicator',
  'flutter_slidable',
  'pull_to_refresh',
  'infinite_scroll_pagination',
  'fl_chart',
  'syncfusion_flutter_charts',
  'table_calendar',
  'pdf',
  'printing',
  'excel',
  'csv',
  'archive',
  'image',
  'image_cropper',
  'flutter_image_compress',
  'photo_view',
  'qr_flutter',
  'mobile_scanner',
  'flutter_barcode_scanner',
  'audioplayers',
  'just_audio',
  'record',
  'speech_to_text',
  'flutter_tts',
  'socket_io_client',
  'web_socket_channel',
  'graphql_flutter',
  'retrofit',
  'chopper',
  'grpc',
  'protobuf',
  'mqtt_client',
  'in_app_purchase',
  'purchases_flutter',
  'flutter_stripe',
  'pay',
  'google_mobile_ads',
  'app_links',
  'uni_links',
  'flutter_web_auth_2',
  'flutter_appauth',
  'oauth2',
  'mime',
  'html',
  'xml',
  'yaml',
  'args',
  'logging',
  'timeago',
  'dartz',
  'fpdart',
  'flutter_hooks',
  'stacked',
  'flutter_animate',
  'animations',
  'badges',
  'flutter_spinkit',
  'toastification',
  'fluttertoast',
  'another_flushbar',
  'flutter_keyboard_visibility',
  'flutter_cache_manager',
  'workmanager',
  'background_fetch',
  'flutter_background_service',
  'android_alarm_manager_plus',
  'wakelock_plus',
  'flutter_contacts',
  'contacts_service',
  'sms_autofill',
  'pinput',
  'country_code_picker',
  'intl_phone_field',
  'flutter_form_builder',
  'form_builder_validators',
  'reactive_forms',
  'mask_text_input_formatter',
  'flutter_typeahead',
  'dropdown_search',
  'flutter_staggered_grid_view',
  'freerasp',
  'safe_device',
  'flutter_jailbreak_detection',
  'screen_protector',
  'flutter_windowmanager',
  'no_screenshot',
};

/// Levenshtein distance up to [limit] (larger distances return limit + 1).
int _distance(String a, String b, int limit) {
  if ((a.length - b.length).abs() > limit) return limit + 1;
  var previous = List<int>.generate(b.length + 1, (i) => i);
  for (var i = 1; i <= a.length; i++) {
    final current = List<int>.filled(b.length + 1, 0)..[0] = i;
    for (var j = 1; j <= b.length; j++) {
      final cost = a[i - 1] == b[j - 1] ? 0 : 1;
      current[j] = [
        previous[j] + 1,
        current[j - 1] + 1,
        previous[j - 1] + cost,
      ].reduce((x, y) => x < y ? x : y);
    }
    previous = current;
  }
  return previous[b.length];
}

/// The popular package [name] imitates, or null.
String? lookAlike(String name) {
  if (name.length < 5 || popularPackages.contains(name)) return null;
  for (final popular in popularPackages) {
    if (popular.length < 5) continue;
    if (_distance(name, popular, 1) == 1) return popular;
  }
  return null;
}

class PackageHygieneRule extends Rule {
  const PackageHygieneRule();

  @override
  RuleMeta get meta => const RuleMeta(
        id: 'AEG-C03',
        title: Bilingual(En.packageHygieneTitle, Ar.packageHygieneTitle),
        passTitleText: Bilingual(En.packageHygienePass, Ar.packageHygienePass),
        description: Bilingual(
            En.packageHygieneDescription, Ar.packageHygieneDescription),
        fix: Bilingual(En.packageHygieneFix, Ar.packageHygieneFix),
        severity: Severity.low,
        masvs: ['MASVS-CODE-3'],
        cwe: 'CWE-1104',
        profiles: _all,
      );

  @override
  Future<RuleCheck> check(Project project, ProfileSet profile) async {
    final direct = {
      ...project.dependencies.keys,
      ...project.devDependencies.keys,
    }.where((n) {
      final source = project.locked[n]?.source;
      return n != 'flutter' &&
          n != 'flutter_test' &&
          (source == null || source == 'hosted');
    }).toList()
      ..sort();
    if (direct.isEmpty) return RuleCheck.notApplicable();
    final out = <Finding>[];
    for (final name in direct) {
      final popular = lookAlike(name);
      if (popular == null || direct.contains(popular)) continue;
      out.add(inFile('pubspec.yaml', null,
          En.packageLookAlike(package: name, popular: popular),
          messageAr: Ar.packageLookAlike(package: name, popular: popular)));
    }
    if (project.offline) return RuleCheck(out);

    final client = HttpClient()
      ..connectionTimeout = const Duration(seconds: 10);
    var failed = 0;
    try {
      // A few requests at a time.
      for (var i = 0; i < direct.length; i += 8) {
        final batch = direct.skip(i).take(8);
        final answers = await Future.wait(batch.map((name) async {
          try {
            final req = await client
                .getUrl(Uri.https('pub.dev', '/api/packages/$name'))
                .timeout(const Duration(seconds: 10));
            final res = await req.close().timeout(const Duration(seconds: 15));
            final text = await res
                .transform(utf8.decoder)
                .join()
                .timeout(const Duration(seconds: 15));
            if (res.statusCode == 404) return null;
            if (res.statusCode != 200) throw StateError('${res.statusCode}');
            final json = jsonDecode(text);
            return json is Map ? (name, json) : null;
          } catch (_) {
            failed++;
            return null;
          }
        }));
        for (final answer in answers.whereType<(String, Map)>()) {
          final (name, json) = answer;
          if (json['isDiscontinued'] != true) continue;
          final replacement = json['replacedBy']?.toString();
          out.add(inFile(
              'pubspec.yaml',
              null,
              replacement == null || replacement.isEmpty
                  ? En.packageDiscontinued(package: name)
                  : En.packageDiscontinuedReplaced(
                      package: name, replacement: replacement),
              messageAr: replacement == null || replacement.isEmpty
                  ? Ar.packageDiscontinued(package: name)
                  : Ar.packageDiscontinuedReplaced(
                      package: name, replacement: replacement)));
        }
      }
    } finally {
      client.close(force: true);
    }
    if (failed > 0) {
      return RuleCheck.incompleteLocalized(
          En.packageLookupFailed(count: '$failed'),
          Ar.packageLookupFailed(count: '$failed'),
          out);
    }
    return RuleCheck(out);
  }
}
