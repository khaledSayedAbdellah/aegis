import 'package:aegis/src/project/native_dependencies.dart';
import 'package:test/test.dart';

List<String> parse(String file, String text) => [
      for (final d in parseNativeDependencies([(file, text)]))
        '${d.ecosystem} ${d.name} ${d.version}'
    ];

void main() {
  test('Gradle files: exact coordinates only', () {
    expect(parse('android/app/build.gradle', '''
dependencies {
    implementation 'com.squareup.okhttp3:okhttp:3.12.0'
    implementation("com.google.code.gson:gson:2.8.5")
    implementation platform("com.google.firebase:firebase-bom:32.7.0")
    implementation "androidx.core:core-ktx:\$coreVersion"
    implementation 'com.example:lib:1.+'
    debugImplementation 'com.github.chuckerteam.chucker:library:4.0.0'
}
'''), [
      'Maven com.squareup.okhttp3:okhttp 3.12.0',
      'Maven com.google.code.gson:gson 2.8.5',
      'Maven com.google.firebase:firebase-bom 32.7.0',
    ]);
  });

  test('version catalogs and Gradle lock files', () {
    expect(parse('gradle/libs.versions.toml', '''
[versions]
okhttp = "4.9.0"  # pinned
[libraries]
okhttp = { module = "com.squareup.okhttp3:okhttp", version.ref = "okhttp" }
retrofit = { group = "com.squareup.retrofit2", name = "retrofit", version = "2.9.0" }
gson = "com.google.code.gson:gson:2.10.1"
'''), [
      'Maven com.squareup.okhttp3:okhttp 4.9.0',
      'Maven com.squareup.retrofit2:retrofit 2.9.0',
      'Maven com.google.code.gson:gson 2.10.1',
    ]);
    expect(parse('app/gradle.lockfile', '''
# This is a Gradle generated file
com.squareup.okio:okio:2.8.0=releaseRuntimeClasspath
empty=
'''), ['Maven com.squareup.okio:okio 2.8.0']);
  });

  test('npm lock files', () {
    expect(parse('package-lock.json', '''
{"lockfileVersion": 3, "packages": {
  "": {"name": "app"},
  "node_modules/axios": {"version": "0.21.0"},
  "node_modules/@babel/core": {"version": "7.20.0"},
  "node_modules/a/node_modules/ms": {"version": "2.0.0"}
}}'''), [
      'npm axios 0.21.0',
      'npm @babel/core 7.20.0',
      'npm ms 2.0.0',
    ]);
    expect(parse('yarn.lock', '''
# yarn lockfile v1

"@babel/core@^7.0.0", "@babel/core@^7.20.0":
  version "7.20.0"
  resolved "https://registry.yarnpkg.com/..."

axios@^0.21.0:
  version "0.21.0"
'''), ['npm @babel/core 7.20.0', 'npm axios 0.21.0']);
  });

  test('Package.resolved, versions 1 and 2', () {
    expect(
        parse(
            'ios/Runner.xcworkspace/xcshareddata/swiftpm/Package.resolved', '''
{"pins": [
  {"identity": "swift-nio", "location": "https://github.com/apple/swift-nio.git",
   "state": {"revision": "abc", "version": "2.0.0"}},
  {"identity": "branchy", "location": "https://github.com/x/branchy",
   "state": {"branch": "main", "revision": "def"}}
], "version": 2}'''),
        ['SwiftURL github.com/apple/swift-nio 2.0.0']);
    expect(parse('Package.resolved', '''
{"object": {"pins": [
  {"package": "Alamofire", "repositoryURL": "git@github.com:Alamofire/Alamofire.git",
   "state": {"version": "4.8.0"}}
]}, "version": 1}'''), ['SwiftURL github.com/Alamofire/Alamofire 4.8.0']);
  });

  test('Gradle versions from variables and gradle.properties', () {
    final deps = parseNativeDependencies([
      (
        'android/gradle.properties',
        'okioVersion=2.8.0\norg.gradle.jvmargs=-Xmx4G\n'
      ),
      (
        'android/build.gradle',
        '''
ext {
    okhttp_version = '3.12.0'
}
'''
      ),
      (
        'android/app/build.gradle.kts',
        '''
val gsonVersion = "2.8.5"
dependencies {
    implementation("com.squareup.okhttp3:okhttp:\${rootProject.ext.okhttp_version}")
    implementation("com.google.code.gson:gson:\$gsonVersion")
    implementation("com.squareup.okio:okio:\$okioVersion")
    implementation("com.example:unknown:\$missing")
}
'''
      ),
    ]);
    expect([
      for (final d in deps) '${d.name} ${d.version}'
    ], [
      'com.squareup.okhttp3:okhttp 3.12.0',
      'com.google.code.gson:gson 2.8.5',
      'com.squareup.okio:okio 2.8.0',
    ]);
  });
}
